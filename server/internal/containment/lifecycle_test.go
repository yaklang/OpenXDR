package containment

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"openxdr/server/ent"
	entcontainment "openxdr/server/ent/containment"
	"openxdr/server/internal/response"
)

// memStore 极简内存存储 + sql/driver，支持在不依赖外部 Postgres 的单元测试里驱动真实的
// Reconcile / expire / liftCleared / Lift / disableSSO / withFuseLock 状态机。
type memStore struct {
	mu                 sync.Mutex
	containments       map[uuid.UUID]*ent.Containment
	commands           map[uuid.UUID]*ent.Command
	assets             map[uuid.UUID]*ent.Asset
	failContainmentIns error
	now                time.Time
	onInsertEvent      func(state string)
}

func newMemStore(now time.Time) *memStore {
	return &memStore{
		containments: map[uuid.UUID]*ent.Containment{},
		commands:     map[uuid.UUID]*ent.Command{},
		assets:       map[uuid.UUID]*ent.Asset{},
		now:          now,
	}
}

func (s *memStore) entClient(t *testing.T) *ent.Client {
	t.Helper()
	db := sql.OpenDB(&memConnector{store: s})
	t.Cleanup(func() { _ = db.Close() })
	return ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, db)))
}

type memConnector struct{ store *memStore }

func (c *memConnector) Connect(context.Context) (driver.Conn, error) {
	return &memConn{s: c.store}, nil
}
func (c *memConnector) Driver() driver.Driver { return &memDriver{s: c.store} }

type memDriver struct{ s *memStore }

func (d *memDriver) Open(string) (driver.Conn, error) { return &memConn{s: d.s}, nil }

type memConn struct{ s *memStore }

func (c *memConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (c *memConn) Close() error                        { return nil }
func (c *memConn) Begin() (driver.Tx, error)           { return &memTx{}, nil }

type memTx struct{}

func (t *memTx) Commit() error   { return nil }
func (t *memTx) Rollback() error { return nil }

func parseSelectCols(q string) []string {
	upper := strings.ToUpper(q)
	i := strings.Index(upper, "SELECT ")
	j := strings.Index(upper, " FROM ")
	if i < 0 || j <= i+7 {
		return nil
	}
	raw := q[i+7 : j]
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if dot := strings.LastIndex(p, "."); dot >= 0 {
			p = p[dot+1:]
		}
		p = strings.Trim(p, `" `)
		out = append(out, p)
	}
	return out
}

func namedVals(args []driver.NamedValue) []any {
	out := make([]any, len(args))
	for i, a := range args {
		out[i] = a.Value
	}
	return out
}

func toUUID(v any) (uuid.UUID, bool) {
	switch x := v.(type) {
	case uuid.UUID:
		return x, true
	case string:
		u, err := uuid.Parse(x)
		return u, err == nil
	case []byte:
		u, err := uuid.ParseBytes(x)
		return u, err == nil
	default:
		return uuid.Nil, false
	}
}

func (c *memConn) ExecContext(_ context.Context, query string, nargs []driver.NamedValue) (driver.Result, error) {
	args := namedVals(nargs)
	q := strings.TrimSpace(query)
	c.s.mu.Lock()
	defer c.s.mu.Unlock()

	if strings.Contains(q, "pg_advisory_") {
		return driver.RowsAffected(1), nil
	}
	if strings.HasPrefix(q, `INSERT INTO "audit_logs"`) {
		return driver.RowsAffected(1), nil
	}
	if strings.HasPrefix(q, `INSERT INTO "containments"`) {
		if c.s.failContainmentIns != nil {
			return nil, c.s.failContainmentIns
		}
		row := parseInsertContainment(q, args)
		if _, dup := c.s.containments[row.ID]; dup {
			return nil, &ent.ConstraintError{}
		}
		c.s.containments[row.ID] = row
		if c.s.onInsertEvent != nil {
			c.s.onInsertEvent(string(row.State))
		}
		return driver.RowsAffected(1), nil
	}
	if strings.HasPrefix(q, `INSERT INTO "commands"`) {
		row := parseInsertCommand(q, args)
		if _, dup := c.s.commands[row.ID]; dup {
			return nil, &ent.ConstraintError{}
		}
		c.s.commands[row.ID] = row
		return driver.RowsAffected(1), nil
	}
	if strings.HasPrefix(q, `UPDATE "containments"`) {
		n := c.s.applyUpdateContainment(q, args)
		return driver.RowsAffected(n), nil
	}
	if strings.HasPrefix(q, `UPDATE "commands"`) {
		n := c.s.applyUpdateCommand(q, args)
		return driver.RowsAffected(n), nil
	}
	return driver.RowsAffected(1), nil
}

func (c *memConn) QueryContext(_ context.Context, query string, nargs []driver.NamedValue) (driver.Rows, error) {
	args := namedVals(nargs)
	q := strings.TrimSpace(query)
	c.s.mu.Lock()
	defer c.s.mu.Unlock()

	upperQ := strings.ToUpper(q)
	if strings.Contains(upperQ, "CLOCK_TIMESTAMP()") || strings.HasPrefix(upperQ, "SELECT NOW()") {
		return &memRows{cols: []string{"now"}, rows: [][]driver.Value{{c.s.now}}}, nil
	}
	if strings.HasPrefix(q, `INSERT INTO "containments"`) {
		if c.s.failContainmentIns != nil {
			return nil, c.s.failContainmentIns
		}
		row := parseInsertContainment(q, args)
		if _, dup := c.s.containments[row.ID]; dup {
			return nil, &ent.ConstraintError{}
		}
		c.s.containments[row.ID] = row
		if c.s.onInsertEvent != nil {
			c.s.onInsertEvent(string(row.State))
		}
		return &memRows{cols: []string{"id"}, rows: [][]driver.Value{{row.ID.String()}}}, nil
	}
	if strings.HasPrefix(q, `INSERT INTO "commands"`) {
		row := parseInsertCommand(q, args)
		if _, dup := c.s.commands[row.ID]; dup {
			return nil, &ent.ConstraintError{}
		}
		c.s.commands[row.ID] = row
		return &memRows{cols: []string{"id"}, rows: [][]driver.Value{{row.ID.String()}}}, nil
	}
	if strings.HasPrefix(q, `INSERT INTO "audit_logs"`) {
		return &memRows{cols: []string{"id"}, rows: [][]driver.Value{{int64(1)}}}, nil
	}
	if strings.Contains(q, `COUNT(`) && strings.Contains(q, `FROM "containments"`) {
		cnt := c.s.countContainments(q, args)
		return &memRows{cols: []string{"count"}, rows: [][]driver.Value{{cnt}}}, nil
	}
	if strings.Contains(q, `FROM "containments"`) {
		cols := parseSelectCols(q)
		matched := c.s.queryContainments(q, args)
		rows := make([][]driver.Value, 0, len(matched))
		for _, item := range matched {
			rows = append(rows, containmentRowValues(cols, item))
		}
		return &memRows{cols: cols, rows: rows}, nil
	}
	if strings.Contains(q, `FROM "commands"`) {
		cols := parseSelectCols(q)
		matched := c.s.queryCommands(q, args)
		rows := make([][]driver.Value, 0, len(matched))
		for _, item := range matched {
			rows = append(rows, commandRowValues(cols, item))
		}
		return &memRows{cols: cols, rows: rows}, nil
	}
	if strings.Contains(q, `FROM "assets"`) {
		cols := parseSelectCols(q)
		matched := c.s.queryAssets(q, args)
		rows := make([][]driver.Value, 0, len(matched))
		for _, item := range matched {
			rows = append(rows, assetRowValues(cols, item))
		}
		return &memRows{cols: cols, rows: rows}, nil
	}
	return &memRows{cols: []string{"x"}}, nil
}

func parseInsertColumns(q string) []string {
	l := strings.Index(q, "(")
	r := strings.Index(q, ")")
	if l < 0 || r <= l {
		return nil
	}
	parts := strings.Split(q[l+1:r], ",")
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = strings.Trim(p, `" `)
	}
	return out
}

func parseInsertContainment(q string, args []any) *ent.Containment {
	cols := parseInsertColumns(q)
	row := &ent.Containment{ID: uuid.New()}
	for i, col := range cols {
		if i >= len(args) {
			break
		}
		v := args[i]
		switch col {
		case "id":
			if u, ok := toUUID(v); ok {
				row.ID = u
			}
		case "created_at":
			if t, ok := v.(time.Time); ok {
				row.CreatedAt = t
			}
		case "asset_id":
			if u, ok := toUUID(v); ok {
				row.AssetID = u
			}
		case "kind":
			row.Kind, _ = v.(string)
		case "target":
			row.Target, _ = v.(string)
		case "key":
			row.Key, _ = v.(string)
		case "signal":
			row.Signal, _ = v.(string)
		case "alert_id":
			if u, ok := toUUID(v); ok {
				row.AlertID = u
			}
		case "role":
			if s, ok := v.(string); ok {
				row.Role = entcontainment.Role(s)
			}
		case "state":
			if s, ok := v.(string); ok {
				row.State = entcontainment.State(s)
			}
		case "reason":
			row.Reason, _ = v.(string)
		case "command_id":
			if u, ok := toUUID(v); ok {
				row.CommandID = &u
			}
		case "expires_at":
			if t, ok := v.(time.Time); ok {
				row.ExpiresAt = &t
			}
		}
	}
	return row
}

func parseInsertCommand(q string, args []any) *ent.Command {
	cols := parseInsertColumns(q)
	row := &ent.Command{ID: uuid.New(), Status: "pending"}
	for i, col := range cols {
		if i >= len(args) {
			break
		}
		v := args[i]
		switch col {
		case "id":
			if u, ok := toUUID(v); ok {
				row.ID = u
			}
		case "created_at":
			if t, ok := v.(time.Time); ok {
				row.CreatedAt = t
			}
		case "kind":
			row.Kind, _ = v.(string)
		case "status":
			row.Status, _ = v.(string)
		case "asset_id":
			if u, ok := toUUID(v); ok {
				row.AssetID = u
			}
		case "issued_by":
			row.IssuedBy, _ = v.(string)
		case "target":
			if s, ok := v.(string); ok {
				row.Target = &s
			}
		}
	}
	return row
}

func (s *memStore) queryContainments(q string, args []any) []*ent.Containment {
	var out []*ent.Containment
	for _, item := range s.containments {
		if matchContainmentWhere(q, args, item, s.commands) {
			cp := *item
			out = append(out, &cp)
		}
	}
	return out
}

func (s *memStore) countContainments(q string, args []any) int64 {
	var n int64
	for _, item := range s.containments {
		if matchContainmentWhere(q, args, item, s.commands) {
			n++
		}
	}
	return n
}

func matchContainmentWhere(q string, args []any, item *ent.Containment, cmds map[uuid.UUID]*ent.Command) bool {
	whereIdx := strings.Index(q, " WHERE ")
	if whereIdx < 0 {
		return true
	}
	where := q[whereIdx+7:]
	// 简单精确匹配本项目 Containment 查询条件
	if strings.Contains(where, `"command_id" IS NOT NULL`) && item.CommandID == nil {
		return false
	}
	if strings.Contains(where, `"lift_command_id" IS NOT NULL`) && item.LiftCommandID == nil {
		return false
	}
	if strings.Contains(where, `"lift_command_id" IS NULL`) && !strings.Contains(where, "OR NOT EXISTS") && item.LiftCommandID != nil {
		return false
	}
	if strings.Contains(where, `OR NOT EXISTS (SELECT 1 FROM commands cmd WHERE cmd.id =`) {
		if item.LiftCommandID != nil {
			if cmd := cmds[*item.LiftCommandID]; cmd != nil && cmd.Status != "failed" {
				return false
			}
		}
	}
	// 解析简单 "col" = $N / "col" IN ($N, ...) / "col" <= $N / "col" >= $N
	for _, cond := range splitTopLevelAnd(where) {
		c := strings.TrimSpace(cond)
		if strings.Contains(c, "EXISTS") || strings.Contains(c, " OR ") || strings.Contains(c, "IS NULL") || strings.Contains(c, "IS NOT NULL") {
			continue
		}
		if col, idx, ok := parseSimpleOp(c, "="); ok && idx < len(args) {
			if !eqContainmentCol(item, col, args[idx]) {
				return false
			}
		} else if col, idx, ok := parseSimpleOp(c, "<="); ok && idx < len(args) {
			if col == "expires_at" {
				t, _ := args[idx].(time.Time)
				if item.ExpiresAt == nil || item.ExpiresAt.After(t) {
					return false
				}
			}
		} else if col, idx, ok := parseSimpleOp(c, ">="); ok && idx < len(args) {
			if col == "created_at" {
				t, _ := args[idx].(time.Time)
				if item.CreatedAt.Before(t) {
					return false
				}
			}
		} else if col, idxs, ok := parseInOp(c); ok {
			if col == "state" {
				matched := false
				for _, i := range idxs {
					if i < len(args) && string(item.State) == fmt.Sprint(args[i]) {
						matched = true
						break
					}
				}
				if !matched {
					return false
				}
			}
		}
	}
	return true
}

func eqContainmentCol(item *ent.Containment, col string, val any) bool {
	switch col {
	case "id":
		u, ok := toUUID(val)
		return ok && item.ID == u
	case "state":
		return string(item.State) == fmt.Sprint(val)
	case "kind":
		return item.Kind == fmt.Sprint(val)
	case "lift_command_id":
		u, ok := toUUID(val)
		return ok && item.LiftCommandID != nil && *item.LiftCommandID == u
	case "command_id":
		u, ok := toUUID(val)
		return ok && item.CommandID != nil && *item.CommandID == u
	default:
		return true
	}
}

func (s *memStore) applyUpdateContainment(q string, args []any) int64 {
	setIdx := strings.Index(q, " SET ")
	whereIdx := strings.Index(q, " WHERE ")
	if setIdx < 0 || whereIdx < 0 {
		return 0
	}
	setClause := q[setIdx+5 : whereIdx]
	var affected int64
	for _, item := range s.containments {
		if !matchContainmentWhere(q, args, item, s.commands) {
			continue
		}
		for _, assign := range strings.Split(setClause, ",") {
			a := strings.TrimSpace(assign)
			eq := strings.Index(a, "=")
			if eq < 0 {
				continue
			}
			col := strings.Trim(strings.TrimSpace(a[:eq]), `"`)
			rhs := strings.TrimSpace(a[eq+1:])
			if strings.EqualFold(rhs, "NULL") {
				switch col {
				case "lift_command_id":
					item.LiftCommandID = nil
				case "lifted_by":
					item.LiftedBy = nil
				case "ended_at":
					item.EndedAt = nil
				case "expires_at":
					item.ExpiresAt = nil
				}
				continue
			}
			idx, ok := parsePlaceholder(rhs)
			if !ok || idx >= len(args) {
				continue
			}
			v := args[idx]
			switch col {
			case "state":
				item.State = entcontainment.State(fmt.Sprint(v))
			case "reason":
				item.Reason = fmt.Sprint(v)
			case "lift_command_id":
				if u, ok := toUUID(v); ok {
					item.LiftCommandID = &u
				}
			case "lifted_by":
				str := fmt.Sprint(v)
				item.LiftedBy = &str
			case "expires_at":
				if t, ok := v.(time.Time); ok {
					item.ExpiresAt = &t
				}
			case "ended_at":
				if t, ok := v.(time.Time); ok {
					item.EndedAt = &t
				}
			}
		}
		affected++
	}
	return affected
}

func (s *memStore) applyUpdateCommand(q string, args []any) int64 {
	setIdx := strings.Index(q, " SET ")
	whereIdx := strings.Index(q, " WHERE ")
	if setIdx < 0 || whereIdx < 0 {
		return 0
	}
	setClause := q[setIdx+5 : whereIdx]
	where := q[whereIdx+7:]
	var affected int64
	for _, cmd := range s.commands {
		match := true
		for _, cond := range splitTopLevelAnd(where) {
			if col, idx, ok := parseSimpleOp(strings.TrimSpace(cond), "="); ok && idx < len(args) {
				if col == "id" {
					if u, ok := toUUID(args[idx]); !ok || cmd.ID != u {
						match = false
					}
				} else if col == "status" && cmd.Status != fmt.Sprint(args[idx]) {
					match = false
				}
			}
		}
		if !match {
			continue
		}
		for _, assign := range strings.Split(setClause, ",") {
			a := strings.TrimSpace(assign)
			eq := strings.Index(a, "=")
			if eq < 0 {
				continue
			}
			col := strings.Trim(strings.TrimSpace(a[:eq]), `"`)
			idx, ok := parsePlaceholder(strings.TrimSpace(a[eq+1:]))
			if !ok || idx >= len(args) {
				continue
			}
			switch col {
			case "status":
				cmd.Status = fmt.Sprint(args[idx])
			case "detail":
				d := fmt.Sprint(args[idx])
				cmd.Detail = &d
			case "completed_at":
				if t, ok := args[idx].(time.Time); ok {
					cmd.CompletedAt = &t
				}
			}
		}
		affected++
	}
	return affected
}

func (s *memStore) queryCommands(q string, args []any) []*ent.Command {
	whereIdx := strings.Index(q, " WHERE ")
	var out []*ent.Command
	for _, cmd := range s.commands {
		if whereIdx >= 0 {
			where := q[whereIdx+7:]
			matched := true
			for _, cond := range splitTopLevelAnd(where) {
				c := strings.TrimSpace(cond)
				if col, idx, ok := parseSimpleOp(c, "="); ok && idx < len(args) && col == "id" {
					u, ok := toUUID(args[idx])
					if !ok || cmd.ID != u {
						matched = false
					}
				} else if col, idxs, ok := parseInOp(c); ok && col == "id" {
					found := false
					for _, i := range idxs {
						if i < len(args) {
							if u, ok := toUUID(args[i]); ok && cmd.ID == u {
								found = true
								break
							}
						}
					}
					if !found {
						matched = false
					}
				}
			}
			if !matched {
				continue
			}
		}
		cp := *cmd
		out = append(out, &cp)
	}
	return out
}

func (s *memStore) queryAssets(q string, args []any) []*ent.Asset {
	whereIdx := strings.Index(q, " WHERE ")
	var out []*ent.Asset
	for _, a := range s.assets {
		if whereIdx >= 0 {
			where := q[whereIdx+7:]
			matched := true
			for _, cond := range splitTopLevelAnd(where) {
				if col, idx, ok := parseSimpleOp(strings.TrimSpace(cond), "="); ok && idx < len(args) && col == "id" {
					if u, ok := toUUID(args[idx]); !ok || a.ID != u {
						matched = false
					}
				}
			}
			if !matched {
				continue
			}
		}
		cp := *a
		out = append(out, &cp)
	}
	return out
}

func splitTopLevelAnd(s string) []string {
	var parts []string
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		}
		if depth == 0 && strings.HasPrefix(s[i:], " AND ") {
			parts = append(parts, s[start:i])
			i += 4
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func parseSimpleOp(c, op string) (string, int, bool) {
	c = strings.TrimSpace(strings.Trim(c, "()"))
	sep := " " + op + " "
	i := strings.Index(c, sep)
	if i < 0 {
		return "", 0, false
	}
	lhs := strings.TrimSpace(c[:i])
	if dot := strings.LastIndex(lhs, "."); dot >= 0 {
		lhs = lhs[dot+1:]
	}
	lhs = strings.Trim(lhs, `" `)
	rhs := strings.TrimSpace(c[i+len(sep):])
	idx, ok := parsePlaceholder(rhs)
	return lhs, idx, ok
}

func parseInOp(c string) (string, []int, bool) {
	c = strings.TrimSpace(strings.Trim(c, "()"))
	i := strings.Index(c, " IN (")
	if i < 0 {
		return "", nil, false
	}
	lhs := strings.TrimSpace(c[:i])
	if dot := strings.LastIndex(lhs, "."); dot >= 0 {
		lhs = lhs[dot+1:]
	}
	lhs = strings.Trim(lhs, `" `)
	body := c[i+5:]
	end := strings.Index(body, ")")
	if end < 0 {
		return "", nil, false
	}
	var idxs []int
	for _, p := range strings.Split(body[:end], ",") {
		if idx, ok := parsePlaceholder(strings.TrimSpace(p)); ok {
			idxs = append(idxs, idx)
		}
	}
	return lhs, idxs, len(idxs) > 0
}

func parsePlaceholder(s string) (int, bool) {
	s = strings.TrimSpace(strings.TrimSuffix(s, ")"))
	if !strings.HasPrefix(s, "$") {
		return 0, false
	}
	n := 0
	for _, ch := range s[1:] {
		if ch < '0' || ch > '9' {
			break
		}
		n = n*10 + int(ch-'0')
	}
	if n <= 0 {
		return 0, false
	}
	return n - 1, true
}

func containmentRowValues(cols []string, item *ent.Containment) []driver.Value {
	vals := make([]driver.Value, len(cols))
	for i, col := range cols {
		switch col {
		case "id":
			vals[i] = item.ID.String()
		case "created_at":
			vals[i] = item.CreatedAt
		case "asset_id":
			vals[i] = item.AssetID.String()
		case "group_id":
			if item.GroupID != nil {
				vals[i] = item.GroupID.String()
			}
		case "kind":
			vals[i] = item.Kind
		case "target":
			vals[i] = item.Target
		case "pid":
			vals[i] = int64(item.Pid)
		case "key":
			vals[i] = item.Key
		case "signal":
			vals[i] = item.Signal
		case "alert_id":
			vals[i] = item.AlertID.String()
		case "incident_id":
			if item.IncidentID != nil {
				vals[i] = item.IncidentID.String()
			}
		case "source_asset_id":
			if item.SourceAssetID != nil {
				vals[i] = item.SourceAssetID.String()
			}
		case "role":
			vals[i] = string(item.Role)
		case "state":
			vals[i] = string(item.State)
		case "reason":
			vals[i] = item.Reason
		case "command_id":
			if item.CommandID != nil {
				vals[i] = item.CommandID.String()
			}
		case "lift_command_id":
			if item.LiftCommandID != nil {
				vals[i] = item.LiftCommandID.String()
			}
		case "expires_at":
			if item.ExpiresAt != nil {
				vals[i] = *item.ExpiresAt
			}
		case "ended_at":
			if item.EndedAt != nil {
				vals[i] = *item.EndedAt
			}
		case "lifted_by":
			if item.LiftedBy != nil {
				vals[i] = *item.LiftedBy
			}
		case "decided_by":
			if item.DecidedBy != nil {
				vals[i] = *item.DecidedBy
			}
		case "reviews":
			vals[i] = int64(item.Reviews)
		}
	}
	return vals
}

func commandRowValues(cols []string, item *ent.Command) []driver.Value {
	vals := make([]driver.Value, len(cols))
	for i, col := range cols {
		switch col {
		case "id":
			vals[i] = item.ID.String()
		case "created_at":
			vals[i] = item.CreatedAt
		case "asset_id":
			vals[i] = item.AssetID.String()
		case "kind":
			vals[i] = item.Kind
		case "status":
			vals[i] = item.Status
		case "issued_by":
			vals[i] = item.IssuedBy
		case "target":
			if item.Target != nil {
				vals[i] = *item.Target
			}
		case "detail":
			if item.Detail != nil {
				vals[i] = *item.Detail
			}
		case "completed_at":
			if item.CompletedAt != nil {
				vals[i] = *item.CompletedAt
			}
		case "pid":
			vals[i] = int64(item.Pid)
		case "timeout_ms":
			vals[i] = int64(item.TimeoutMs)
		case "allow_endpoints":
			vals[i] = []byte("[]")
		case "truncated":
			vals[i] = item.Truncated
		}
	}
	return vals
}

func assetRowValues(cols []string, item *ent.Asset) []driver.Value {
	vals := make([]driver.Value, len(cols))
	for i, col := range cols {
		switch col {
		case "id":
			vals[i] = item.ID.String()
		case "hostname":
			vals[i] = item.Hostname
		case "agent_id":
			if item.AgentID != nil {
				vals[i] = item.AgentID.String()
			}
		case "os":
			if item.Os != nil {
				vals[i] = *item.Os
			}
		case "first_seen":
			vals[i] = item.FirstSeen
		case "last_seen":
			vals[i] = item.LastSeen
		case "ip_addrs", "tags", "locked_fields":
			vals[i] = []byte("[]")
		}
	}
	return vals
}

type memRows struct {
	cols []string
	rows [][]driver.Value
	idx  int
}

func (r *memRows) Columns() []string { return r.cols }
func (r *memRows) Close() error      { return nil }
func (r *memRows) Next(dest []driver.Value) error {
	if r.idx >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.idx])
	r.idx++
	return nil
}

// 复现并验证到期解除失败活锁已被彻底消除：
// 1. 首次到期解除失败（agent 离线或回执 failed）后，Reconcile 清空失败的 LiftCommandID 并推后 ExpiresAt 5 分钟；
// 2. 5 分钟后再次先跑 Reconcile 再跑 expire：Reconcile 不再重复推后 ExpiresAt，expire 成功下发新的解除指令；
// 3. 新指令回执成功后 Reconcile 将租约推进为 StateExpired。
func TestExpiryLiftFailureRetriesWithoutLivelock(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	store := newMemStore(now)
	db := store.entClient(t)
	hub := response.NewHub(db, true)

	agentID := uuid.New()
	assetID := uuid.New()
	store.assets[assetID] = &ent.Asset{ID: assetID, Hostname: "lab-1", AgentID: &agentID}

	// 场景 A：首次到期解除时 agent 离线（Hub.Issue 立即返回 failed），5 分钟后 agent 上线，必须成功重发新解除指令
	cID := uuid.New()
	exp := now.Add(-time.Minute)
	store.containments[cID] = &ent.Containment{
		ID:        cID,
		CreatedAt: now.Add(-24 * time.Hour),
		AssetID:   assetID,
		Kind:      "block_network",
		Target:    "198.51.100.7",
		Key:       assetID.String() + "|block_network|198.51.100.7",
		Signal:    "rule.test",
		AlertID:   uuid.New(),
		Role:      entcontainment.RoleVictim,
		State:     entcontainment.StateActive,
		ExpiresAt: &exp,
	}

	eng := &Engine{DB: db, Hub: hub, TTL: 24 * time.Hour, MaxPerHour: 10, Now: func() time.Time { return store.now }}

	// T=0：agent 离线，expire 下发 cmd1 失败
	if err := eng.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := eng.expire(context.Background()); err != nil {
		t.Fatal(err)
	}
	c := store.containments[cID]
	if c.LiftCommandID != nil {
		t.Fatalf("立即失败后应清空 LiftCommandID 避免后续活锁，实际=%v", c.LiftCommandID)
	}
	if c.ExpiresAt == nil || !c.ExpiresAt.Equal(now.Add(liftRetry)) {
		t.Fatalf("首次失败应退避 5 分钟，实际 ExpiresAt=%v", c.ExpiresAt)
	}
	if len(store.commands) != 1 {
		t.Fatalf("应生成 1 条失败解除指令，实际=%d", len(store.commands))
	}
	var firstCmdID uuid.UUID
	for id := range store.commands {
		firstCmdID = id
	}

	// 模拟场景 B：即便历史上是 sent 后才异步收到 failed 回执，Reconcile 也必须清空 LiftCommandID 且仅退避一次
	store.containments[cID].LiftCommandID = &firstCmdID
	store.containments[cID].ExpiresAt = &exp
	if err := eng.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	c = store.containments[cID]
	if c.LiftCommandID != nil {
		t.Fatalf("Reconcile 处理 failed 回执后必须清空 LiftCommandID，实际=%v", c.LiftCommandID)
	}
	if c.ExpiresAt == nil || !c.ExpiresAt.Equal(now.Add(liftRetry)) {
		t.Fatalf("Reconcile 处理 failed 回执应退避一次，实际=%v", c.ExpiresAt)
	}

	// T+5 分钟：agent 恢复上线，先跑 reconcile 再跑 expire —— 绝不能再次推后 ExpiresAt！
	store.now = now.Add(liftRetry)
	inbox := hub.Attach(agentID)
	defer hub.Detach(agentID, inbox)

	if err := eng.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !store.containments[cID].ExpiresAt.Equal(now.Add(liftRetry)) {
		t.Fatalf("5 分钟后 Reconcile 不应再次推后 ExpiresAt（活锁复现！）: got=%v", store.containments[cID].ExpiresAt)
	}
	if err := eng.expire(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.commands) != 2 {
		t.Fatalf("5 分钟后 expire 应下发第 2 条解除指令，实际共=%d 条", len(store.commands))
	}
	if store.containments[cID].LiftCommandID == nil || *store.containments[cID].LiftCommandID == firstCmdID {
		t.Fatalf("应绑定新的解除指令 ID，got=%v first=%v", store.containments[cID].LiftCommandID, firstCmdID)
	}
	secondID := *store.containments[cID].LiftCommandID
	select {
	case pbCmd := <-inbox:
		if pbCmd.Id != secondID.String() {
			t.Fatalf("收到错误指令 ID: got=%s want=%s", pbCmd.Id, secondID)
		}
	default:
		t.Fatal("agent 通道应收到新的解除指令")
	}

	// 回执 succeeded 后，Reconcile 将租约推进为 expired
	store.commands[secondID].Status = "succeeded"
	doneAt := store.now
	store.commands[secondID].CompletedAt = &doneAt
	if err := eng.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.containments[cID].State != entcontainment.StateExpired || store.containments[cID].EndedAt == nil {
		t.Fatalf("第 2 次解除成功后应推进为 StateExpired: state=%s ended=%v", store.containments[cID].State, store.containments[cID].EndedAt)
	}
}

type stubSSO struct {
	mu           sync.Mutex
	disabled     []string
	enabled      []string
	disableErr   error
	enableErr    error
	onBeforeCall func(op, user string)
}

func (s *stubSSO) Disable(_ context.Context, username string) (string, error) {
	if s.onBeforeCall != nil {
		s.onBeforeCall("disable", username)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.disableErr != nil {
		return "", s.disableErr
	}
	s.disabled = append(s.disabled, username)
	return "已停用 " + username, nil
}

func (s *stubSSO) Enable(_ context.Context, username string) (string, error) {
	if s.onBeforeCall != nil {
		s.onBeforeCall("enable", username)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.enableErr != nil {
		return "", s.enableErr
	}
	s.enabled = append(s.enabled, username)
	return "已恢复 " + username, nil
}

// 验证 disableSSO 先落库 pending 再调外部 Authentik Disable；落库失败绝不调外部，Disable 失败回写 failed。
func TestDisableSSOPersistsBeforeExternalCall(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	store := newMemStore(now)
	db := store.entClient(t)

	var order []string
	store.onInsertEvent = func(state string) {
		order = append(order, "db_insert:"+state)
	}
	sso := &stubSSO{
		onBeforeCall: func(op, user string) {
			order = append(order, "sso_"+op+":"+user)
		},
	}
	eng := &Engine{DB: db, MaxPerHour: 10, SSO: sso, Now: func() time.Time { return store.now }}
	asset := &ent.Asset{ID: uuid.New(), Hostname: "sso-gw"}
	al := &ent.Alert{ID: uuid.New(), RuleID: "auth.bruteforce"}
	act := action{asset: asset, kind: KindSSO, target: "alice", role: "victim", why: "爆破得手"}

	create := db.Containment.Create().SetID(uuid.New()).SetCreatedAt(now).
		SetAssetID(asset.ID).SetKind(KindSSO).SetTarget("alice").SetKey(act.key()).
		SetSignal(al.RuleID).SetAlertID(al.ID).SetRole(entcontainment.RoleVictim)
	if err := eng.disableSSO(context.Background(), create, act, al); err != nil {
		t.Fatal(err)
	}
	if len(order) != 2 || order[0] != "db_insert:pending" || order[1] != "sso_disable:alice" {
		t.Fatalf("落库顺序错误，必须先写 pending 再调外部 SSO: %v", order)
	}
	for _, c := range store.containments {
		if c.State != entcontainment.StateExecuted {
			t.Fatalf("成功后状态应更新为 executed，实际=%s", c.State)
		}
	}

	// 外部 Disable 失败时，已落库的 pending 更新为 failed
	sso.disableErr = errors.New("authentik 502")
	id2 := uuid.New()
	create2 := db.Containment.Create().SetID(id2).SetCreatedAt(now).
		SetAssetID(asset.ID).SetKind(KindSSO).SetTarget("bob").SetKey(asset.ID.String() + "|" + KindSSO + "|bob").
		SetSignal(al.RuleID).SetAlertID(al.ID).SetRole(entcontainment.RoleVictim)
	if err := eng.disableSSO(context.Background(), create2, action{asset: asset, kind: KindSSO, target: "bob", role: "victim", why: "爆破"}, al); err != nil {
		t.Fatal(err)
	}
	if store.containments[id2].State != entcontainment.StateFailed {
		t.Fatalf("外部停用失败应回写 StateFailed，实际=%s", store.containments[id2].State)
	}

	// 落库失败时绝不调用外部 SSO
	sso.disableErr = nil
	calledAfterDBFail := false
	sso.onBeforeCall = func(string, string) { calledAfterDBFail = true }
	store.failContainmentIns = errors.New("db write error")
	create3 := db.Containment.Create().SetID(uuid.New()).SetCreatedAt(now).
		SetAssetID(asset.ID).SetKind(KindSSO).SetTarget("charlie").SetKey(asset.ID.String() + "|" + KindSSO + "|charlie").
		SetSignal(al.RuleID).SetAlertID(al.ID).SetRole(entcontainment.RoleVictim)
	if err := eng.disableSSO(context.Background(), create3, action{asset: asset, kind: KindSSO, target: "charlie", role: "victim", why: "爆破"}, al); err == nil {
		t.Fatal("写库失败应返回错误")
	}
	if calledAfterDBFail {
		t.Fatal("落库失败后绝不应调用外部 SSO.Disable")
	}
}

// 验证 liftCleared 对 KindSSO 走 e.SSO.Enable（绝不经 Hub 下发未知指令 0），对失败解除记录退避后重试。
func TestLiftClearedSSOAndRetryAfterFailure(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	store := newMemStore(now)
	db := store.entClient(t)
	hub := response.NewHub(db, true)

	agentID := uuid.New()
	assetID := uuid.New()
	store.assets[assetID] = &ent.Asset{ID: assetID, Hostname: "sso-host", AgentID: &agentID}

	ssoID := uuid.New()
	store.containments[ssoID] = &ent.Containment{
		ID:        ssoID,
		CreatedAt: now.Add(-time.Hour),
		AssetID:   assetID,
		Kind:      KindSSO,
		Target:    "alice",
		Key:       assetID.String() + "|" + KindSSO + "|alice",
		Signal:    "auth.bruteforce",
		AlertID:   uuid.New(),
		Role:      entcontainment.RoleVictim,
		State:     entcontainment.StateExecuted,
		Reason:    "爆破得手",
	}

	// 直接调 Lift() 传 KindSSO 必须拒绝，不能发给 Hub
	if _, err := Lift(context.Background(), db, hub, store.containments[ssoID], "admin", ""); err == nil {
		t.Fatal("Lift() 必须拒绝 KindSSO，避免下发未知命令枚举 0")
	}

	sso := &stubSSO{}
	eng := &Engine{DB: db, Hub: hub, SSO: sso, Now: func() time.Time { return store.now }}
	if err := eng.liftCleared(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sso.enabled) != 1 || sso.enabled[0] != "alice" {
		t.Fatalf("liftCleared 应对 KindSSO 调用 SSO.Enable: %v", sso.enabled)
	}
	if len(store.commands) != 0 {
		t.Fatalf("KindSSO 恢复不应经 Hub 建 agent 指令，实际建单=%d", len(store.commands))
	}
	if store.containments[ssoID].State != entcontainment.StateLifted {
		t.Fatalf("SSO 恢复后状态应为 lifted，实际=%s", store.containments[ssoID].State)
	}

	// 普通处置：历史已有失败解除指令时，退避期内不重发，5 分钟后自动重试成功
	blockID := uuid.New()
	failedCmdID := liftCommandID(blockID, uuid.Nil)
	failedAt := now
	target := "203.0.113.9"
	store.commands[failedCmdID] = &ent.Command{
		ID:          failedCmdID,
		AssetID:     assetID,
		Kind:        "unblock_network",
		Target:      &target,
		Status:      "failed",
		CreatedAt:   failedAt,
		CompletedAt: &failedAt,
	}
	exp := now.Add(24 * time.Hour)
	store.containments[blockID] = &ent.Containment{
		ID:            blockID,
		CreatedAt:     now.Add(-time.Hour),
		AssetID:       assetID,
		Kind:          "block_network",
		Target:        target,
		Key:           assetID.String() + "|block_network|" + target,
		Signal:        "rule.fp",
		AlertID:       uuid.New(),
		Role:          entcontainment.RoleVictim,
		State:         entcontainment.StateActive,
		LiftCommandID: &failedCmdID,
		ExpiresAt:     &exp,
	}

	inbox := hub.Attach(agentID)
	defer hub.Detach(agentID, inbox)

	// 退避期内（仅过 1 分钟）不重发
	store.now = now.Add(time.Minute)
	if err := eng.liftCleared(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.commands) != 1 {
		t.Fatalf("退避期内不应重复下发解除指令，实际=%d", len(store.commands))
	}

	// 满 5 分钟退避后，允许对曾失败的记录重试并下发新解除指令
	store.now = now.Add(liftRetry)
	if err := eng.liftCleared(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.commands) != 2 {
		t.Fatalf("退避期满后应重新下发新的解除指令，实际=%d", len(store.commands))
	}
	select {
	case <-inbox:
	default:
		t.Fatal("退避期满后 agent 应收到新解除指令")
	}
}

// 验证 withFuseLock 串行化并发审批熔断检查，并发竞争 MaxPerHour=1 时不会突破熔断上限。
func TestFuseLockPreventsConcurrentBudgetOverrun(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	store := newMemStore(now)
	db := store.entClient(t)

	eng := &Engine{DB: db, MaxPerHour: 1, Now: func() time.Time { return now }}
	asset := &ent.Asset{ID: uuid.New(), Hostname: "host-a"}

	const workers = 12
	var granted, held atomic.Int32
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			<-start
			act := action{asset: asset, kind: "block_network", target: fmt.Sprintf("198.51.100.%d", n+1)}
			err := eng.withFuseLock(context.Background(), func() error {
				reason, err := eng.fuse(context.Background(), act)
				if err != nil {
					return err
				}
				if reason != "" {
					held.Add(1)
					return nil
				}
				// 故意放大临界区窗口，暴露缺少锁时的竞态
				time.Sleep(5 * time.Millisecond)
				id := uuid.New()
				return db.Containment.Create().SetID(id).SetCreatedAt(now).
					SetAssetID(asset.ID).SetKind(act.kind).SetTarget(act.target).SetKey(act.key()).
					SetSignal("verdict").SetAlertID(uuid.New()).SetRole(entcontainment.RoleHost).
					SetState(entcontainment.StatePending).SetReason("approved").Exec(context.Background())
			})
			if err != nil {
				t.Errorf("worker %d err: %v", n, err)
				return
			}
		}(i)
	}
	close(start)
	wg.Wait()

	for _, c := range store.containments {
		if c.State == entcontainment.StatePending {
			granted.Add(1)
		}
	}
	if granted.Load() != 1 || held.Load() != workers-1 {
		t.Fatalf("并发熔断被突破: granted=%d held=%d want=1/%d", granted.Load(), held.Load(), workers-1)
	}
}
