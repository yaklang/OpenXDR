package schedule

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/agentsession"
)

type rerunStubDB struct {
	mu       sync.Mutex
	runID    uuid.UUID
	runSess  uuid.UUID
	runStat  string
	sessions map[uuid.UUID]*ent.AgentSession
}

type rerunStubConnector struct{ db *rerunStubDB }

func (c *rerunStubConnector) Connect(context.Context) (driver.Conn, error) {
	return &rerunStubConn{db: c.db}, nil
}
func (c *rerunStubConnector) Driver() driver.Driver { return nil }

type rerunStubConn struct{ db *rerunStubDB }

func (c *rerunStubConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (c *rerunStubConn) Close() error                        { return nil }
func (c *rerunStubConn) Begin() (driver.Tx, error)           { return rerunStubTx{}, nil }
func (c *rerunStubConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return rerunStubTx{}, nil
}

type rerunStubTx struct{}

func (rerunStubTx) Commit() error   { return nil }
func (rerunStubTx) Rollback() error { return nil }

func (c *rerunStubConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.db.mu.Lock()
	defer c.db.mu.Unlock()
	switch {
	case strings.Contains(query, `FROM "agent_sessions"`):
		id := toUUID(args[0].Value)
		sess, ok := c.db.sessions[id]
		if !ok {
			return &rerunStubRows{cols: agentsession.Columns}, nil
		}
		var titleVal, errVal, runOwner, subjects any
		var finVal, expVal, dlVal, cancelVal any
		if sess.Title != nil {
			titleVal = *sess.Title
		}
		if sess.FinishedAt != nil {
			finVal = *sess.FinishedAt
		}
		if sess.RunExpiresAt != nil {
			expVal = *sess.RunExpiresAt
		}
		if sess.RunDeadlineAt != nil {
			dlVal = *sess.RunDeadlineAt
		}
		if sess.CancelRequestedAt != nil {
			cancelVal = *sess.CancelRequestedAt
		}
		return &rerunStubRows{
			cols: agentsession.Columns,
			rows: [][]driver.Value{{
				sess.ID.String(), sess.CreatedAt, sess.Kind, sess.GroupID.String(),
				sess.Initiator, sess.Model, titleVal, sess.Status,
				errVal, finVal, expVal, runOwner, dlVal, sess.RunReplaySafe, subjects, cancelVal,
			}},
		}, nil
	default:
		return &rerunStubRows{}, nil
	}
}

func (c *rerunStubConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	c.db.mu.Lock()
	defer c.db.mu.Unlock()
	if strings.Contains(query, `INSERT INTO "agent_sessions"`) {
		var sess ent.AgentSession
		sess.Status = "running"
		sess.RunReplaySafe = true
		sess.Kind = "task"
		sess.Initiator = Initiator
		dl := time.Now().Add(time.Hour)
		sess.RunDeadlineAt = &dl
		if lp, rp := strings.Index(query, "("), strings.Index(query, ")"); lp >= 0 && rp > lp {
			for i, col := range strings.Split(query[lp+1:rp], ",") {
				col = strings.Trim(strings.TrimSpace(col), `"`)
				if i < len(args) {
					switch col {
					case "id":
						sess.ID = toUUID(args[i].Value)
					case "group_id":
						sess.GroupID = toUUID(args[i].Value)
					case "model":
						if m, ok := args[i].Value.(string); ok {
							sess.Model = m
						}
					}
				}
			}
		}
		c.db.sessions[sess.ID] = &sess
		return driver.RowsAffected(1), nil
	}
	if strings.Contains(query, `UPDATE "task_runs"`) {
		// 校验 WHERE 中的 id 与 session_id 必须匹配当前行，模拟并发接管/过期会话保护
		var uuids []uuid.UUID
		for _, a := range args {
			if u, ok := tryUUID(a.Value); ok {
				uuids = append(uuids, u)
			}
		}
		// rerun: SET session_id=$1, status=$2 ... WHERE id=$3 AND session_id=$4 AND status IN (...)
		if strings.Contains(query, `"session_id" = $1`) && len(uuids) >= 3 {
			newSess, runID, wantSess := uuids[0], uuids[1], uuids[2]
			if runID == c.db.runID && wantSess == c.db.runSess && (c.db.runStat == "failed" || c.db.runStat == StatusInterrupted) {
				c.db.runSess = newSess
				c.db.runStat = "running"
				return driver.RowsAffected(1), nil
			}
			return driver.RowsAffected(0), nil
		}
		// attempt 落终态: WHERE id=... AND status='running' AND session_id=...
		if len(uuids) >= 2 {
			runID, wantSess := uuids[len(uuids)-2], uuids[len(uuids)-1]
			if runID == c.db.runID && wantSess == c.db.runSess && c.db.runStat == "running" {
				c.db.runStat = "failed"
				return driver.RowsAffected(1), nil
			}
			return driver.RowsAffected(0), nil
		}
	}
	return driver.RowsAffected(1), nil
}

type rerunStubRows struct {
	cols []string
	rows [][]driver.Value
	idx  int
}

func (r *rerunStubRows) Columns() []string { return r.cols }
func (r *rerunStubRows) Close() error      { return nil }
func (r *rerunStubRows) Next(dest []driver.Value) error {
	if r.idx >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.idx])
	r.idx++
	return nil
}

func tryUUID(v any) (uuid.UUID, bool) {
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

func toUUID(v any) uuid.UUID {
	u, _ := tryUUID(v)
	return u
}

type fnRunner func(context.Context, Job) error

func (f fnRunner) RunTask(ctx context.Context, j Job) error { return f(ctx, j) }

// TestRecoveredInterruptedRunUpdatesSessionIDBeforeRetry 回归测试：
// 被打断的任务经 rerun 恢复后，若本次运行再次失败，execute 发起重试时 run.SessionID 必须已是
// 恢复会话的新 ID，而不能残留旧 ID 导致误判 errRunSuperseded 静默丢掉重试和失败通知。
func TestRecoveredInterruptedRunUpdatesSessionIDBeforeRetry(t *testing.T) {
	ctx := context.Background()
	groupID := uuid.New()
	runID := uuid.New()
	oldSessID := uuid.New()
	dl := time.Now().Add(time.Hour)
	stub := &rerunStubDB{
		runID:   runID,
		runSess: oldSessID,
		runStat: StatusInterrupted,
		sessions: map[uuid.UUID]*ent.AgentSession{
			oldSessID: {
				ID:            oldSessID,
				CreatedAt:     time.Now().Add(-time.Minute),
				Kind:          "task",
				GroupID:       groupID,
				Initiator:     Initiator,
				Model:         "m",
				Status:        StatusInterrupted,
				RunReplaySafe: true,
				RunDeadlineAt: &dl,
			},
		},
	}
	sqldb := sql.OpenDB(&rerunStubConnector{db: stub})
	t.Cleanup(func() { sqldb.Close() })
	client := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, sqldb)))

	task := &ent.Task{ID: "audit", Name: "审计", Prompt: "只读"}
	group := &ent.Group{ID: groupID, Name: "g1"}
	run := &ent.TaskRun{ID: runID, TaskID: task.ID, GroupID: groupID, SessionID: &oldSessID, Status: StatusInterrupted}

	calls := 0
	notified := 0
	s := &Scheduler{
		DB: client,
		Runner: fnRunner(func(_ context.Context, j Job) error {
			calls++
			stub.mu.Lock()
			if sess := stub.sessions[j.Session.ID]; sess != nil {
				sess.Status = "failed"
			}
			stub.mu.Unlock()
			return errors.New("模拟失败")
		}),
		Notify: func(context.Context, string, string, string) error {
			notified++
			return nil
		},
	}

	recovered, err := s.rerun(ctx, task, group, run, "m")
	if err != nil {
		t.Fatalf("恢复被打断的任务失败: %v", err)
	}
	if run.SessionID == nil || *run.SessionID != recovered.ID {
		t.Fatalf("rerun 提交后 run.SessionID 未同步: got=%v want=%v", run.SessionID, recovered.ID)
	}

	s.execute(ctx, task, group, run, recovered)
	if calls != 2 {
		t.Fatalf("恢复后失败应重试一次共执行 2 次，实际=%d", calls)
	}
	if notified != 1 {
		t.Fatalf("重试仍失败后应发送 1 次失败通知，实际=%d", notified)
	}
}
