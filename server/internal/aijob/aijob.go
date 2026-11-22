// Package aijob 把一次模型调用从 HTTP 请求里挪到后台：发起时落一行 running 立即返回，
// 跑完写回结果或错误，前端轮询。请求断开（换页、刷新、反代超时）不影响模型调用本身，
// 结果在库里，哪个节点都能读到。
package aijob

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	entjob "openxdr/server/ent/aijob"
)

const (
	// 单次模型调用的上限；超过就记失败
	runTimeout = 5 * time.Minute
	// running 超过这个时间还没写回，只可能是跑它的进程没了（发版重启）
	staleAfter = runTimeout + time.Minute
)

const interrupted = "服务重启打断了这次调用，请重新发起"

// 各类结果保留多久：导入结果里有封存的凭据令牌，用完即走
var keep = map[string]time.Duration{"explain": 7 * 24 * time.Hour, "host_import": time.Hour}

// View 给前端的样子：status 取 none / running / done / failed
type View struct {
	ID         uuid.UUID      `json:"id,omitempty"`
	Status     string         `json:"status"`
	Result     map[string]any `json:"result,omitempty"`
	Error      string         `json:"error,omitempty"`
	CreatedAt  *time.Time     `json:"createdAt,omitempty"`
	FinishedAt *time.Time     `json:"finishedAt,omitempty"`
}

// Key 一个任务属于谁、针对什么
type Key struct{ Kind, Subject, Variant, Owner string }

// ViewOf 把一行变成 View；nil 表示还没跑过。卡在 running 太久的按被打断处理
func ViewOf(j *ent.AIJob) View {
	if j == nil {
		return View{Status: "none"}
	}
	v := View{ID: j.ID, Status: j.Status, Result: j.Result, Error: j.Error, CreatedAt: &j.CreatedAt, FinishedAt: j.FinishedAt}
	if j.Status == "running" && time.Since(j.CreatedAt) > staleAfter {
		v.Status, v.Error = "failed", interrupted
	}
	return v
}

// Latest 这个对象最近一次任务，没有返回 nil
func Latest(ctx context.Context, db *ent.Client, k Key) (*ent.AIJob, error) {
	j, err := db.AIJob.Query().
		Where(entjob.KindEQ(k.Kind), entjob.SubjectEQ(k.Subject), entjob.VariantEQ(k.Variant), entjob.OwnerEQ(k.Owner),
			entjob.CreatedAtGT(time.Now().Add(-keep[k.Kind]))).
		Order(ent.Desc(entjob.FieldCreatedAt)).First(ctx)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	return j, err
}

// Running 这个对象是否已有一次在跑（没卡死的）
func Running(j *ent.AIJob) bool { return j != nil && ViewOf(j).Status == "running" }

// EnsureSchema 同一对象同时只允许一个 running：部分唯一索引兜住多节点、多标签页同时发起。
// 建索引前把卡死的与重复的 running 记成失败，免得旧数据让索引建不起来
func EnsureSchema(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `
UPDATE ai_jobs j SET status = 'failed', error = $1, finished_at = now()
 WHERE status = 'running' AND (created_at < now() - make_interval(secs => $2) OR EXISTS (
   SELECT 1 FROM ai_jobs k WHERE k.status = 'running' AND k.kind = j.kind AND k.subject = j.subject
      AND k.variant = j.variant AND k.owner = j.owner AND (k.created_at, k.id) > (j.created_at, j.id)))`,
		interrupted, staleAfter.Seconds()); err != nil {
		return err
	}
	_, err := db.ExecContext(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS ai_jobs_one_running
  ON ai_jobs (kind, subject, variant, owner) WHERE status = 'running'`)
	return err
}

// Start 落一行 running，后台跑 fn，结果按 JSON 存。release 在跑完后调用（释放并发名额），可为 nil。
// 这个对象已有一次在跑时不再发起，返回在跑的那次，started 为 false
func Start(ctx context.Context, db *ent.Client, k Key, fn func(context.Context) (any, error), release func()) (j *ent.AIJob, started bool, err error) {
	defer func() {
		if !started && release != nil {
			release()
		}
	}()
	prune(ctx, db)
	// 跑它的进程没了的 running 让位，否则唯一索引会一直挡住重新发起
	if _, err := db.AIJob.Update().Where(entjob.KindEQ(k.Kind), entjob.SubjectEQ(k.Subject), entjob.VariantEQ(k.Variant), entjob.OwnerEQ(k.Owner),
		entjob.StatusEQ("running"), entjob.CreatedAtLT(time.Now().Add(-staleAfter))).
		SetStatus("failed").SetError(interrupted).SetFinishedAt(time.Now()).Save(ctx); err != nil {
		return nil, false, err
	}
	j, err = db.AIJob.Create().SetKind(k.Kind).SetSubject(k.Subject).SetVariant(k.Variant).SetOwner(k.Owner).Save(ctx)
	if ent.IsConstraintError(err) {
		j, err = Latest(ctx, db, k)
		if err == nil && j == nil {
			err = errors.New("任务状态冲突，请重试")
		}
		return j, false, err
	}
	if err != nil {
		return nil, false, err
	}
	go func() {
		if release != nil {
			defer release()
		}
		run, cancel := context.WithTimeout(context.Background(), runTimeout)
		defer cancel()
		out, err := fn(run)
		// 写回不跟着调用的超时走，免得模型刚好用满时间结果写不进去
		save, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		up := db.AIJob.UpdateOneID(j.ID).SetFinishedAt(time.Now())
		if err == nil {
			var m map[string]any
			if m, err = encodeResult(out); err == nil {
				up.SetStatus("done").SetResult(m)
			}
		}
		if err != nil {
			up.SetStatus("failed").SetError(err.Error())
		}
		if sErr := up.Exec(save); sErr != nil {
			slog.Error("AI 任务结果写回失败", "kind", k.Kind, "job", j.ID, "err", sErr)
		}
	}()
	return j, true, nil
}

// encodeResult 将任务返回值编码为 JSON 对象映射；非对象值或序列化失败均返回明确错误，避免任务卡在 running。
func encodeResult(out any) (map[string]any, error) {
	b, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// Discard 删掉某人对某对象的任务（导入确认后，结果里的凭据令牌不再需要）
func Discard(ctx context.Context, db *ent.Client, k Key) error {
	_, err := db.AIJob.Delete().Where(entjob.KindEQ(k.Kind), entjob.SubjectEQ(k.Subject), entjob.OwnerEQ(k.Owner)).Exec(ctx)
	return err
}

func prune(ctx context.Context, db *ent.Client) {
	for kind, d := range keep {
		if _, err := db.AIJob.Delete().Where(entjob.KindEQ(kind), entjob.CreatedAtLT(time.Now().Add(-d))).Exec(ctx); err != nil {
			slog.Warn("清理过期 AI 任务失败", "kind", kind, "err", err)
		}
	}
}
