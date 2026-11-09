package triage

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"openxdr/server/ent"
	"openxdr/server/ent/incident"
	"openxdr/server/ent/triagerun"
	"openxdr/server/internal/incidentwork"
	"openxdr/server/internal/review"
)

type timingKey struct{}
type runTiming struct {
	tools                                            []map[string]any
	modelMS, toolMS                                  int64
	modelCalls, toolCalls, toolErrors, input, output int
}

func timingFrom(ctx context.Context) *runTiming {
	v, _ := ctx.Value(timingKey{}).(*runTiming)
	return v
}

func (e *Engine) chat(ctx context.Context, msgs []Message, tools []Tool) (Message, error) {
	if err := e.checkInvestigationScope(ctx); err != nil {
		return Message{}, err
	}
	start := time.Now()
	defer func() {
		if r := timingFrom(ctx); r != nil {
			r.modelCalls++
			r.modelMS += time.Since(start).Milliseconds()
		}
	}()
	return e.LLM.Chat(ctx, msgs, tools)
}

// readyAt 是可开始排队的时刻，普通新证据扣除冷却期；旧版重开没有时间记录，不伪造等待时间。
func (e *Engine) runTrigger(inc *ent.Incident) (string, *time.Time) {
	if inc.Status == "open" {
		if inc.TriageCount == 0 {
			return "initial", &inc.CreatedAt
		}
		return "reopened", nil
	}
	if inc.UrgentAt != nil && (inc.TriagedAt == nil || inc.UrgentAt.After(*inc.TriagedAt)) {
		return "urgent", inc.UrgentAt
	}
	if needsCapabilityUpgrade(inc) {
		if inc.TriagedAt == nil {
			return capabilityTrigger, nil
		}
		ready := inc.TriagedAt.Add(e.Cooldown)
		return capabilityTrigger, &ready
	}
	if workFollowup(inc, time.Now()) {
		return "autonomy_followup", inc.WorkNextCheckAt
	}
	ready := inc.EvidenceAt
	if ready != nil && inc.TriagedAt != nil {
		end := inc.TriagedAt.Add(e.Cooldown)
		if end.After(*ready) {
			ready = &end
		}
	}
	return "evidence", ready
}

// 执行身份和尝试记录同事务创建；抢占失败不留假尝试，接管时旧尝试明确记为中断。
func (e *Engine) beginRun(ctx context.Context, inc *ent.Incident, started time.Time, model string) (*ent.TriageRun, error) {
	tx, err := e.DB.Tx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	claim := tx.Incident.Update().Where(incident.IDEQ(inc.ID), incident.StatusIn("open", "triaged"),
		incident.Or(incident.TriageStartedAtIsNil(), incident.TriageHeartbeatAtIsNil(), incident.TriageHeartbeatAtLTE(started.Add(-RunningTTL)))).
		SetTriageStartedAt(started).SetTriageHeartbeatAt(started)
	if workFollowup(inc, started) {
		claim.Where(incidentwork.Due(started))
	}
	if needsCapabilityUpgrade(inc) {
		claim.Where(capabilityDue(started, e.Cooldown))
	}
	n, err := claim.Save(ctx)
	if err != nil || n == 0 {
		return nil, err
	}
	if _, err = tx.TriageRun.Update().Where(triagerun.IncidentIDEQ(inc.ID), triagerun.StatusEQ(triagerun.StatusRunning)).
		SetStatus(triagerun.StatusInterrupted).SetErrorCode("lease_replaced").SetFinishedAt(started).Save(ctx); err != nil {
		return nil, err
	}
	current, err := tx.Incident.Get(ctx, inc.ID)
	if err != nil {
		return nil, err
	}
	reason, ready := e.runTrigger(current)
	if current.TriageRetryAt != nil && ready != nil && current.TriageRetryAt.After(*ready) {
		ready = current.TriageRetryAt
	}
	if reason == "autonomy_followup" && current.Work != nil {
		work := *current.Work
		work.Attempts++
		if err := tx.Incident.UpdateOneID(inc.ID).SetWork(&work).Exec(ctx); err != nil {
			return nil, err
		}
	}
	row, err := tx.TriageRun.Create().SetIncidentID(inc.ID).SetStartedAt(started).SetNillableReadyAt(ready).SetTrigger(reason).SetModel(model).Save(ctx)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return row, nil
}

// 推理服务没给出回答的失败（超时、连不上）：怪不到证据或模型输出上，不消耗按次数封顶的重研判资格
const (
	inferenceTimeout = "inference_timeout"
	transportFailure = "inference_unreachable"
)

func runUpdate(db *ent.Client, row *ent.TriageRun, timing *runTiming, finished time.Time) *ent.TriageRunUpdateOne {
	return db.TriageRun.UpdateOneID(row.ID).Where(triagerun.StatusEQ(triagerun.StatusRunning)).
		SetFinishedAt(finished).SetDurationMs(max(0, finished.Sub(row.StartedAt).Milliseconds())).
		SetToolDetails(timing.tools).SetModelMs(timing.modelMS).SetToolMs(timing.toolMS).SetModelCalls(timing.modelCalls).
		SetToolCalls(timing.toolCalls).SetToolErrors(timing.toolErrors).SetInputTokens(timing.input).SetOutputTokens(timing.output)
}

func (e *Engine) failRun(row *ent.TriageRun, timing *runTiming, stage string, cause error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	status := triagerun.StatusFailed
	if errors.Is(cause, context.Canceled) {
		status = triagerun.StatusInterrupted
		stage = "canceled"
	}
	if errors.Is(cause, context.DeadlineExceeded) {
		stage = "timeout"
	}
	var transport *LLMTransportError
	if errors.As(cause, &transport) {
		stage = transportFailure
		if transport.Timeout > 0 {
			// 推理没跑完，不是研判失败：记成中断，等稍后重试
			stage, status = inferenceTimeout, triagerun.StatusInterrupted
		}
	}
	if err := runUpdate(e.DB, row, timing, time.Now()).SetStatus(status).SetErrorCode(stage).Exec(ctx); err != nil && !ent.IsNotFound(err) {
		slog.Error("保存研判尝试失败", "run", row.ID, "err", err)
	}
}

func workFollowup(inc *ent.Incident, now time.Time) bool {
	return inc.Status == "triaged" && !review.IsRetriage(inc) && !review.IsUrgent(inc) && !needsCapabilityUpgrade(inc) && inc.Work != nil && inc.Work.Owner == "ai" && inc.Work.Stage == "followup" && inc.Work.Attempts < incidentwork.MaxAttempts && inc.WorkNextCheckAt != nil && !inc.WorkNextCheckAt.After(now)
}
