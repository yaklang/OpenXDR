package closurereview

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/incident"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/questions"
	"openxdr/server/internal/review"
)

// stallError 结案审计确定结不掉的原因（不是等待）：AI 判了却结不了，事件必须交给人，不能静默挂着
type stallError struct {
	reason string
	// ask 缺的是这台主机的业务事实：交人的同时向总控提问，答一次同主机同类事件以后可自动结案
	ask *uuid.UUID
}

func (e *stallError) Error() string        { return e.reason }
func (e *stallError) Is(target error) bool { return target == ErrIneligible }

func stall(format string, args ...any) error {
	return &stallError{reason: fmt.Sprintf(format, args...)}
}

// settle 加载材料判为不合格时：等待类原因（安静期、研判后的新告警、研判在跑）什么都不做，确定结不掉的转人工
func (r *Reviewer) settle(ctx context.Context, id uuid.UUID, err error) error {
	var s *stallError
	if !errors.As(err, &s) {
		return nil
	}
	return r.handoff(ctx, id, s.reason, s.ask)
}

// handoff 只接 AI 静默自治中的事件（owner=ai、stage=monitoring）：改成人工复核并写明原因，进待复核列表与每日汇总。
// 研判结论和证据版本原样保留，新证据到来重研判时工作计划会重新交回 AI；已交人的事件结案审计照样可以在补上事实后自动结案。
func (r *Reviewer) handoff(ctx context.Context, id uuid.UUID, reason string, ask *uuid.UUID) error {
	inc, err := r.DB.Incident.Get(ctx, id)
	if err != nil {
		return err
	}
	if ask != nil {
		r.askHost(ctx, inc, *ask, reason)
	}
	if inc.Status != "triaged" || inc.TriagedAt == nil || inc.Work == nil {
		return nil
	}
	reason = review.HandoffPrefix + clip(reason, 300)
	w := *inc.Work
	// 早先由结案审计交出的事件每轮照样重审：结不掉的原因变了就改写，人看到的不能是已经不成立的旧原因
	refresh := w.Owner == "human" && w.Stage == "escalated" && w.ManualOwner == "" && !w.ManualLock && strings.HasPrefix(w.Reason, review.HandoffPrefix) && w.Reason != reason
	if !refresh && (w.Owner != "ai" || w.Stage != "monitoring") {
		return nil
	}
	w.Owner, w.Stage, w.Reason = "human", "escalated", reason
	n, err := r.DB.Incident.Update().Where(incident.IDEQ(id), incident.StatusEQ("triaged"), incident.TriagedAtEQ(*inc.TriagedAt)).SetWork(&w).ClearWorkNextCheckAt().Save(ctx)
	if err != nil || n == 0 {
		return err
	}
	slog.Info("结案审计结不掉，转人工", "incident", id, "reason", reason, "refresh", refresh)
	return audit.Checked(ctx, r.DB.AuditLog.Create(), Actor, "server", "incident_closure_handoff", id.String(), reason)
}

// askHost 高危告警所在主机没有写明业务的事实：问管理员这台主机的业务，同主机的问题按主题合并
func (r *Reviewer) askHost(ctx context.Context, inc *ent.Incident, hostID uuid.UUID, reason string) {
	host, err := r.DB.Asset.Get(ctx, hostID)
	if err != nil {
		slog.Warn("结案审计主机事实提问失败", "incident", inc.ID, "err", err)
		return
	}
	var groups []uuid.UUID
	if host.GroupID != nil {
		groups = append(groups, *host.GroupID)
	}
	req := questions.Request{Kind: "authorization", SubjectKind: "asset", Subject: hostID.String(), Groups: groups, Assets: []uuid.UUID{hostID},
		Incident: &inc.ID, Source: "closure_review", Note: reason + "：请写明这台主机的业务（资产角色），同类事件以后可由审计员自动结案", CreatedBy: Actor}
	if _, err := questions.Ask(ctx, r.DB, req, time.Now()); err != nil {
		slog.Warn("结案审计主机事实提问失败", "incident", inc.ID, "err", err)
	}
}

// retryable 服务端驳回了审计员的批准，或审计回复不合格：都是可纠正的失误，同一快照再审一次
func retryable(detail string) bool {
	return strings.Contains(detail, `"approve":true`) && strings.Contains(detail, " rejected=") ||
		strings.Contains(detail, invalidReason)
}

// serverFeedback 给第二次审计的驳回说明
func serverFeedback(detail string) string {
	if strings.Contains(detail, invalidReason) {
		return "上一次回复不合格（" + auditReason(detail) + "），请严格按格式只输出一个 JSON 对象，引用值保持简短完整"
	}
	return "上一次批准被服务端驳回：" + auditReason(detail) + "。请对照材料修正 event_ids 与 claims 后重新判断"
}

// auditReason 审计记录里最能说明结论的一句：服务端驳回原因优先，其次是审计员给的理由
func auditReason(detail string) string {
	// 分批审计记的是不过的那一批：「snapshot=… batch=2/5 approved=…」
	if f := strings.SplitN(detail, " ", 3); len(f) == 3 && strings.HasPrefix(f[1], "batch=") {
		return "第 " + strings.TrimPrefix(f[1], "batch=") + " 批：" + reasonOf(detail)
	}
	return reasonOf(detail)
}

func reasonOf(detail string) string {
	if _, why, ok := strings.Cut(detail, " rejected="); ok && why != "审计员未批准" {
		return clip(why, 200)
	}
	if _, rest, ok := strings.Cut(detail, `"reason":"`); ok {
		reason, _, _ := strings.Cut(rest, `","`)
		return clip(reason, 200)
	}
	return "审计员未批准"
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
