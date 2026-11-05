package findings

import (
	"context"
	"encoding/json"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/finding"
	"openxdr/server/ent/predicate"
)

const FollowupTask = "ops-followup"
const BatchSize = 3
const RepairBudget = 3

// Work 只记录当前调查计划与真实引用，不把模型判断当成人工授权。
type Work struct {
	Version               int         `json:"version,omitempty"`
	InvestigationAttempts int         `json:"investigation_attempts,omitempty"`
	RepairAttempts        int         `json:"repair_attempts,omitempty"`
	VerificationAttempts  int         `json:"verification_attempts,omitempty"`
	TransportFailures     int         `json:"transport_failures,omitempty"`
	OriginalTitle         string      `json:"original_title,omitempty"`
	OriginalProblem       string      `json:"original_problem,omitempty"`
	Stage                 string      `json:"stage"`
	Plan                  string      `json:"plan"`
	WakeOn                string      `json:"wake_on"`
	Blocker               string      `json:"blocker,omitempty"`
	EvidenceCommands      []uuid.UUID `json:"evidence_commands,omitempty"`
	EvidenceAt            *time.Time  `json:"evidence_at,omitempty"`
	EvidenceStale         bool        `json:"evidence_stale,omitempty"`
	RiskSince             *time.Time  `json:"risk_since,omitempty"`
	RiskObservedAt        *time.Time  `json:"risk_observed_at,omitempty"`
	RiskKind              string      `json:"risk_kind,omitempty"`
	RiskTarget            *RiskTarget `json:"risk_target,omitempty"`
	EscalatedAt           *time.Time  `json:"escalated_at,omitempty"`
	EscalationNotifiedAt  *time.Time  `json:"escalation_notified_at,omitempty"`
}

type RiskTarget struct {
	Kind    string    `json:"kind"`
	Mount   string    `json:"mount,omitempty"`
	AssetID uuid.UUID `json:"asset_id"`
}

func EncodeWork(w Work) json.RawMessage { b, _ := json.Marshal(w); return b }

// Snapshot 防止旧巡检计划覆盖并发新增的修复预留、证据或人工决定。
func Snapshot(f *ent.Finding) predicate.Finding {
	return func(s *sql.Selector) {
		if len(f.Work) == 0 {
			s.Where(sql.IsNull(s.C(finding.FieldWork)))
			return
		}
		s.Where(sql.P(func(b *sql.Builder) {
			b.Ident(s.C(finding.FieldWork)).WriteString(" = ").Arg(string(f.Work)).WriteString("::jsonb")
		}))
	}
}

// Claim 每轮只领取少量到期记录。租约随任务硬期限设置，节点退出后自动到期。
// 预算耗尽后仍由平台负责，但只做低频只读观察，不再主动修复。
func Claim(ctx context.Context, db *ent.Client, session *ent.AgentSession, now time.Time) ([]*ent.Finding, error) {
	tx, err := db.Tx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.Finding.Query().Where(
		finding.GroupIDEQ(session.GroupID), finding.StatusEQ("open"),
		finding.Or(finding.WorkOwnerEQ("ai"), finding.And(finding.WorkOwnerEQ("human"), func(s *sql.Selector) {
			s.Where(sql.ExprP(s.C(finding.FieldWork) + "->>'stage' = 'blocked'"))
		})),
		finding.Or(finding.WorkNextCheckAtIsNil(), finding.WorkNextCheckAtLTE(now)),
		finding.Or(finding.WorkLeaseUntilIsNil(), finding.WorkLeaseUntilLTE(now)),
	).Where(func(s *sql.Selector) {
		owned := sql.Table(asset.Table).As("work_asset")
		s.Where(sql.Exists(sql.Select(owned.C(asset.FieldID)).From(owned).Where(sql.And(sql.ColumnsEQ(owned.C(asset.FieldID), s.C(finding.FieldAssetID)), sql.EQ(owned.C(asset.FieldGroupID), session.GroupID)))))
		s.ForUpdate(sql.WithLockAction(sql.SkipLocked))
	}).Order(func(s *sql.Selector) {
		s.OrderExpr(sql.Expr("CASE " + s.C(finding.FieldSeverity) + " WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END"))
		s.OrderExpr(sql.Expr(s.C(finding.FieldWorkNextCheckAt) + " ASC NULLS FIRST"))
	}, ent.Asc(finding.FieldFirstSeen), ent.Asc(finding.FieldID)).Limit(BatchSize).All(ctx)
	if err != nil {
		return nil, err
	}
	lease := now.Add(30 * time.Minute)
	if session.RunDeadlineAt != nil && session.RunDeadlineAt.Before(lease) {
		lease = *session.RunDeadlineAt
	}
	claimed := make([]*ent.Finding, 0, len(rows))
	for _, f := range rows {
		allowed, err := tx.Asset.Query().Where(asset.IDEQ(f.AssetID), asset.GroupIDEQ(session.GroupID)).Exist(ctx)
		if err != nil {
			return nil, err
		}
		if !allowed {
			continue
		}
		var prior Work
		if err := json.Unmarshal(f.Work, &prior); err != nil && len(f.Work) > 0 {
			return nil, err
		}
		if prior.OriginalTitle == "" {
			prior.OriginalTitle = f.Title
		}
		if prior.OriginalProblem == "" {
			prior.OriginalProblem = f.Detail
		}
		prior.Version = 2
		prior.InvestigationAttempts = f.WorkAttempts + 1
		prior.Stage = "investigating"
		if prior.Plan == "" {
			prior.Plan = "先只读复查现状；在明确授权范围内最小修复，再独立验证"
		}
		if prior.RepairAttempts >= RepairBudget {
			prior.Stage = "monitoring"
		}
		if prior.Blocker != "" {
			prior.Stage = "blocked"
		}
		if len(prior.EvidenceCommands) > 0 && (prior.EvidenceAt == nil || prior.EvidenceAt.Before(now.Add(-time.Hour))) {
			prior.EvidenceStale = true
		}
		f, err = tx.Finding.UpdateOneID(f.ID).SetWorkSessionID(session.ID).SetWorkLeaseUntil(lease).
			AddWorkAttempts(1).SetWork(EncodeWork(prior)).Save(ctx)
		if err != nil {
			return nil, err
		}
		claimed = append(claimed, f)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return claimed, nil
}

// Release 无论模型成功、失败或超时都释放本次领取，不把未复查的待办标为修复。
func Release(ctx context.Context, db *ent.Client, session uuid.UUID, now time.Time, failed ...bool) error {
	rows, err := db.Finding.Query().Where(finding.WorkSessionIDEQ(session), finding.StatusEQ("open")).All(ctx)
	if err != nil {
		return err
	}
	for _, f := range rows {
		var w Work
		if err := json.Unmarshal(f.Work, &w); err != nil && len(f.Work) > 0 {
			return err
		}
		if len(failed) > 0 && failed[0] {
			w.TransportFailures++
		}
		delay := time.Hour
		if w.RepairAttempts >= RepairBudget || w.Blocker != "" || f.WorkAttempts >= 3 {
			delay = 24 * time.Hour
		} else if f.WorkAttempts > 1 {
			delay = 4 * time.Hour
		}
		if f.Severity == "high" && w.EscalatedAt == nil {
			delay = time.Hour
		}
		if w.RiskSince != nil && w.EscalatedAt == nil {
			delay = 15 * time.Minute
		}
		next := now.Add(delay)
		if f.WorkNextCheckAt != nil && f.WorkNextCheckAt.After(now) && f.WorkNextCheckAt.Before(next) {
			next = *f.WorkNextCheckAt
		}
		if w.Stage == "investigating" {
			w.Stage = "waiting"
		}
		_, err = db.Finding.Update().Where(finding.IDEQ(f.ID), finding.StatusEQ("open"), finding.WorkSessionIDEQ(session), Snapshot(f)).
			SetWorkNextCheckAt(next).SetWork(EncodeWork(w)).ClearWorkSessionID().ClearWorkLeaseUntil().Save(ctx)
		if err != nil {
			return err
		}
	}
	return nil
}
