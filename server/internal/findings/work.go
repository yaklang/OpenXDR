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
)

const FollowupTask = "ops-followup"
const BatchSize = 3
const RepairBudget = 3

// Work 只记录当前调查计划与真实引用，不把模型判断当成人工授权。
type Work struct {
	OriginalTitle    string      `json:"original_title,omitempty"`
	OriginalProblem  string      `json:"original_problem,omitempty"`
	Stage            string      `json:"stage"`
	Plan             string      `json:"plan"`
	WakeOn           string      `json:"wake_on"`
	Blocker          string      `json:"blocker,omitempty"`
	EvidenceCommands []uuid.UUID `json:"evidence_commands,omitempty"`
}

func EncodeWork(w Work) json.RawMessage { b, _ := json.Marshal(w); return b }

// Claim 每轮只领取少量到期记录。租约随任务硬期限设置，节点退出后自动到期。
// 预算耗尽后仍由平台负责，但只做低频只读观察，不再主动修复。
func Claim(ctx context.Context, db *ent.Client, session *ent.AgentSession, now time.Time) ([]*ent.Finding, error) {
	tx, err := db.Tx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.Finding.Query().Where(
		finding.GroupIDEQ(session.GroupID), finding.StatusEQ("open"), finding.WorkOwnerEQ("ai"),
		finding.Or(finding.WorkNextCheckAtIsNil(), finding.WorkNextCheckAtLTE(now)),
		finding.Or(finding.WorkLeaseUntilIsNil(), finding.WorkLeaseUntilLTE(now)),
	).Where(func(s *sql.Selector) { s.ForUpdate(sql.WithLockAction(sql.SkipLocked)) }).
		Order(ent.Asc(finding.FieldWorkNextCheckAt), ent.Asc(finding.FieldFirstSeen), ent.Asc(finding.FieldID)).Limit(BatchSize).All(ctx)
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
		_ = json.Unmarshal(f.Work, &prior)
		if prior.OriginalTitle == "" {
			prior.OriginalTitle = f.Title
		}
		if prior.OriginalProblem == "" {
			prior.OriginalProblem = f.Detail
		}
		stage, plan := "investigating", "先只读复查现状；仅在现有组授权范围内执行必要的最小可回滚修复，随后独立验证"
		if f.WorkAttempts >= RepairBudget {
			stage, plan = "monitoring", "主动修复预算已用尽，仅只读观察；新证据或人工重新打开后再评估"
		}
		f, err = tx.Finding.UpdateOneID(f.ID).SetWorkSessionID(session.ID).SetWorkLeaseUntil(lease).
			AddWorkAttempts(1).SetWork(EncodeWork(Work{OriginalTitle: prior.OriginalTitle, OriginalProblem: prior.OriginalProblem, Stage: stage, Plan: plan, WakeOn: "new_observation_or_next_check"})).Save(ctx)
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
func Release(ctx context.Context, db *ent.Client, session uuid.UUID, now time.Time) error {
	rows, err := db.Finding.Query().Where(finding.WorkSessionIDEQ(session), finding.StatusEQ("open")).All(ctx)
	if err != nil {
		return err
	}
	for _, f := range rows {
		delay := time.Hour
		if f.WorkAttempts >= RepairBudget {
			delay = 24 * time.Hour
		} else if f.WorkAttempts > 1 {
			delay = 4 * time.Hour
		}
		var w Work
		_ = json.Unmarshal(f.Work, &w)
		if w.Stage == "investigating" {
			w.Stage = "waiting"
		}
		_, err = db.Finding.Update().Where(finding.IDEQ(f.ID), finding.StatusEQ("open"), finding.WorkSessionIDEQ(session)).
			SetWorkNextCheckAt(now.Add(delay)).SetWork(EncodeWork(w)).ClearWorkSessionID().ClearWorkLeaseUntil().Save(ctx)
		if err != nil {
			return err
		}
	}
	return nil
}
