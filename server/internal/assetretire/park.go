package assetretire

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/finding"
	"openxdr/server/ent/question"
	"openxdr/server/ent/schema"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/facts"
	"openxdr/server/internal/findings"
	"openxdr/server/internal/review"
)

var (
	ErrParked       = errors.New("主机已处于停机保留状态")
	ErrNotParked    = errors.New("主机未处于停机保留状态")
	ErrNoParkReason = errors.New("请填写停机保留原因")
)

const maxParkReason = 500

// Park 把主机设为「停机保留」：管理员确认主机按计划关机保留，不再产生静默/失联告警与待办，
// Pi 不再跟进该主机，已有未结的静默/采集失联待办自动按停机保留关闭，涉及该主机是否计划停机的待答问题随之收敛。
func Park(ctx context.Context, db *ent.Client, a *ent.Asset, actor, reason string, now time.Time) (*ent.Asset, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return nil, ErrNoParkReason
	}
	if utf8.RuneCountInString(reason) > maxParkReason {
		return nil, fmt.Errorf("停机保留原因最多 %d 字", maxParkReason)
	}
	tx, err := db.Tx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	cur, err := tx.Asset.Query().Where(asset.IDEQ(a.ID)).Where(func(s *sql.Selector) { s.ForUpdate() }).Only(ctx)
	if err != nil {
		return nil, err
	}
	if cur.RetiredAt != nil {
		return nil, ErrRetired
	}
	if cur.ParkedAt != nil {
		return nil, ErrParked
	}
	if err := tx.Asset.UpdateOneID(a.ID).
		SetParkedAt(now).SetParkedBy(actor).SetParkedReason(reason).
		ClearSilentSince().ClearHealthProblem().ClearSensorProblem().
		Exec(ctx); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	updated, err := db.Asset.Get(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	if findN, qN, err := sweepParkedAsset(ctx, db, updated, actor, now); err != nil {
		slog.Error("停机保留收敛关联待办或问题失败", "asset", a.ID, "err", err)
	} else if findN+qN > 0 {
		slog.Info("停机保留已收敛关联待办与问题", "asset", a.ID, "hostname", a.Hostname, "findings", findN, "questions", qN)
	}
	return updated, nil
}

// Unpark 取消「停机保留」，恢复正常的失联检测与运维跟进
func Unpark(ctx context.Context, db *ent.Client, a *ent.Asset, now time.Time) (*ent.Asset, error) {
	n, err := db.Asset.Update().Where(asset.IDEQ(a.ID), asset.ParkedAtNotNil()).
		ClearParkedAt().ClearParkedBy().ClearParkedReason().Save(ctx)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, ErrNotParked
	}
	// 唤醒该主机上仍未结的非静默 AI 待办，使其恢复跟进
	if _, err := db.Finding.Update().
		Where(finding.AssetIDEQ(a.ID), finding.StatusEQ("open"), finding.WorkOwnerEQ("ai")).
		SetWorkNextCheckAt(now).Save(ctx); err != nil {
		slog.Warn("取消停机保留后唤醒遗留待办失败", "asset", a.ID, "err", err)
	}
	return db.Asset.Get(ctx, a.ID)
}

// FormatParked 生成可审计的停机保留说明
func FormatParked(a *ent.Asset) string {
	if a == nil || a.ParkedAt == nil {
		return ""
	}
	base := fmt.Sprintf("资产已于 %s 由 %s 设为停机保留（原因：%s），属于计划内关机保留",
		formatTime(a.ParkedAt),
		retiredActor(a.ParkedBy),
		retiredWhy(a.ParkedReason),
	)
	if h := strings.TrimSpace(a.Hostname); h != "" {
		return base + "（" + h + "）"
	}
	return base
}

// IsSilenceFinding 判断一条待办是否属于整机静默 / 失联 / 遥测中断类问题
func IsSilenceFinding(key, title string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	if strings.HasPrefix(k, "collect:") {
		return true
	}
	for _, kw := range []string{"silent", "offline", "unreachable", "telemetry-lost", "agent-down", "agent_down"} {
		if strings.Contains(k, kw) {
			return true
		}
	}
	for _, kw := range []string{"静默", "失联", "离线", "遥测中断", "采集中断"} {
		if strings.Contains(title, kw) {
			return true
		}
	}
	return false
}

func sweepParkedAsset(ctx context.Context, db *ent.Client, host *ent.Asset, actor string, now time.Time) (int, int, error) {
	openFindings, err := db.Finding.Query().Where(finding.AssetIDEQ(host.ID), finding.StatusEQ("open")).All(ctx)
	if err != nil {
		return 0, 0, err
	}
	summary := FormatParked(host)
	closedFindings := 0
	for _, f := range openFindings {
		if IsSilenceFinding(f.Key, f.Title) {
			note := "停机保留：" + summary
			var w findings.Work
			_ = json.Unmarshal(f.Work, &w)
			w.Stage = "resolved"
			w.Blocker, w.BlockedReason, w.BlockerDetail, w.BlockedRounds = "", "", "", 0
			w.Question = ""
			w.WakeOn = "human_reopen"
			w.Plan = note
			n, err := db.Finding.Update().Where(finding.IDEQ(f.ID), finding.StatusEQ("open"), findings.Snapshot(f)).
				SetStatus("resolved").SetResolvedAt(now).SetResolvedBy(review.ClosedBy).SetNote(note).
				ClearWorkSessionID().ClearWorkLeaseUntil().ClearWorkNextCheckAt().
				SetWork(findings.EncodeWork(w)).Save(ctx)
			if err != nil {
				return closedFindings, 0, err
			}
			if n > 0 {
				closedFindings++
				audit.System(ctx, db, "finding_status", f.ID.String(), "resolved "+note)
			}
			continue
		}
		// 非静默待办保留 open，但释放当前租约与下次跟进时间，停机保留期间不再轮询
		_, _ = db.Finding.Update().Where(finding.IDEQ(f.ID), finding.StatusEQ("open"), findings.Snapshot(f)).
			ClearWorkSessionID().ClearWorkLeaseUntil().ClearWorkNextCheckAt().Save(ctx)
	}

	// 该主机上挂着的「归属 / 策略」（如是否计划内停机）待答问题直接按停机保留记录收敛
	qs, err := db.Question.Query().Where(
		question.StatusEQ("open"),
		question.SubjectKindEQ("asset"),
		question.SubjectEQ(host.ID.String()),
		question.KindIn("owner", "policy"),
	).All(ctx)
	if err != nil {
		return closedFindings, 0, err
	}
	closedQuestions := 0
	for _, q := range qs {
		ok, err := answerParkedQuestion(ctx, db, q.ID, summary, actor, now)
		if err != nil {
			return closedFindings, closedQuestions, err
		}
		if ok {
			closedQuestions++
		}
	}
	return closedFindings, closedQuestions, nil
}

func answerParkedQuestion(ctx context.Context, db *ent.Client, qID uuid.UUID, summary, actor string, now time.Time) (bool, error) {
	tx, err := db.Tx(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	q, err := tx.Question.Query().Where(question.IDEQ(qID)).Where(func(s *sql.Selector) { s.ForUpdate() }).Only(ctx)
	if ent.IsNotFound(err) {
		return false, nil
	}
	if err != nil || q.Status != "open" {
		return false, err
	}
	n, err := tx.Question.Update().Where(question.IDEQ(q.ID), question.StatusEQ("open")).
		SetStatus("answered").
		SetAnsweredBy(actor).
		SetAnsweredAt(now).
		SetAnswer(&schema.QuestionAnswer{Choice: "parked", Content: summary}).
		Save(ctx)
	if err != nil || n == 0 {
		return false, err
	}
	// 若该问题还关联了其他未停机主机上的待办，解除其阻塞重新排队
	if len(q.FindingIds) > 0 {
		ref := facts.Ref("Q", q.ID)
		rows, err := tx.Finding.Query().Where(finding.IDIn(q.FindingIds...), finding.StatusEQ("open")).All(ctx)
		if err != nil {
			return false, err
		}
		for _, f := range rows {
			fh, err := tx.Asset.Get(ctx, f.AssetID)
			if err != nil || fh.RetiredAt != nil || fh.ParkedAt != nil {
				continue
			}
			var w findings.Work
			if err := json.Unmarshal(f.Work, &w); err != nil && len(f.Work) > 0 {
				continue
			}
			if w.Question != ref {
				continue
			}
			w.Blocker, w.BlockedReason, w.BlockerDetail, w.BlockedRounds = "", "", "", 0
			w.Stage, w.WakeOn, w.LastWakeReason = "waiting", "next_check", "总控问题 "+ref+" 已由停机保留应答"
			w.Plan = "关联主机已设为停机保留，按最新资产状态重新评估其余涉事主机"
			w.Question = ""
			_, _ = tx.Finding.Update().Where(finding.IDEQ(f.ID), finding.StatusEQ("open"), findings.Snapshot(f)).
				SetWorkOwner("ai").SetWorkNextCheckAt(now).SetWork(findings.EncodeWork(w)).Save(ctx)
		}
	}
	detail := fmt.Sprintf("%s %s %s %s choice=parked %s", facts.Ref("Q", q.ID), q.Kind, q.SubjectKind, q.Subject, summary)
	if err := audit.Checked(ctx, tx.AuditLog.Create(), actor, "server", "question_answered", q.ID.String(), detail); err != nil {
		return false, err
	}
	return true, tx.Commit()
}
