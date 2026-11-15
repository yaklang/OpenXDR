package questions

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/fact"
	"openxdr/server/ent/finding"
	"openxdr/server/ent/incident"
	"openxdr/server/ent/question"
	"openxdr/server/ent/schema"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/facts"
)

// StaleQuestionAge 关联待办与事件均已解决后，未答问题自动作废的静默等待时间
const StaleQuestionAge = 24 * time.Hour

// Digest 待答问题总数与按主题的一行摘要，给每日群消息用。
// 群里不止管理员一人：只放类型、格式受限的对象与影响面，钥匙注释、命令行、提问原文这类攻击者可控的内容一概不放；
// 域名与主机名去掉点号的链接化，防止被渲染成可点的链接
func Digest(ctx context.Context, db *ent.Client, limit int) (int, []string, error) {
	rows, err := db.Question.Query().Where(question.StatusEQ("open")).Order(ent.Asc(question.FieldCreatedAt)).All(ctx)
	if err != nil || len(rows) == 0 {
		return 0, nil, err
	}
	var assets []uuid.UUID
	for _, q := range rows {
		if id, ok := SubjectAsset(q.SubjectKind, q.Subject); ok {
			assets = append(assets, id)
		}
	}
	names := map[uuid.UUID]string{}
	if len(assets) > 0 {
		hosts, err := db.Asset.Query().Where(asset.IDIn(assets...)).Select(asset.FieldID, asset.FieldHostname).All(ctx)
		if err != nil {
			return 0, nil, err
		}
		for _, h := range hosts {
			names[h.ID] = h.Hostname
		}
	}
	lines := make([]string, 0, min(len(rows), limit))
	for i, q := range rows {
		if i == limit {
			lines = append(lines, fmt.Sprintf("…另有 %d 个", len(rows)-limit))
			break
		}
		lines = append(lines, fmt.Sprintf("%s %s｜%s %s｜%d 个事件、%d 条待办", Ref(q.ID), KindNames[q.Kind], SubjectNames[q.SubjectKind],
			Label(q.SubjectKind, q.Subject, names), len(q.IncidentIds), len(q.FindingIds)))
	}
	return len(rows), lines, nil
}

// Label 主题对象的短标签：指纹截短、域名去链接化、主机名只留安全字符
func Label(kind, subject string, hostnames map[uuid.UUID]string) string {
	switch kind {
	case "key":
		if len(subject) > 19 {
			return subject[:19] + "…"
		}
		return subject
	case "domain":
		return defang(subject)
	case "asset", "change":
		id, ok := SubjectAsset(kind, subject)
		if !ok {
			return "?"
		}
		label := facts.Ref("A", id)
		if h := safeHost(hostnames[id]); h != "" {
			label = defang(h)
		}
		// 变更标识字符集受限，仍去掉点号免得被渲染成链接
		if key := changeKey(subject); kind == "change" && key != "" {
			label += " · " + defang(key)
		}
		return label
	case "rule":
		return facts.Ref("R", uuid.MustParse(subject))
	case "fact":
		return facts.Ref("F", uuid.MustParse(subject))
	}
	return subject
}

func defang(s string) string { return strings.ReplaceAll(s, ".", "[.]") }

func safeHost(h string) string {
	var b strings.Builder
	for _, r := range h {
		if r < 128 && (r == '-' || r == '_' || r == '.' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			b.WriteRune(r)
		}
		if b.Len() >= 63 {
			break
		}
	}
	return b.String()
}

// RenewalSweep 授权类事实（作答写回的 authorization: / permission: 主题）到期前 RenewBefore 提一个「是否续期」的问题；
// 同一到期周期只问一次，续期后到期时间后移才进入下一周期
func RenewalSweep(ctx context.Context, db *ent.Client, now time.Time) (int, error) {
	rows, err := db.Fact.Query().Where(facts.Live(now), fact.ExpiresAtLTE(now.Add(RenewBefore)),
		fact.Or(fact.SubjectHasPrefix("authorization:"), fact.SubjectHasPrefix("permission:"))).Limit(200).All(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, f := range rows {
		asked, err := db.Question.Query().Where(question.SubjectKindEQ("fact"), question.SubjectEQ(f.ID.String()),
			question.CreatedAtGTE(f.ExpiresAt.Add(-RenewBefore-time.Hour))).Exist(ctx)
		if err != nil {
			return n, err
		}
		if asked {
			continue
		}
		req := Request{Kind: "authorization", SubjectKind: "fact", Subject: f.ID.String(), Source: "renewal", Ref: facts.Ref("F", f.ID),
			Note: "授权事实将于 " + f.ExpiresAt.Format(time.RFC3339) + " 到期：" + f.Content, CreatedBy: "system"}
		if f.GroupID != nil {
			req.Groups = []uuid.UUID{*f.GroupID}
		}
		if f.AssetID != nil {
			req.Assets = []uuid.UUID{*f.AssetID}
		}
		if _, err := Ask(ctx, db, req, now); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// VoidSweep 把关联待办与事件全部已解决/已关闭、且悬置超过 StaleQuestionAge 的待答问题自动作废并留审计（不写事实）
func VoidSweep(ctx context.Context, db *ent.Client, now time.Time) (int, error) {
	cutoff := now.Add(-StaleQuestionAge)
	rows, err := db.Question.Query().
		Where(question.StatusEQ("open"), question.CreatedAtLTE(cutoff)).
		Order(ent.Asc(question.FieldCreatedAt)).Limit(200).All(ctx)
	if err != nil || len(rows) == 0 {
		return 0, err
	}
	voided := 0
	for _, q := range rows {
		if len(q.FindingIds) == 0 && len(q.IncidentIds) == 0 {
			continue
		}
		ok, err := voidIfAllResolved(ctx, db, q.ID, cutoff, now)
		if err != nil {
			return voided, err
		}
		if ok {
			voided++
		}
	}
	return voided, nil
}

func voidIfAllResolved(ctx context.Context, db *ent.Client, id uuid.UUID, cutoff, now time.Time) (bool, error) {
	tx, err := db.Tx(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	q, err := tx.Question.Query().Where(question.IDEQ(id)).Where(func(s *sql.Selector) { s.ForUpdate() }).Only(ctx)
	if ent.IsNotFound(err) {
		return false, nil
	}
	if err != nil || q.Status != "open" || q.CreatedAt.After(cutoff) {
		return false, err
	}
	if len(q.FindingIds) == 0 && len(q.IncidentIds) == 0 {
		return false, nil
	}

	totalLinked := 0
	if len(q.FindingIds) > 0 {
		fTotal, err := tx.Finding.Query().Where(finding.IDIn(q.FindingIds...)).Count(ctx)
		if err != nil {
			return false, err
		}
		totalLinked += fTotal
		hasOpen, err := tx.Finding.Query().Where(finding.IDIn(q.FindingIds...), finding.StatusEQ("open")).Exist(ctx)
		if err != nil || hasOpen {
			return false, err
		}
	}
	if len(q.IncidentIds) > 0 {
		iTotal, err := tx.Incident.Query().Where(incident.IDIn(q.IncidentIds...)).Count(ctx)
		if err != nil {
			return false, err
		}
		totalLinked += iTotal
		hasOpen, err := tx.Incident.Query().Where(incident.IDIn(q.IncidentIds...), incident.StatusIn("open", "triaged")).Exist(ctx)
		if err != nil || hasOpen {
			return false, err
		}
	}
	if totalLinked == 0 {
		return false, nil
	}

	n, err := tx.Question.Update().Where(question.IDEQ(q.ID), question.StatusEQ("open")).
		SetStatus("voided").
		SetAnsweredBy("system").
		SetAnsweredAt(now).
		SetAnswer(&schema.QuestionAnswer{Choice: "voided_resolved", Content: "关联待办均已解决"}).
		Save(ctx)
	if err != nil || n == 0 {
		return false, err
	}
	detail := fmt.Sprintf("%s %s %s %s 已作废：关联待办均已解决（关联事件=%d 关联待办=%d）",
		Ref(q.ID), q.Kind, q.SubjectKind, q.Subject, len(q.IncidentIds), len(q.FindingIds))
	if err := audit.Checked(ctx, tx.AuditLog.Create(), "system", "server", "question_voided", q.ID.String(), detail); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// BackfillSweep 对存量待答问题执行两项收敛：
//  1. 确定性查找已能直接作答的（如平台自身组件、新登记的同主题事实、已续期的事实），自动结为 answered 并唤醒阻塞待办（退役资产交由 assetretire 统一作废）；
//  2. 尚未能作答但已有背景事实的（如授权问题对应的钥匙归属事实），补挂进问题证据，免去管理员再去翻事实表。
func BackfillSweep(ctx context.Context, db *ent.Client, now time.Time) (answered int, enriched int, err error) {
	rows, err := db.Question.Query().Where(question.StatusEQ("open")).Order(ent.Asc(question.FieldCreatedAt)).Limit(200).All(ctx)
	if err != nil || len(rows) == 0 {
		return 0, 0, err
	}
	for _, q := range rows {
		req := Request{Kind: q.Kind, SubjectKind: q.SubjectKind, Subject: q.Subject, Groups: q.GroupIds}
		res, err := Lookup(ctx, db, req, now)
		if err != nil {
			return answered, enriched, err
		}
		if res.Answered {
			// 只靠退役资产命中的问题交由 assetretire 标为 voided_retired，保持退役口径一致
			if len(res.Facts) == 0 && len(res.Records) > 0 && !slices.ContainsFunc(res.Records, func(r Record) bool { return r.Kind != "asset_retired" }) {
				continue
			}
			ok, err := autoAnswerOpen(ctx, db, q.ID, res, now)
			if err != nil {
				return answered, enriched, err
			}
			if ok {
				answered++
			}
			continue
		}
		pinned := contextEvidences(res.Context, now)
		if len(pinned) == 0 {
			continue
		}
		if _, changed := mergeEvidence(q.Evidence, pinned, nil); !changed {
			continue
		}
		ok, err := attachPinnedEvidence(ctx, db, q.ID, pinned, now)
		if err != nil {
			return answered, enriched, err
		}
		if ok {
			enriched++
		}
	}
	return answered, enriched, nil
}

func autoAnswerOpen(ctx context.Context, db *ent.Client, id uuid.UUID, res *Result, now time.Time) (bool, error) {
	tx, err := db.Tx(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	q, err := tx.Question.Query().Where(question.IDEQ(id)).Where(func(s *sql.Selector) { s.ForUpdate() }).Only(ctx)
	if ent.IsNotFound(err) {
		return false, nil
	}
	if err != nil || q.Status != "open" {
		return false, err
	}
	var parts, refs []string
	for _, f := range res.Facts {
		r := facts.Ref("F", f.ID)
		refs = append(refs, r)
		parts = append(parts, r+" "+f.Content)
	}
	for _, rec := range res.Records {
		refs = append(refs, rec.Ref)
		parts = append(parts, rec.Detail)
	}
	summary := strings.Join(parts, "；")
	if summary == "" {
		summary = "已满足确定性条件"
	}
	u := tx.Question.Update().Where(question.IDEQ(q.ID), question.StatusEQ("open")).
		SetStatus("answered").
		SetAnsweredBy("system").
		SetAnsweredAt(now).
		SetAnswer(&schema.QuestionAnswer{Choice: "auto_lookup", Content: summary})
	if len(res.Facts) > 0 {
		u.SetFactID(res.Facts[0].ID)
	}
	n, err := u.Save(ctx)
	if err != nil || n == 0 {
		return false, err
	}
	requeued, err := requeue(ctx, tx, q, now)
	if err != nil {
		return false, err
	}
	detail := fmt.Sprintf("%s %s %s %s refs=%s 重新排队待办=%d",
		Ref(q.ID), q.Kind, q.SubjectKind, q.Subject, strings.Join(refs, ","), requeued)
	if err := audit.Checked(ctx, tx.AuditLog.Create(), "system", "server", "controller_answered", q.ID.String(), detail); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	if len(res.Facts) > 0 {
		_ = facts.Cite(ctx, db, &facts.Brief{Facts: res.Facts}, now)
	}
	return true, nil
}

func attachPinnedEvidence(ctx context.Context, db *ent.Client, id uuid.UUID, pinned []schema.QuestionEvidence, now time.Time) (bool, error) {
	tx, err := db.Tx(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	q, err := tx.Question.Query().Where(question.IDEQ(id)).Where(func(s *sql.Selector) { s.ForUpdate() }).Only(ctx)
	if ent.IsNotFound(err) {
		return false, nil
	}
	if err != nil || q.Status != "open" {
		return false, err
	}
	merged, changed := mergeEvidence(q.Evidence, pinned, nil)
	if !changed {
		return false, nil
	}
	if err := tx.Question.UpdateOneID(q.ID).SetEvidence(merged).SetUpdatedAt(now).Exec(ctx); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// Run 单活循环：定期执行过时问题自动作废、存量待答问题确定性收敛/背景补挂、将到期授权续期提醒
func Run(ctx context.Context, db *ent.Client) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	// 变更授权曾被按资产跨问题复用：上线这一版时把错误自动作答的置回待答
	if n, err := ReopenCrossChangeAnswers(ctx, db, time.Now()); err != nil && ctx.Err() == nil {
		slog.Error("变更问题跨问题自动作答回滚失败", "err", err)
	} else if n > 0 {
		slog.Warn("变更问题跨问题自动作答已置回待答", "count", n)
	}
	for {
		now := time.Now()
		if n, err := VoidSweep(ctx, db, now); err != nil && ctx.Err() == nil {
			slog.Error("过时问题自动作废失败", "err", err)
		} else if n > 0 {
			slog.Info("过时总控问题已自动作废", "count", n)
		}
		if ans, enr, err := BackfillSweep(ctx, db, now); err != nil && ctx.Err() == nil {
			slog.Error("待答问题确定性收敛失败", "err", err)
		} else if ans+enr > 0 {
			slog.Info("待答问题确定性收敛完成", "answered", ans, "enriched", enr)
		}
		if n, err := RenewalSweep(ctx, db, now); err != nil && ctx.Err() == nil {
			slog.Error("授权到期续期提问失败", "err", err)
		} else if n > 0 {
			slog.Info("已提出授权续期问题", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
