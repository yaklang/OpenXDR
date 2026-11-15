package questions

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/fact"
	"openxdr/server/ent/question"
	"openxdr/server/internal/facts"
)

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
		if q.SubjectKind == "asset" || q.SubjectKind == "change" {
			assets = append(assets, uuid.MustParse(q.Subject))
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
		id, err := uuid.Parse(subject)
		if err != nil {
			return "?"
		}
		if h := safeHost(hostnames[id]); h != "" {
			return defang(h)
		}
		return facts.Ref("A", id)
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

// Run 单活循环：每小时检查一次将到期的授权
func Run(ctx context.Context, db *ent.Client) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		if n, err := RenewalSweep(ctx, db, time.Now()); err != nil && ctx.Err() == nil {
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
