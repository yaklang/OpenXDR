package closurereview

import (
	"context"
	"encoding/json"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent/asset"
	"openxdr/server/internal/questions"
)

// askMissing 审计员因「行为超出已登记事实范围」拒绝时，按它给出的结构化缺口向总控提问（同主题合并）。
// 缺口对象必须在材料里出现过：模型不能凭空造问题，事件原文里的注入也只能让管理员多看到一个材料里本来就有的对象。
// 提问失败只记日志：审计结论已落库，不因提问失败回滚
func (r *Reviewer) askMissing(ctx context.Context, m *material, d Decision, hash string) {
	if len(d.MissingFacts) == 0 {
		return
	}
	raw, _ := json.Marshal(m)
	text := strings.ToLower(string(raw))
	var hosts []uuid.UUID
	for _, h := range m.Benign.Hosts {
		hosts = append(hosts, h.ID)
	}
	rows, err := r.DB.Asset.Query().Where(asset.IDIn(hosts...)).All(ctx)
	if err != nil {
		slog.Error("结案审计缺口提问失败", "incident", m.IncidentID, "err", err)
		return
	}
	var groups []uuid.UUID
	for _, a := range rows {
		if a.GroupID != nil && !slices.Contains(groups, *a.GroupID) {
			groups = append(groups, *a.GroupID)
		}
	}
	note := d.Reason
	if len([]rune(note)) > 400 {
		note = string([]rune(note)[:400])
	}
	for _, mf := range d.MissingFacts {
		subject, ok := missingSubject(mf, m, text)
		if !ok {
			continue
		}
		req := questions.Request{Kind: mf.Kind, SubjectKind: mf.SubjectKind, Subject: subject, Groups: groups, Assets: hosts,
			Incident: &m.IncidentID, Source: "closure_review", Ref: "snapshot=" + hash[:16], Note: note, CreatedBy: Actor}
		if _, err := questions.Ask(ctx, r.DB, req, time.Now()); err != nil {
			slog.Warn("结案审计缺口提问失败", "incident", m.IncidentID, "subject_kind", mf.SubjectKind, "err", err)
		}
	}
}

// missingSubject 核对缺口：类型在范围内，主机名换成本事件的资产 ID，其余对象须在材料原文里出现
func missingSubject(mf MissingFact, m *material, text string) (string, bool) {
	subject := strings.TrimSpace(mf.Subject)
	if !slices.Contains([]string{"authorization", "owner", "policy"}, mf.Kind) {
		return "", false
	}
	switch mf.SubjectKind {
	case "asset":
		i := slices.IndexFunc(m.Benign.Hosts, func(h benignHost) bool { return h.Hostname == subject || h.ID.String() == subject })
		if i < 0 {
			return "", false
		}
		return m.Benign.Hosts[i].ID.String(), true
	case "domain", "ip", "key":
		return subject, len(subject) >= 3 && strings.Contains(text, strings.ToLower(subject))
	}
	return "", false
}
