package closurereview

import (
	"context"
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
	raw, _ := encode(m)
	rawText := string(raw)
	var hosts []uuid.UUID
	for _, h := range m.hosts() {
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
		subject, ok := missingSubject(mf, m, rawText)
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

// missingSubject 核对缺口：类型在范围内，主机名换成本事件的资产 ID，其余对象须在材料原文里出现；
// 缩写钥匙指纹按去省略号后的前缀匹配材料中唯一出现的完整公钥指纹。
func missingSubject(mf MissingFact, m *material, rawText string) (string, bool) {
	subject := strings.TrimSpace(mf.Subject)
	if !slices.Contains([]string{"authorization", "owner", "policy"}, mf.Kind) {
		return "", false
	}
	switch mf.SubjectKind {
	case "asset":
		hs := m.hosts()
		i := slices.IndexFunc(hs, func(h benignHost) bool { return h.Hostname == subject || h.ID.String() == subject })
		if i < 0 {
			return "", false
		}
		return hs[i].ID.String(), true
	case "domain", "ip":
		return subject, len(subject) >= 3 && strings.Contains(strings.ToLower(rawText), strings.ToLower(subject))
	case "key":
		return resolveKeySubject(subject, rawText)
	}
	return "", false
}

// resolveKeySubject 核对或补全 SHA256 公钥指纹：完整指纹须在材料原文中精确出现；
// 缩写指纹去掉尾部省略号后按前缀匹配材料中的完整指纹，唯一命中才替换，零个或多个命中一律丢弃。
func resolveKeySubject(subject, rawText string) (string, bool) {
	candidates := fullKeyFingerprints(rawText)
	if isFullKeyFP(subject) {
		if !slices.Contains(candidates, subject) {
			return "", false
		}
		return subject, true
	}
	prefix := strings.TrimSpace(strings.TrimRight(subject, ".…"))
	b64, ok := strings.CutPrefix(prefix, "SHA256:")
	if !ok || b64 == "" || len(b64) > 43 {
		return "", false
	}
	for i := 0; i < len(b64); i++ {
		if !isBase64Char(b64[i]) {
			return "", false
		}
	}
	var matched string
	for _, fp := range candidates {
		if strings.HasPrefix(fp, prefix) {
			if matched != "" {
				return "", false
			}
			matched = fp
		}
	}
	return matched, matched != ""
}

func isFullKeyFP(s string) bool {
	b64, ok := strings.CutPrefix(s, "SHA256:")
	if !ok {
		return false
	}
	b64 = strings.TrimSuffix(b64, "=")
	if len(b64) != 43 {
		return false
	}
	for i := 0; i < len(b64); i++ {
		if !isBase64Char(b64[i]) {
			return false
		}
	}
	return true
}

func fullKeyFingerprints(text string) []string {
	const tag = "SHA256:"
	var out []string
	for rest := text; ; {
		idx := strings.Index(rest, tag)
		if idx < 0 {
			return out
		}
		after := rest[idx+len(tag):]
		n := 0
		for n < len(after) && isBase64Char(after[n]) {
			n++
		}
		end := n
		if n == 43 {
			if end < len(after) && after[end] == '=' {
				end++
			}
			if end == len(after) || (!isBase64Char(after[end]) && after[end] != '=') {
				fp := rest[idx : idx+len(tag)+end]
				if !slices.Contains(out, fp) {
					out = append(out, fp)
				}
			}
		}
		if n == 0 {
			rest = after
		} else {
			rest = after[n:]
		}
	}
}

func isBase64Char(b byte) bool {
	return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '+' || b == '/'
}
