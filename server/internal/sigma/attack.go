package sigma

import (
	"regexp"
	"sort"
	"strings"
)

// ATT&CK 战术，按杀伤链顺序。矩阵要按这个顺序展示——
// 覆盖缺口在哪一环，比覆盖了多少条更有意义。
var attackTactics = []string{
	"reconnaissance",
	"resource-development",
	"initial-access",
	"execution",
	"persistence",
	"privilege-escalation",
	"defense-evasion",
	"credential-access",
	"discovery",
	"lateral-movement",
	"collection",
	"command-and-control",
	"exfiltration",
	"impact",
}

var tacticSet = func() map[string]bool {
	m := make(map[string]bool, len(attackTactics))
	for _, t := range attackTactics {
		m[t] = true
	}
	return m
}()

// Tactics 全部战术，按杀伤链顺序。
func Tactics() []string { return attackTactics }

// technique ID：T1059 或 T1059.001（含子技术）
var techniqueRe = regexp.MustCompile(`^t\d{4}(\.\d{3})?$`)

// parseAttackTags 从 Sigma tags 里提取 ATT&CK 战术与技术。
// Sigma 里战术写作 attack.defense_evasion，技术写作 attack.t1059.001；
// 其余标签（attack.g0016 组织、cve.xxx 等）与检测覆盖无关，丢掉。
func parseAttackTags(raw any) (tactics, techniques []string) {
	list, ok := raw.([]any)
	if !ok {
		return nil, nil
	}
	seenTactic := map[string]bool{}
	seenTech := map[string]bool{}
	for _, item := range list {
		tag, ok := item.(string)
		if !ok {
			continue
		}
		rest, ok := cutAttackPrefix(strings.ToLower(strings.TrimSpace(tag)))
		if !ok {
			continue
		}
		switch {
		case techniqueRe.MatchString(rest):
			id := strings.ToUpper(rest)
			if !seenTech[id] {
				seenTech[id] = true
				techniques = append(techniques, id)
			}
		default:
			// Sigma 用下划线，ATT&CK 官方用连字符，统一成后者
			name := strings.ReplaceAll(rest, "_", "-")
			if tacticSet[name] && !seenTactic[name] {
				seenTactic[name] = true
				tactics = append(tactics, name)
			}
		}
	}
	sort.Strings(techniques)
	return tactics, techniques
}

func cutAttackPrefix(tag string) (string, bool) {
	for _, prefix := range []string{"attack.", "attack:"} {
		if rest, ok := strings.CutPrefix(tag, prefix); ok {
			return rest, true
		}
	}
	return "", false
}
