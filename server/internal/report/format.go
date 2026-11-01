package report

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// 报告统一格式：标题与一句话结论由平台渲染在页头，正文按固定的二级标题分节。
// 结论、需要人处理、未验证三节必须有（没有就写「无」），读的人每份报告都在同一个位置找到同一类信息。
const (
	MaxTitle   = 50
	MaxSummary = 120
)

// Sections 正文的节，按这个顺序写；Required 为必须出现的节
var (
	Sections = []string{"结论", "已执行的操作", "需要人处理", "证据", "推断", "未验证"}
	Required = []string{"结论", "需要人处理", "未验证"}
)

// Template 给模型看的正文骨架，报告不合格时原样带回去
const Template = `## 结论
≤3 行：总体定性（🟢 正常 / 🟡 需关注 / 🔴 紧急）+ 异常与正常主机分布统计。
## 已执行的操作
本轮 AI 已自主完成的动作（同步待办、写入/更新记忆、标记服务或外联、提议抑制/结案等），每条 1 行；只读无改动写「无」或省略。
## 需要人处理
按「### 🔴 紧急 / 新增」「### 🟡 仍未解决」「### ✅ 本轮已修复」列出，每条限 1–2 行（**[主机] 事项** — 影响 + 处置建议）；没有写「无」。
## 证据
仅异常先行：无异常主机合并为一张紧凑表格或一句话（严禁逐台展开「未见异常」）；有异常主机只列支撑异常的核心证据（≤4 条/台）。
## 推断
基于证据的简短判断与把握度，≤3 条，没有可省略。
## 未验证
合并为 ≤3 条单行列表，没有写「无」。`

var (
	h1      = regexp.MustCompile(`^#\s+\S`)
	section = regexp.MustCompile(`(?m)^##\s+(.+?)\s*$`)
)

func cleanHeading(s string) string {
	return strings.TrimLeftFunc(strings.TrimSpace(s), func(r rune) bool {
		if strings.ContainsRune("一二三四五六七八九十、.0123456789 \t", r) {
			return true
		}
		return !unicode.Is(unicode.Han, r) && !unicode.IsLetter(r)
	})
}

// Normalize 校验并整理一份报告：标题与结论去掉首尾空白并限长，正文去掉模型自己写的一级标题（页头已经有标题），
// 必需的节缺了就拒绝并带回骨架。返回值可直接入库。
func Normalize(title, summary, markdown string) (string, string, string, error) {
	title, summary = strings.TrimSpace(title), strings.TrimSpace(summary)
	if n := utf8.RuneCountInString(title); n == 0 || n > MaxTitle {
		return "", "", "", fmt.Errorf("标题须为 1–%d 字（现在 %d 字）：写成「对象 + 主题」，比如「pve1/pve2 每日巡检」，结论放 summary", MaxTitle, n)
	}
	if n := utf8.RuneCountInString(summary); n == 0 || n > MaxSummary || strings.ContainsAny(summary, "\r\n") {
		return "", "", "", fmt.Errorf("summary 须为一句话结论，1–%d 字、不换行（现在 %d 字），比如「pve2 RAID 电池故障待更换，其余正常」", MaxSummary, n)
	}
	markdown = stripTitle(markdown)
	if markdown == "" || len(markdown) > 262144 {
		return "", "", "", errors.New("正文长度无效")
	}
	have := map[string]bool{}
	for _, m := range section.FindAllStringSubmatch(markdown, -1) {
		cleaned := cleanHeading(m[1])
		for _, name := range Sections {
			if strings.HasPrefix(cleaned, name) {
				have[name] = true
			}
		}
	}
	var missing []string
	for _, name := range Required {
		if !have[name] {
			missing = append(missing, "## "+name)
		}
	}
	if len(missing) > 0 {
		return "", "", "", fmt.Errorf("正文缺少 %s。按这个骨架分节（二级标题照写，节内自由组织）：\n%s", strings.Join(missing, "、"), Template)
	}
	return title, summary, markdown, nil
}

// SplitFold 将报告正文拆成首屏决策层（结论、已执行的操作、需要人处理）与可折叠取证层（证据、推断、未验证）。
func SplitFold(markdown string) (top, fold string) {
	markdown = stripTitle(markdown)
	lines := strings.Split(markdown, "\n")
	var topBlocks, foldBlocks []string
	var cur []string
	curIsFold := false
	flush := func() {
		if len(cur) == 0 {
			return
		}
		block := strings.TrimSpace(strings.Join(cur, "\n"))
		if block != "" {
			if curIsFold {
				foldBlocks = append(foldBlocks, block)
			} else {
				topBlocks = append(topBlocks, block)
			}
		}
		cur = nil
	}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "## ") && !strings.HasPrefix(trimmed, "### ") {
			flush()
			h := cleanHeading(strings.TrimPrefix(trimmed, "## "))
			curIsFold = strings.HasPrefix(h, "证据") || strings.HasPrefix(h, "推断") || strings.HasPrefix(h, "未验证")
		}
		cur = append(cur, line)
	}
	flush()
	return strings.Join(topBlocks, "\n\n"), strings.Join(foldBlocks, "\n\n")
}

// stripTitle 去掉正文开头的一级标题：标题由平台渲染，正文里再写一遍就重复了
func stripTitle(markdown string) string {
	markdown = strings.TrimSpace(markdown)
	if first, rest, _ := strings.Cut(markdown, "\n"); h1.MatchString(first) {
		return strings.TrimSpace(rest)
	}
	return markdown
}
