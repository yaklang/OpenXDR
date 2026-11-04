package suppressreview

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/schema"
	"openxdr/server/internal/commandreview"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
)

type stubCatalog []*sigma.Rule

func (s stubCatalog) Evaluate(int, string, map[string]any) []*sigma.Rule { return nil }
func (s stubCatalog) Rules() []*sigma.Rule                               { return s }
func (s stubCatalog) AuthorOf(string) string                             { return "" }
func (s stubCatalog) TitleOf(id string) string {
	for _, r := range s {
		if r.ID == id {
			return r.Title
		}
	}
	return ""
}

// 样本只列关键字段，每个值截断，超长的命令行不会把材料撑爆
func TestSampleBounded(t *testing.T) {
	detail := strings.Repeat("d", 1000)
	a := &ent.Alert{Ts: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), Count: 3, Detail: &detail}
	raw := map[string]any{
		"process":   map[string]any{"cmd_line": strings.Repeat("x", 5000), "file": map[string]any{"path": "/usr/bin/apt"}},
		"container": map[string]any{"runtime": "docker"},
		"secret":    strings.Repeat("s", 5000),
	}
	got := sample(a, raw, append(keyFields, "query.hostname"))
	for _, want := range []string{"2026-11-01T00:00:00Z", "次数 3", `process.file.path="/usr/bin/apt"`, `container.runtime="docker"`} {
		if !strings.Contains(got, want) {
			t.Errorf("样本缺少 %q: %s", want, got)
		}
	}
	if strings.Contains(got, "sss") {
		t.Error("不在关键字段里的不该列出")
	}
	if n := utf8.RuneCountInString(got); n > valueLimit+200+200 {
		t.Errorf("样本应有上限，得到 %d 字", n)
	}
}

// 没有条件要明说会压掉全部命中，审计员才看得出范围
func TestConditions(t *testing.T) {
	if got := conditions(nil); !strings.Contains(got, "全部命中") {
		t.Errorf("无条件: %q", got)
	}
	got := conditions([]suppress.Condition{{Field: "query.hostname", Op: "endswith", Value: ".example.com"}, {Field: "process.file.path", Op: "equals", Value: "/usr/bin/apt"}})
	if got != `query.hostname endswith ".example.com" 且 process.file.path equals "/usr/bin/apt"` {
		t.Errorf("条件: %q", got)
	}
}

// 模型回复不可信：拿不到明确的布尔结论一律出错，由 Review 记为拒绝
func TestVerdictUntrusted(t *testing.T) {
	for _, bad := range []string{"批准", `{"approve":"true","reason":"x"}`, `{"approve":1}`, `{"reason":"批准"}`, ""} {
		if _, _, err := commandreview.Verdict(bad); err == nil {
			t.Errorf("应出错: %q", bad)
		}
	}
	if ok, reason, err := commandreview.Verdict(`{"approve": false, "reason": "条件只是 bash 映像，等于整条规则"}`); err != nil || ok || reason == "" {
		t.Errorf("应拒绝并带理由: %v %q %v", ok, reason, err)
	}
	if !strings.Contains(prompt, "source=ai") || !strings.Contains(prompt, "靶场") {
		t.Error("审计员提示词应明确禁止凭 source=ai 记忆或靶场猜测批准抑制")
	}
}

// 硬闸门必须 fail-closed：AI 提议（哪怕伪造非 nil 或空 Evidence）遇到高危、未知规则、缺严重度规则或情报规则一律留人工审批
func TestShouldHoldForHuman(t *testing.T) {
	r := &Reviewer{
		Rules: stubCatalog{
			{ID: "low", Severity: 2},
			{ID: "med", Severity: 3},
			{ID: "high", Severity: 4},
			{ID: "zero-sev", Severity: 0},
		},
	}
	cond := []suppress.Condition{{Field: "process.cmd_line", Op: "contains", Value: "/flag"}}
	sess := uuid.New()
	validEv := &schema.SuppressEvidence{FalsePositives: 3, Incidents: []schema.EvidenceIncident{{ID: uuid.New(), ResolvedBy: "admin"}}}
	emptyEv := &schema.SuppressEvidence{}

	cases := []struct {
		name string
		s    *ent.Suppression
		want bool
	}{
		{
			name: "AI 提议低危带条件可进审计",
			s:    &ent.Suppression{RuleID: "low", SessionID: &sess, CreatedBy: "ai:1", Conditions: cond},
			want: false,
		},
		{
			name: "AI 提议中危带条件可进审计",
			s:    &ent.Suppression{RuleID: "med", SessionID: &sess, CreatedBy: "ai:1", Conditions: cond},
			want: false,
		},
		{
			name: "AI 提议高危带条件必须留人工",
			s:    &ent.Suppression{RuleID: "high", SessionID: &sess, CreatedBy: "ai:1", Conditions: cond},
			want: true,
		},
		{
			name: "AI 提议高危哪怕携带非nil有效Evidence仍必须留人工",
			s:    &ent.Suppression{RuleID: "high", SessionID: &sess, CreatedBy: "fp-stats", Conditions: cond, Evidence: validEv},
			want: true,
		},
		{
			name: "非fp-stats创建人伪造Evidence的高危提议必须留人工",
			s:    &ent.Suppression{RuleID: "high", CreatedBy: "ai:1", Conditions: cond, Evidence: validEv},
			want: true,
		},
		{
			name: "fp-stats携带空Evidence的高危提议必须留人工",
			s:    &ent.Suppression{RuleID: "high", CreatedBy: "fp-stats", Conditions: cond, Evidence: emptyEv},
			want: true,
		},
		{
			name: "服务端fp-stats携带有效人工误报统计且带条件的高危提议可进审计",
			s:    &ent.Suppression{RuleID: "high", CreatedBy: "fp-stats", Conditions: cond, Evidence: validEv},
			want: false,
		},
		{
			name: "未知规则不能当低危自动批准（AI提议带条件也留人工）",
			s:    &ent.Suppression{RuleID: "unknown-rule", SessionID: &sess, CreatedBy: "ai:1", Conditions: cond},
			want: true,
		},
		{
			name: "缺严重度规则（Severity=0）不能当低危自动批准",
			s:    &ent.Suppression{RuleID: "zero-sev", SessionID: &sess, CreatedBy: "ai:1", Conditions: cond},
			want: true,
		},
		{
			name: "情报规则（intel:*）AI提议必须留人工",
			s:    &ent.Suppression{RuleID: "intel:ip:1.2.3.4", SessionID: &sess, CreatedBy: "ai:1", Conditions: cond},
			want: true,
		},
		{
			name: "无条件中危草案（哪怕来自fp-stats）必须留人工",
			s:    &ent.Suppression{RuleID: "med", CreatedBy: "fp-stats", Evidence: validEv},
			want: true,
		},
		{
			name: "无条件未知规则草案必须留人工",
			s:    &ent.Suppression{RuleID: "unknown-rule", CreatedBy: "fp-stats", Evidence: validEv},
			want: true,
		},
	}
	for _, tc := range cases {
		if got := r.shouldHoldForHuman(tc.s); got != tc.want {
			t.Errorf("%s: shouldHoldForHuman=%v, 期望 %v", tc.name, got, tc.want)
		}
	}
	// Rules 为 nil 时同样 fail-closed
	nilCatalog := &Reviewer{}
	if !nilCatalog.shouldHoldForHuman(&ent.Suppression{RuleID: "low", SessionID: &sess, CreatedBy: "ai:1", Conditions: cond}) {
		t.Error("Rules=nil 时应 fail-closed 留人工")
	}
}
