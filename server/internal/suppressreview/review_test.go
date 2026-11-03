package suppressreview

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"openxdr/server/ent"
	"openxdr/server/internal/commandreview"
	"openxdr/server/internal/suppress"
)

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
}
