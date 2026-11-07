package sigma

import (
	"strings"
	"testing"
)

const customRule = `title: Custom Curl Pipe
id: 6a3b1f0e-1111-4c2d-9e8f-000000000001
level: high
logsource:
  category: process_creation
  product: linux
detection:
  sel:
    CommandLine|contains: 'curl-pipe-marker'
  condition: sel
`

func TestOverlayCustomRules(t *testing.T) {
	base, err := CompileSources(map[string]string{"base-1": strings.ReplaceAll(strings.ReplaceAll(customRule,
		"6a3b1f0e-1111-4c2d-9e8f-000000000001", "base-1"), "Custom Curl Pipe", "Base Rule")})
	if err != nil {
		t.Fatal(err)
	}
	o := &Overlay{Base: base}
	raw := map[string]any{"process": map[string]any{"cmd_line": "sh -c curl-pipe-marker"}}
	if hits := o.Evaluate(1007, "linux", raw); len(hits) != 1 {
		t.Fatalf("没加自定义层时只命中基础规则: %d", len(hits))
	}

	id := "6a3b1f0e-1111-4c2d-9e8f-000000000001"
	broken := "f0000000-0000-4000-8000-000000000000"
	failed := o.SetCustom(map[string]string{id: customRule, broken: "title: x\nid: " + broken + "\n"})
	if len(failed) != 1 || failed[broken] == nil {
		t.Fatalf("坏规则单独报错、不影响其他: %v", failed)
	}
	hits := o.Evaluate(1007, "linux", raw)
	if len(hits) != 2 || !hits[1].Custom || o.TitleOf(id) != "Custom Curl Pipe" || o.TitleOf("base-1") != "Base Rule" {
		t.Fatalf("自定义规则应叠加生效: %+v", hits)
	}
	if len(o.Rules()) != 2 {
		t.Fatalf("规则列表含两层: %d", len(o.Rules()))
	}
	if hits := o.Evaluate(1007, "windows", raw); len(hits) != 0 {
		t.Fatalf("Linux 规则不在 Windows 事件上求值: %d", len(hits))
	}

	for name, content := range map[string]string{
		"缺 id":    strings.Replace(customRule, "id: "+id+"\n", "", 1),
		"与内置重名":   strings.Replace(customRule, id, "base-1", 1),
		"信号规则":    strings.Replace(customRule, "level: high", "level: informational\nopenxdr_signal: true", 1),
		"语法错误":    customRule + "  bad: [",
		"不支持的数据源": strings.Replace(customRule, "product: linux", "product: zeek", 1),
	} {
		if _, err := o.CheckCustom([]byte(content)); err == nil {
			t.Errorf("%s 应拒绝", name)
		}
	}
	if failed := o.SetCustom(map[string]string{"other-id": customRule}); failed["other-id"] == nil {
		t.Error("原文 id 与记录不符应拒绝")
	}
}
