package commandreview

import (
	"encoding/json"
	"testing"
)

// 回复里认 JSON 结论；拿不到结论按出错处理，由闸门记为拒绝
func TestVerdict(t *testing.T) {
	ok, reason, err := verdict("好的。\n```json\n{\"approve\": true, \"reason\": \"只读核对 sudoers 语法\"}\n```")
	if err != nil || !ok || reason != "只读核对 sudoers 语法" {
		t.Fatalf("应批准: %v %q %v", ok, reason, err)
	}
	if ok, _, err := verdict(`{"approve": false, "reason": "会改配置但没有备份"}`); err != nil || ok {
		t.Fatalf("应拒绝: %v %v", ok, err)
	}
	for _, bad := range []string{"可以执行", `{"reason": "没有结论"}`, `{"approve": "yes"}`} {
		if _, _, err := verdict(bad); err == nil {
			t.Errorf("拿不到结论应出错: %q", bad)
		}
	}
	if _, reason, _ := verdict(`{"approve": true}`); reason == "" {
		t.Error("没给理由也要留一句说明")
	}
}

// 只取消息里的文字，工具调用不算
func TestText(t *testing.T) {
	parts := json.RawMessage(`{"role":"assistant","content":[{"type":"text","text":"先备份再改"},{"type":"toolCall","name":"exec"},{"type":"text","text":"然后用 visudo 校验"}]}`)
	if got := text(parts); got != "先备份再改\n然后用 visudo 校验" {
		t.Fatalf("文字部分: %q", got)
	}
	if got := text(json.RawMessage(`{"role":"user","content":"帮我修 sudoers"}`)); got != "帮我修 sudoers" {
		t.Fatalf("字符串内容: %q", got)
	}
}
