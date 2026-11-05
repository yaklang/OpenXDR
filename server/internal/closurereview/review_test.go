package closurereview

import (
	"encoding/json"
	"github.com/google/uuid"
	"openxdr/server/ent"
	"testing"
)

func TestStrictDecision(t *testing.T) {
	for _, raw := range []string{`{"approve":true,"reason":"充分肯定证据"}`, `{"approve":false,"reason":"保持事件等待更多可核验正面证据","cmd":"true"}`, `{"approve":false,"reason":"保持事件等待更多可核验正面证据"} {}`, `null`} {
		if _, err := ParseDecision(raw); err == nil {
			t.Fatalf("应拒绝 %s", raw)
		}
	}
	id := uuid.New()
	raw := `{"approve":true,"reason":"构建记录与命令精确匹配，属于已授权构建", "positive_evidence":"签名构建清单给出本次完整命令及资产、工件哈希，逐项与事件匹配", "event_ids":["` + id.String() + `"],"claims":[{"event_id":"` + id.String() + `","field":"process.cmd_line","value":"/bin/build"}]}`
	d, err := ParseDecision(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !validate(d, &material{Events: []*ent.Event{{ID: id, Raw: json.RawMessage(`{"process":{"cmd_line":"/bin/build"}}`)}}}) {
		t.Fatal("应接受相同事件引用")
	}
	if validate(d, &material{Events: []*ent.Event{{ID: uuid.New()}}}) {
		t.Fatal("禁止伪造引用")
	}
}
func TestVerdictHash(t *testing.T) {
	if VerdictHash(json.RawMessage(`{ "verdict": "benign" }`)) != VerdictHash(json.RawMessage(`{"verdict":"benign"}`)) {
		t.Fatal("空白不影响hash")
	}
	if VerdictHash(json.RawMessage(`bad`)) != "" {
		t.Fatal("拒绝无效JSON")
	}
}
