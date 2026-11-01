//go:build integration

package triage

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"openxdr/server/internal/testdb"
)

// 模拟模型只验证研判管线和证据传递，不作为真实模型正确性验收。
func TestSuricataTriage(t *testing.T) {
	ctx, client := testdb.New(t)
	now := time.Now()
	event := client.Event.Create().SetTs(now).SetClassUID(2004).SetSource("suricata").
		SetRaw(json.RawMessage(`{"dst_endpoint":{"ip":"10.0.0.2"},"suricata":{"alert":{"signature":"网络测试告警","rev":2}}}`)).SaveX(ctx)
	inc := client.Incident.Create().SetTitle("网络测试告警").SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	client.Alert.Create().SetTs(now).SetRuleID("suricata:1:42").SetSeverity(4).
		SetDetail("网络测试告警（Suricata gid=1 sid=42 rev=2）").SetEventID(event.ID).SetIncidentID(inc.ID).SaveX(ctx)
	stub := &stubLLM{}
	engine := &Engine{DB: client, LLM: stub.llm(t)}
	if err := engine.batch(ctx); err != nil {
		t.Fatal(err)
	}
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if len(stub.contexts) != 1 {
		t.Fatalf("没有进入既有研判管线: %d", len(stub.contexts))
	}
	for _, want := range []string{"suricata:1:42", "网络测试告警", "rev=2", "10.0.0.2"} {
		if !strings.Contains(stub.contexts[0], want) {
			t.Errorf("模型上下文缺少 %s", want)
		}
	}
	got := client.Incident.GetX(ctx, inc.ID)
	if got.Status != "triaged" || got.TriageCount != 1 || len(got.AiVerdict) == 0 {
		t.Fatal("研判结果没有落库")
	}
}
