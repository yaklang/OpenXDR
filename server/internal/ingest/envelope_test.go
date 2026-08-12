package ingest

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestStableID(t *testing.T) {
	a := StableID("agent", "1", "payload")
	b := StableID("agent", "1", "payload")
	c := StableID("agent", "2", "payload")
	if a != b || a == c {
		t.Fatalf("稳定 ID 不稳定或未区分输入: %s %s %s", a, b, c)
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	want := Envelope{Version: EnvelopeVersion, ID: StableID("x"), PartitionKey: "asset", Timestamp: time.Now().UTC(), ClassUID: 1007, Source: "agent", Raw: json.RawMessage(`{"ok":true}`)}
	body, err := want.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unmarshal(body)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID || got.PartitionKey != want.PartitionKey || got.ClassUID != want.ClassUID {
		t.Fatalf("信封往返不一致: %#v", got)
	}
}

func TestNullString(t *testing.T) {
	if got := nullString(""); got != nil {
		t.Errorf("空串应转 nil，实际 %v", got)
	}
	if got := nullString("bash"); got != "bash" {
		t.Errorf("非空串应原样返回，实际 %v", got)
	}
}

func TestNullUUID(t *testing.T) {
	if got := nullUUID(nil); got != nil {
		t.Errorf("nil uuid 应转 nil，实际 %v", got)
	}
	nilID := uuid.Nil
	if got := nullUUID(&nilID); got != nil {
		t.Errorf("零值 uuid 应转 nil，实际 %v", got)
	}
	id := uuid.New()
	if got := nullUUID(&id); got != id {
		t.Errorf("真实 uuid 应原样返回，实际 %v", got)
	}
}

func TestIngestAuthStatus(t *testing.T) {
	if got := authStatus(map[string]any{"status_id": float64(1)}); got != 1 {
		t.Errorf("登录成功 status_id=1，实际 %d", got)
	}
	if got := authStatus(map[string]any{"status_id": float64(5)}); got != 5 {
		t.Errorf("锁定失败 status_id=5，实际 %d", got)
	}
	if got := authStatus(map[string]any{}); got != 0 {
		t.Errorf("缺 status_id 应为 0，实际 %d", got)
	}
	if got := authStatus(map[string]any{"status_id": "1"}); got != 0 {
		t.Errorf("类型不对应按 0 处理，实际 %d", got)
	}
}
