package ingest

import (
	"encoding/json"
	"testing"
	"time"
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
