//go:build integration

package triage

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/internal/testdb"
)

func TestInvalidVerdictBackoffPreservesConclusion(t *testing.T) {
	for _, retriage := range []bool{false, true} {
		t.Run(map[bool]string{false: "首次研判", true: "重新研判"}[retriage], func(t *testing.T) {
			ctx, client := testdb.New(t)
			f := &retriageFixture{t: t, ctx: ctx, client: client}
			inc := f.fresh("格式异常", time.Now().Add(-time.Hour))
			if retriage {
				client.Incident.DeleteOne(inc).ExecX(ctx)
				inc = f.triaged("格式异常", time.Hour)
				f.evidence(inc, "rule-new", 3, true)
				inc = f.get(inc)
			}
			llm, calls := verdictLLM(t, []Message{{Role: "assistant", Content: `{"verdict":"benign","summary":"expr \(.*\)"}`}})
			notified := false
			e := &Engine{DB: client, LLM: llm, OnVerdict: func(context.Context, uuid.UUID, json.RawMessage) { notified = true }}
			if err := e.batch(ctx); err != nil {
				t.Fatal(err)
			}
			got := f.get(inc)
			if *calls != 2 || notified || got.Status != inc.Status || got.TriageCount != inc.TriageCount || !bytes.Equal(got.AiVerdict, inc.AiVerdict) {
				t.Fatalf("无效输出不应完成研判或触发处置: calls=%d notified=%v status=%s count=%d", *calls, notified, got.Status, got.TriageCount)
			}
			if got.TriageFailures != 1 || got.TriageRetryAt == nil || got.TriageStartedAt != nil {
				t.Fatal("失败应清理运行标记并安排退避重试")
			}
		})
	}
}

func TestInvalidActionsDoNotPersistOrNotify(t *testing.T) {
	ctx, client := testdb.New(t)
	f := &retriageFixture{t: t, ctx: ctx, client: client}
	inc := f.fresh("无效建议", time.Now().Add(-time.Hour))
	llm, calls := verdictLLM(t, []Message{{Role: "assistant", Content: `{"verdict":"malicious","confidence":99,"summary":"待核实","action_codes":["remove_raw_limit"]}`}})
	notified := false
	e := Engine{DB: client, LLM: llm, OnVerdict: func(context.Context, uuid.UUID, json.RawMessage) { notified = true }}
	if err := e.batch(ctx); err != nil {
		t.Fatal(err)
	}
	got := f.get(inc)
	if *calls != 2 || notified || len(got.AiVerdict) != 0 || got.TriageCount != 0 || got.TriageFailures != 1 || got.TriageRetryAt == nil {
		t.Fatalf("无效建议被落库或触发回调：calls=%d notified=%v incident=%+v", *calls, notified, got)
	}
}

func TestMissingEvidenceClaimsDoNotPersistOrNotify(t *testing.T) {
	ctx, client := testdb.New(t)
	f := &retriageFixture{t: t, ctx: ctx, client: client}
	inc := f.fresh("缺少证据引用", time.Now().Add(-time.Hour))
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		msg := Message{Role: "assistant", Content: `{"verdict":"malicious","confidence":99,"summary":"可疑进程","action_codes":["review_response"]}`}
		if calls == 1 {
			if err := json.Unmarshal([]byte(`{"role":"assistant","tool_calls":[{"id":"call-1","type":"function","function":{"name":"process_lineage","arguments":"{\"process_guid\":\"invalid\"}"}}]}`), &msg); err != nil {
				t.Error(err)
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": msg}}})
	}))
	defer srv.Close()
	notified := false
	e := Engine{DB: client, LLM: NewLLM(srv.URL, "test", "", time.Second), OnVerdict: func(context.Context, uuid.UUID, json.RawMessage) { notified = true }}
	if err := e.batch(ctx); err != nil {
		t.Fatal(err)
	}
	got := f.get(inc)
	if calls != 3 || notified || len(got.AiVerdict) != 0 || got.TriageCount != 0 || got.TriageFailures != 1 || got.TriageRetryAt == nil || got.TriageStartedAt != nil {
		t.Fatalf("缺少引用仍落库或触发回调：calls=%d notified=%v incident=%+v", calls, notified, got)
	}
}
