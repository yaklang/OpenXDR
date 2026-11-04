//go:build integration

package triage

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/internal/testdb"
)

func rawToolResult(t *testing.T, e *Engine, eventID uuid.UUID) (map[string]any, string) {
	t.Helper()
	result := e.execTool(t.Context(), "query_event_raw", fmt.Sprintf(`{"event_id":%q}`, eventID))
	var out map[string]any
	if err := json.Unmarshal([]byte(result), &out); err != nil {
		t.Fatal(err)
	}
	return out, result
}

func TestEventRawReadsPastListExcerptWithBoundedEvidence(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("raw").SaveX(ctx)
	a := db.Asset.Create().SetHostname("raw-host").SetGroupID(g.ID).SaveX(ctx)
	guid, parent := uuid.New(), uuid.New()
	raw, _ := json.Marshal(map[string]string{"script": "raw-marker " + strings.Repeat("x", 900) + " complete-tail"})
	ev := db.Event.Create().SetAssetID(a.ID).SetTs(time.Now()).SetClassUID(1007).SetSource("agent").SetProcessGUID(guid).SetParentProcessGUID(parent).SetRaw(raw).SaveX(ctx)
	e := scopedToolEngine(ctx, db, a.ID)
	excerpt := e.execTool(ctx, "query_events", `{"keyword":"raw-marker"}`)
	if strings.Contains(excerpt, "complete-tail") || !strings.Contains(excerpt, `"raw_truncated":true`) {
		t.Fatalf("未覆盖真实摘要裁剪: %s", excerpt)
	}
	out, result := rawToolResult(t, e, ev.ID)
	if out["status"] != "ok" {
		t.Fatal(result)
	}
	item := out["items"].([]any)[0].(map[string]any)
	if item["raw_truncated"] != false || !strings.Contains(item["raw"].(string), "complete-tail") || item["parent_process_guid"] != parent.String() {
		t.Fatal(result)
	}
	if item["raw"] != string(db.Event.GetX(ctx, ev.ID).Raw) {
		t.Fatal("完整原文与留存记录不一致")
	}
	var call ToolCall
	call.ID, call.Function.Name = "raw-read", "query_event_raw"
	ledger := queryEvidenceFrom([]Message{{Role: "assistant", ToolCalls: []ToolCall{call}}, {Role: "tool", ToolCallID: call.ID, Content: result}})
	if len(ledger) != 1 || len(ledger[0].Records) != 1 || ledger[0].Records[0].Facts["raw_truncated"] != false || ledger[0].Records[0].Facts["process_guid"] != guid.String() {
		t.Fatalf("精查未进入证据台账: %+v", ledger)
	}
	if err := ValidateEvidenceSnapshots([]EvidenceSnapshot{{Tool: "query_event_raw", Result: json.RawMessage(result)}}); err != nil {
		t.Fatal(err)
	}
}

func TestEventRawCapAndUTF8CannotBeOverridden(t *testing.T) {
	ctx, db := testdb.New(t)
	a := db.Asset.Create().SetHostname("large-raw").SaveX(ctx)
	raw, _ := json.Marshal(map[string]string{"query": strings.Repeat("界", 2000) + " hidden-tail"})
	ev := db.Event.Create().SetAssetID(a.ID).SetTs(time.Now()).SetClassUID(1007).SetSource("agent").SetRaw(raw).SaveX(ctx)
	e := scopedToolEngine(ctx, db, a.ID)
	result := e.execTool(ctx, "query_event_raw", fmt.Sprintf(`{"event_id":%q,"limit":1000000,"raw_limit":1000000,"mode":"unlimited","hours":1000000}`, ev.ID))
	var out struct {
		Status string       `json:"status"`
		Limit  int          `json:"raw_excerpt_limit_bytes"`
		Items  []eventBrief `json:"items"`
	}
	if err := json.Unmarshal([]byte(result), &out); err != nil {
		t.Fatal(err)
	}
	if out.Status != "ok" || out.Limit != 4096 || len(out.Items) != 1 {
		t.Fatal(result)
	}
	item := out.Items[0]
	if !item.RawTruncated || len(item.Raw) > 4096 || !utf8.ValidString(item.Raw) || strings.Contains(result, "hidden-tail") || len(item.DNS) > 0 {
		t.Fatalf("原文预算或 UTF-8 失守: bytes=%d result=%s", len(item.Raw), result)
	}
}

func TestEventRawRejectsForeignMissingAndOutOfWindow(t *testing.T) {
	ctx, db := testdb.New(t)
	ga := db.Group.Create().SetName("a").SaveX(ctx)
	gb := db.Group.Create().SetName("b").SaveX(ctx)
	a := db.Asset.Create().SetHostname("allowed").SetGroupID(ga.ID).SaveX(ctx)
	peer := db.Asset.Create().SetHostname("peer").SetGroupID(ga.ID).SaveX(ctx)
	b := db.Asset.Create().SetHostname("foreign").SetGroupID(gb.ID).SaveX(ctx)
	ungrouped := db.Asset.Create().SetHostname("ungrouped").SaveX(ctx)
	add := func(host *ent.Asset, ts time.Time) uuid.UUID {
		q := db.Event.Create().SetTs(ts).SetClassUID(1007).SetSource("agent").SetRaw(json.RawMessage(`{"marker":"secret-original"}`))
		if host != nil {
			q.SetAssetID(host.ID)
		}
		return q.SaveX(ctx).ID
	}
	e := scopedToolEngine(ctx, db, a.ID)
	peerEvent := add(peer, time.Now())
	if out, result := rawToolResult(t, e, peerEvent); out["status"] != "ok" {
		t.Fatalf("同组调查被误拒绝: %s", result)
	}
	cases := map[string]uuid.UUID{"foreign": add(b, time.Now()), "unassigned": add(ungrouped, time.Now()), "orphan": add(nil, time.Now()), "old": add(a, time.Now().Add(-8*24*time.Hour)), "future": add(a, time.Now().Add(time.Hour)), "missing": uuid.New(), "zero": uuid.Nil}
	for name, id := range cases {
		t.Run(name, func(t *testing.T) {
			result := e.execTool(ctx, "query_event_raw", fmt.Sprintf(`{"event_id":%q,"group_id":%q,"incident_id":%q,"hours":1000000}`, id, gb.ID, uuid.New()))
			if !strings.Contains(result, `"status":"error"`) || strings.Contains(result, "secret-original") {
				t.Fatal(result)
			}
		})
	}
	for _, unbound := range []*Engine{{DB: db}, {DB: db, investigationID: uuid.New()}} {
		if out, result := rawToolResult(t, unbound, peerEvent); out["status"] != "error" {
			t.Fatal(result)
		}
	}
}

func TestEventRawInvalidatesMovedInvestigationReferences(t *testing.T) {
	ctx, db := testdb.New(t)
	ga := db.Group.Create().SetName("a").SaveX(ctx)
	gb := db.Group.Create().SetName("b").SaveX(ctx)
	a := db.Asset.Create().SetHostname("root").SetGroupID(ga.ID).SaveX(ctx)
	peer := db.Asset.Create().SetHostname("peer").SetGroupID(ga.ID).SaveX(ctx)
	ev := db.Event.Create().SetAssetID(peer.ID).SetTs(time.Now()).SetClassUID(1007).SetSource("agent").SetRaw(json.RawMessage(`{"marker":"scoped-original"}`)).SaveX(ctx)
	e := scopedToolEngine(ctx, db, a.ID)
	var err error
	e.investigationMembers, err = e.investigationMembership(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if out, result := rawToolResult(t, e, ev.ID); out["status"] != "ok" {
		t.Fatal(result)
	}
	db.Asset.UpdateOneID(peer.ID).SetGroupID(gb.ID).ExecX(ctx)
	if out, result := rawToolResult(t, e, ev.ID); out["status"] != "error" || strings.Contains(result, "scoped-original") || !e.investigationInvalid {
		t.Fatalf("引用资产转组仍允许继续研判: %s", result)
	}
}
