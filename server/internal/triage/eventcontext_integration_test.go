//go:build integration

package triage

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/internal/testdb"
)

func TestEventContextFindsOldPeerTrafficWithinBoundScope(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("context").SaveX(ctx)
	host := db.Asset.Create().SetHostname("gateway").SetGroupID(g.ID).SaveX(ctx)
	peer := db.Asset.Create().SetHostname("peer").SetGroupID(g.ID).SaveX(ctx)
	at := time.Now().UTC().Add(-72 * time.Hour).Truncate(time.Second)
	add := func(asset uuid.UUID, ts time.Time, message string) *ent.Event {
		raw, _ := json.Marshal(map[string]string{"message": message})
		return db.Event.Create().SetAssetID(asset).SetTs(ts).SetClassUID(4001).SetSource("agent").SetRaw(raw).SaveX(ctx)
	}
	anchor := add(host.ID, at, "outbound 27.18.40.154")
	inbound := add(host.ID, at.Add(-4*time.Minute), "inbound 27.18.40.154 "+strings.Repeat("x", 500))
	add(host.ID, at.Add(-16*time.Minute), "outside-window 27.18.40.154")
	add(peer.ID, at, "foreign-peer 27.18.40.154")
	add(host.ID, time.Now(), "recent-irrelevant 27.18.40.154")
	e := scopedToolEngine(ctx, db, host.ID)
	result := e.execTool(ctx, "query_event_context", fmt.Sprintf(`{"event_id":%q,"keyword":"27.18.40.154"}`, anchor.ID))
	var out struct {
		Status    string       `json:"status"`
		Items     []eventBrief `json:"items"`
		Truncated bool         `json:"truncated"`
		From      time.Time    `json:"from"`
		To        time.Time    `json:"to"`
	}
	if err := json.Unmarshal([]byte(result), &out); err != nil || out.Status != "ok" || len(out.Items) != 2 || out.Truncated {
		t.Fatal("无法找回旧事发窗口的记录", result, err)
	}
	if !out.From.Equal(at.Add(-15*time.Minute)) || !out.To.Equal(at.Add(15*time.Minute)) {
		t.Fatal("时间窗被扩大或改为调查时刻", result)
	}
	if strings.Contains(result, "outside-window") || strings.Contains(result, "foreign-peer") || strings.Contains(result, "recent-irrelevant") {
		t.Fatal("读取超出主机或事发时间窗", result)
	}
	if out.Items[1].EventID != inbound.ID.String() || !out.Items[1].RawTruncated {
		t.Fatal("返回记录关系或裁剪标记错误", result)
	}
	var call ToolCall
	call.ID, call.Function.Name = "context", "query_event_context"
	ledger := queryEvidenceFrom([]Message{{Role: "assistant", ToolCalls: []ToolCall{call}}, {Role: "tool", ToolCallID: call.ID, Content: result}})
	if len(ledger) != 1 || len(ledger[0].Records) != 2 || ledger[0].Facts["anchor_event_id"] != anchor.ID.String() {
		t.Fatal("锚点与关联记录未进入证据台账", ledger)
	}
	if err := ValidateEvidenceSnapshots([]EvidenceSnapshot{{Tool: "query_event_context", Result: json.RawMessage(result)}}); err != nil {
		t.Fatal("不能离线回放新工具的证据", err)
	}
}

func TestEventContextRejectsScopeOverridesAndInvalidAnchors(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("scope").SaveX(ctx)
	other := db.Group.Create().SetName("foreign").SaveX(ctx)
	host := db.Asset.Create().SetHostname("host").SetGroupID(g.ID).SaveX(ctx)
	peer := db.Asset.Create().SetHostname("peer").SetGroupID(g.ID).SaveX(ctx)
	foreign := db.Asset.Create().SetHostname("foreign").SetGroupID(other.ID).SaveX(ctx)
	add := func(asset uuid.UUID, at time.Time) uuid.UUID {
		return db.Event.Create().SetAssetID(asset).SetTs(at).SetClassUID(4001).SetSource("agent").SetRaw(json.RawMessage(`{"marker":"secret"}`)).SaveX(ctx).ID
	}
	anchor := add(host.ID, time.Now())
	e := scopedToolEngine(ctx, db, host.ID)
	for _, id := range []uuid.UUID{add(peer.ID, time.Now()), add(foreign.ID, time.Now()), add(host.ID, time.Now().Add(-169*time.Hour)), uuid.New()} {
		result := e.execTool(ctx, "query_event_context", fmt.Sprintf(`{"event_id":%q,"keyword":"secret"}`, id))
		if !strings.Contains(result, `"status":"error"`) || strings.Contains(result, `"raw"`) {
			t.Fatal("非法锚点返回了数据", result)
		}
	}
	for _, override := range []string{`"hours":168`, `"limit":10000`, `"asset_id":"` + peer.ID.String() + `"`, `"group_id":"` + other.ID.String() + `"`} {
		result := e.execTool(ctx, "query_event_context", fmt.Sprintf(`{"event_id":%q,"keyword":"secret",%s}`, anchor, override))
		if !strings.Contains(result, `"status":"error"`) {
			t.Fatal("允许扩展搜索范围", result)
		}
	}
}

func TestEventContextHonorsResultCap(t *testing.T) {
	ctx, db := testdb.New(t)
	host := db.Asset.Create().SetHostname("bounded").SaveX(ctx)
	at := time.Now().Add(-time.Hour)
	var anchor uuid.UUID
	for i := range 18 {
		ev := db.Event.Create().SetAssetID(host.ID).SetTs(at.Add(time.Duration(i) * time.Second)).SetClassUID(4001).SetSource("agent").SetRaw(json.RawMessage(`{"message":"a%_b literal"}`)).SaveX(ctx)
		anchor = ev.ID
	}
	e := scopedToolEngine(ctx, db, host.ID)
	result := e.execTool(ctx, "query_event_context", fmt.Sprintf(`{"event_id":%q,"keyword":"a%%_b"}`, anchor))
	var out map[string]any
	_ = json.Unmarshal([]byte(result), &out)
	if out["status"] != "ok" || out["returned"] != float64(15) || out["truncated"] != true {
		t.Fatal("没有保留条数裁剪与覆盖边界", result)
	}
}
