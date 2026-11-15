//go:build integration

package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/internal/clockskew"
	"openxdr/server/internal/testdb"
)

func TestInvestigationCoverage(t *testing.T) {
	ctx, db := testdb.New(t)
	host := db.Asset.Create().SetHostname("coverage").SaveX(ctx)
	e := scopedToolEngine(ctx, db, host.ID)
	now := time.Now().Add(-30 * time.Second)
	for i := 0; i < 16; i++ {
		db.Event.Create().SetAssetID(host.ID).SetTs(now.Add(-time.Duration(i) * time.Second)).SetClassUID(4001).SetSource("agent").SetRaw(json.RawMessage(`{"message":"coverage-test"}`)).SaveX(ctx)
	}
	out, err := e.toolQueryEvents(ctx, `{"keyword":"coverage-test","hours":1}`)
	if err != nil {
		t.Fatal(err)
	}
	m := out.(map[string]any)
	if m["truncated"] != true || m["returned"] != 15 || m["from"] == nil || m["to"] == nil {
		t.Fatalf("覆盖信息错误：%v", m)
	}
	out, err = e.toolQueryEvents(ctx, `{"keyword":"not-found"}`)
	if err != nil {
		t.Fatal(err)
	}
	m = out.(map[string]any)
	if m["truncated"] != false || m["returned"] != 0 || m["coverage"] == "" {
		t.Fatal(m)
	}
	// P5：检索工具的覆盖说明必须包含归档缺口——只查热表，已归档冷事件搜不到
	if cov, ok := m["coverage"].(string); !ok || !strings.Contains(cov, "归档") {
		t.Fatalf("覆盖说明应包含归档缺口: %v", m["coverage"])
	}

	for i := 0; i < 21; i++ {
		db.Alert.Create().SetAssetID(host.ID).SetTs(now.Add(-time.Duration(i) * time.Second)).SetRuleID("test").SetSeverity(2).SaveX(ctx)
	}
	out, err = e.toolHostAlerts(ctx, fmt.Sprintf(`{"asset_id":%q}`, host.ID))
	if err != nil {
		t.Fatal(err)
	}
	if out.(map[string]any)["truncated"] != true {
		t.Fatal(out)
	}
	missing := uuid.New()
	out, err = e.toolProcessLineage(ctx, fmt.Sprintf(`{"process_guid":%q}`, missing))
	if err != nil {
		t.Fatal(err)
	}
	if out.(map[string]any)["missing_ancestor"] != true {
		t.Fatal(out)
	}
	// 断库必须成为查询失败，不能伪装成空血缘。
	db.Close()
	result := e.execTool(ctx, "process_lineage", fmt.Sprintf(`{"process_guid":%q}`, missing))
	if !strings.Contains(result, `"status":"error"`) {
		t.Fatal(result)
	}
}

func TestBriefTruncationUTF8(t *testing.T) {
	ctx, db := testdb.New(t)
	ev := db.Event.Create().SetTs(time.Now()).SetClassUID(4001).SetSource("agent").SetRaw(json.RawMessage(`{"message":"` + strings.Repeat("中文", 100) + `"}`)).SaveX(ctx)
	b := brief(ev)
	if !b.RawTruncated || !utf8.ValidString(b.Raw) {
		t.Fatal(b)
	}
}

func TestDNSBriefAndToolFailureDetails(t *testing.T) {
	raw := json.RawMessage(`{"padding":"` + strings.Repeat("x", 600) + `","query":{"hostname":"nonce.example.test","type":"A"},"requester":{"ip":"10.1.1.144"},"answers":[{"ip":"192.0.2.1"}],"process":{"cmd_line":"` + strings.Repeat("x", 2100) + `"}}`)
	b := briefLimit(&ent.Event{Raw: raw}, 500)
	if !b.RawTruncated || !strings.Contains(string(b.DNS["requester"]), "10.1.1.144") || len(b.DNSOmitted) != 1 || b.DNSOmitted[0] != "process" {
		t.Fatalf("DNS 摘要丢失关键字段：%+v", b)
	}
	ctx, db := testdb.New(t)
	timing := &runTiming{}
	ctx = context.WithValue(ctx, timingKey{}, timing)
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	result := (&Engine{DB: db}).execTool(ctx, "query_events", `{"keyword":"test","mode":"raw"}`)
	if !strings.Contains(result, `"status":"error"`) || timing.toolErrors != 1 || len(timing.tools) != 1 || timing.tools[0]["failed"] != true {
		t.Fatal(result, timing)
	}
	encoded, _ := json.Marshal(timing.tools)
	if strings.Contains(string(encoded), "keyword") {
		t.Fatal("不应保存查询原文")
	}
}

func TestTriageHotWindowClockSkewBounds(t *testing.T) {
	ctx, db := testdb.New(t)
	host := db.Asset.Create().SetHostname("skew-host").SaveX(ctx)
	e := scopedToolEngine(ctx, db, host.ID)

	now := time.Now().UTC()
	withinEvent := db.Event.Create().SetAssetID(host.ID).SetTs(now.Add(2 * time.Second)).SetClassUID(4001).SetSource("agent").
		SetRaw(json.RawMessage(`{"message":"skew-within-marker"}`)).SaveX(ctx)
	beyondEvent := db.Event.Create().SetAssetID(host.ID).SetTs(now.Add(clockskew.Max + 5*time.Second)).SetClassUID(4001).SetSource("agent").
		SetRaw(json.RawMessage(`{"message":"skew-beyond-marker"}`)).SaveX(ctx)
	db.Alert.Create().SetAssetID(host.ID).SetTs(now.Add(2 * time.Second)).SetRuleID("skew-within-alert").SetSeverity(3).SaveX(ctx)
	db.Alert.Create().SetAssetID(host.ID).SetTs(now.Add(clockskew.Max + 5*time.Second)).SetRuleID("skew-beyond-alert").SetSeverity(3).SaveX(ctx)

	// 1. toolQueryEvents：容差内（+2s）命中，超出容差（+10s）排除。
	out, err := e.toolQueryEvents(ctx, `{"keyword":"skew-within-marker","hours":1}`)
	if err != nil || out.(map[string]any)["returned"] != 1 {
		t.Fatalf("容差内事件未命中: out=%v err=%v", out, err)
	}
	out, err = e.toolQueryEvents(ctx, `{"keyword":"skew-beyond-marker","hours":1}`)
	if err != nil || out.(map[string]any)["returned"] != 0 {
		t.Fatalf("超出容差的未来事件未被排除: out=%v err=%v", out, err)
	}

	// 2. toolHostAlerts：容差内告警命中，超出容差告警排除。
	out, err = e.toolHostAlerts(ctx, fmt.Sprintf(`{"asset_id":%q}`, host.ID))
	if err != nil {
		t.Fatal(err)
	}
	rawAlerts, _ := json.Marshal(out)
	if !strings.Contains(string(rawAlerts), "skew-within-alert") || strings.Contains(string(rawAlerts), "skew-beyond-alert") {
		t.Fatalf("主机告警热窗时钟偏斜边界不符: %s", string(rawAlerts))
	}

	// 3. toolEventRaw：容差内放行，超出容差拒绝。
	if _, err := e.toolEventRaw(ctx, fmt.Sprintf(`{"event_id":%q}`, withinEvent.ID)); err != nil {
		t.Fatalf("toolEventRaw 容差内被拒: %v", err)
	}
	if _, err := e.toolEventRaw(ctx, fmt.Sprintf(`{"event_id":%q}`, beyondEvent.ID)); err == nil {
		t.Fatal("toolEventRaw 超出容差未被拒绝")
	}

	// 4. toolEventContext：容差内锚点放行且上下文排除超出容差记录；超出容差锚点拒绝。
	ctxOut, err := e.toolEventContext(ctx, fmt.Sprintf(`{"event_id":%q,"keyword":"skew-"}`, withinEvent.ID))
	if err != nil {
		t.Fatalf("toolEventContext 容差内锚点被拒: %v", err)
	}
	rawCtx, _ := json.Marshal(ctxOut)
	if !strings.Contains(string(rawCtx), "skew-within-marker") || strings.Contains(string(rawCtx), "skew-beyond-marker") {
		t.Fatalf("toolEventContext 上下文边界不符: %s", string(rawCtx))
	}
	if _, err := e.toolEventContext(ctx, fmt.Sprintf(`{"event_id":%q,"keyword":"skew-"}`, beyondEvent.ID)); err == nil {
		t.Fatal("toolEventContext 超出容差锚点未被拒绝")
	}
}
