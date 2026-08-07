package correlate

import (
	"testing"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/internal/sigma"
)

// attach 把一条告警画进 incident 图。这里用不带 DB 的事件（无父进程），
// 因此 processName 分支不会触发，整条链路可以在内存里跑。

func attachEngine() *Engine {
	return &Engine{Rules: &sigma.Engine{}, MaxGraphNodes: 4}
}

func attachAlert(assetID *uuid.UUID, evt *ent.Event) *ent.Alert {
	return &ent.Alert{ID: uuid.New(), RuleID: "r-test", AssetID: assetID, Edges: ent.AlertEdges{Event: evt}}
}

func countNodes(g *Graph, typ string) int {
	n := 0
	for _, nd := range g.Nodes {
		if nd.Type == typ {
			n++
		}
	}
	return n
}

// 取图中唯一 alert 节点的 ID（不含 alert: 前缀）。
func alertID(g *Graph) string {
	for _, n := range g.Nodes {
		if n.Type == "alert" {
			return n.ID[len("alert:"):]
		}
	}
	return ""
}

// 进程事件：asset + alert + process 三节点，hosts/triggered 边齐活。
func TestAttachProcessEvent(t *testing.T) {
	g := &Graph{}
	asset := uuid.New()
	pg := guidPtr()
	evt := mkEvent(1007, "", "", pg, `{"process":{"name":"cmd.exe","pid":123}}`)

	attachEngine().attach(nil, g, attachAlert(&asset, evt))

	if countNodes(g, "asset") != 1 || countNodes(g, "alert") != 1 || countNodes(g, "process") != 1 {
		t.Fatalf("期望 asset/alert/process 各 1 节点，实际 %+v", g.Nodes)
	}
	pid := "process:" + pg.String()
	if !hasEdge(g, "asset:"+asset.String(), pid, "hosts") {
		t.Error("缺 asset->process hosts 边")
	}
	if !hasEdge(g, pid, "alert:"+alertID(g), "triggered") {
		t.Error("缺 process->alert triggered 边")
	}
}

// 无资产归属：只有 alert + process 节点，无 hosts 边。
func TestAttachNoAsset(t *testing.T) {
	g := &Graph{}
	pg := guidPtr()
	evt := mkEvent(1007, "", "", pg, `{}`)
	attachEngine().attach(nil, g, attachAlert(nil, evt))

	if countNodes(g, "asset") != 0 {
		t.Error("无资产时不应有 asset 节点")
	}
	if countNodes(g, "process") != 1 || countNodes(g, "alert") != 1 {
		t.Fatalf("应有 process+alert，实际 %+v", g.Nodes)
	}
	for _, e := range g.Edges {
		if e.Rel == "hosts" {
			t.Error("无资产时不应有 hosts 边")
		}
	}
}

// 无事件：退化为 asset->alert triggered。
func TestAttachNoEvent(t *testing.T) {
	g := &Graph{}
	asset := uuid.New()
	attachEngine().attach(nil, g, attachAlert(&asset, nil))

	if countNodes(g, "alert") != 1 {
		t.Fatalf("应有 alert 节点，实际 %+v", g.Nodes)
	}
	if !hasEdge(g, "asset:"+asset.String(), "alert:"+alertID(g), "triggered") {
		t.Errorf("无事件时应加 asset->alert triggered 边，实际 %+v", g.Edges)
	}
}

// 网络事件 → connection 节点（不进 process）。
func TestAttachNetworkEvent(t *testing.T) {
	g := &Graph{}
	asset := uuid.New()
	evt := mkEvent(4001, "", "1.1.1.1:9000->2.2.2.2:443", nil,
		`{"dst_endpoint":{"ip":"2.2.2.2","port":443}}`)
	attachEngine().attach(nil, g, attachAlert(&asset, evt))

	if countNodes(g, "connection") != 1 || countNodes(g, "process") != 0 {
		t.Fatalf("网络事件应得到 connection 节点，实际 %+v", g.Nodes)
	}
}

// 节点数触顶 → 只累加溢出，不再加节点。
func TestAttachOverflow(t *testing.T) {
	eng := attachEngine()
	g := &Graph{}
	for i := 0; i < 4; i++ {
		g.ensureNode(string(rune('a'+i)), "process", "")
	}
	before := len(g.Nodes)
	asset := uuid.New()

	eng.attach(nil, g, attachAlert(&asset, mkEvent(1007, "", "", nil, `{}`)))
	if len(g.Nodes) != before {
		t.Errorf("触顶后不应加节点，before=%d after=%d", before, len(g.Nodes))
	}
	if g.Overflow != 1 {
		t.Errorf("触顶应累加 overflow=1，得到 %d", g.Overflow)
	}
	eng.attach(nil, g, attachAlert(&asset, mkEvent(1007, "", "", nil, `{}`)))
	if g.Overflow != 2 {
		t.Errorf("连续触顶 overflow 应=2，得到 %d", g.Overflow)
	}
}

// 有资产对象时，label 用真实 hostname；alert 节点 label 用规则标题（未知则回退 ruleID）。
func TestAttachLabels(t *testing.T) {
	g := &Graph{}
	assetID := uuid.New()
	al := &ent.Alert{
		ID:      uuid.New(),
		RuleID:  "r-unknown",
		AssetID: &assetID,
		Edges: ent.AlertEdges{
			Asset: &ent.Asset{Hostname: "host-42"},
			Event: mkEvent(1007, "", "", nil, `{"process":{"name":"bash","pid":9}}`),
		},
	}
	attachEngine().attach(nil, g, al)

	labels := map[string]string{}
	for _, n := range g.Nodes {
		labels[n.Type] = n.Label
	}
	if labels["asset"] != "host-42" {
		t.Errorf("asset label = %q, want host-42", labels["asset"])
	}
	if labels["alert"] != "r-unknown" {
		t.Errorf("alert label 应回退 ruleID，得到 %q", labels["alert"])
	}
}

// 无进程 GUID 的端点事件 → event:<uuid> 兜底 id，且仍连 hosts/triggered。
func TestAttachEventWithoutGUID(t *testing.T) {
	g := &Graph{}
	assetID := uuid.New()
	attachEngine().attach(nil, g, attachAlert(&assetID, mkEvent(1007, "", "", nil, `{}`)))

	var eventID string
	for _, n := range g.Nodes {
		if len(n.ID) > len("event:") && n.ID[:len("event:")] == "event:" {
			eventID = n.ID
		}
	}
	if eventID == "" {
		t.Fatalf("应存在 event:<uuid> 节点，实际 %+v", g.Nodes)
	}
	if !hasEdge(g, "asset:"+assetID.String(), eventID, "hosts") {
		t.Error("应连 asset->event hosts 边")
	}
}

// 同一事件多次 attach（多条告警命中同一进程）→ 节点按 id 去重。
func TestAttachSharedEventNode(t *testing.T) {
	g := &Graph{}
	asset := uuid.New()
	pg := guidPtr()
	evt := mkEvent(1007, "", "", pg, `{}`)

	eng := attachEngine()
	eng.attach(nil, g, attachAlert(&asset, evt))
	eng.attach(nil, g, attachAlert(&asset, evt))

	if countNodes(g, "process") != 1 {
		t.Fatalf("同事件两次 attach 进程节点应去重，实际 %d", countNodes(g, "process"))
	}
	if countNodes(g, "alert") != 2 {
		t.Fatalf("两条告警应为两个 alert 节点，实际 %d", countNodes(g, "alert"))
	}
}
