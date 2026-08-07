package correlate

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"openxdr/server/ent"
)

// Graph 纯内存操作：去重节点/边、序列化往返、溢出计数。

func hasEdge(g *Graph, from, to, rel string) bool {
	for _, e := range g.Edges {
		if e.From == from && e.To == to && e.Rel == rel {
			return true
		}
	}
	return false
}

func TestEnsureNodeDedup(t *testing.T) {
	g := &Graph{}
	g.ensureNode("asset:1", "asset", "host-a")
	g.ensureNode("asset:1", "asset", "host-a")
	if len(g.Nodes) != 1 {
		t.Fatalf("同 id 节点应去重，实际 %d 个", len(g.Nodes))
	}
	// 首次插入时 label 被记录
	if g.Nodes[0].Label != "host-a" {
		t.Errorf("label = %q", g.Nodes[0].Label)
	}
}

func TestEnsureEdgeDedup(t *testing.T) {
	g := &Graph{}
	g.ensureEdge("a", "b", "hosts")
	g.ensureEdge("a", "b", "hosts")
	if len(g.Edges) != 1 {
		t.Fatalf("同 (from,to,rel) 边应去重，实际 %d 条", len(g.Edges))
	}
	// 不同 rel 视为不同边
	g.ensureEdge("a", "b", "triggered")
	if len(g.Edges) != 2 {
		t.Fatalf("不同 rel 的边应保留，实际 %d 条", len(g.Edges))
	}
}

func TestGraphRoundTrip(t *testing.T) {
	g := &Graph{}
	g.ensureNode("asset:1", "asset", "host-a")
	g.ensureNode("proc:1", "process", "cmd.exe (123)")
	g.ensureEdge("asset:1", "proc:1", "hosts")
	g.Overflow = 5

	g2 := parseGraph(g.raw())
	if len(g2.Nodes) != 2 || len(g2.Edges) != 1 || g2.Overflow != 5 {
		t.Fatalf("round trip 不一致: %+v", g2)
	}
}

// 损坏的 JSON 不应 panic，退回空图。
func TestParseGraphGarbage(t *testing.T) {
	g := parseGraph(json.RawMessage(`{invalid`))
	if g == nil || len(g.Nodes) != 0 {
		t.Fatalf("损坏 JSON 应退回空图，得到 %+v", g)
	}
}

func mkEvent(classUID int, id, connTuple string, processGUID *uuid.UUID, raw string) *ent.Event {
	var g *uuid.UUID
	if processGUID != nil {
		g = processGUID
	}
	return &ent.Event{
		ID:          uuid.New(),
		ClassUID:    classUID,
		ConnTuple:   strPtr(connTuple),
		ProcessGUID: g,
		Raw:         json.RawMessage(raw),
	}
}

func strPtr(s string) *string {
	return &s
}

func guidPtr() *uuid.UUID {
	u := uuid.New()
	return &u
}

func TestEventNodeProcess(t *testing.T) {
	pg := guidPtr()
	evt := mkEvent(1007, "", "", pg, `{"process":{"name":"cmd.exe","pid":123}}`)
	id, typ, label := eventNode(evt)
	if typ != "process" {
		t.Errorf("端点事件节点类型应为 process，得到 %q", typ)
	}
	if id != "process:"+pg.String() {
		t.Errorf("有 process_guid 时 id 应为 process:<guid>，得到 %q", id)
	}
	if label != "cmd.exe (123)" {
		t.Errorf("label = %q", label)
	}
}

func TestEventNodeNetwork(t *testing.T) {
	evt := mkEvent(4001, "", "1.2.3.4:443->5.6.7.8:80", nil,
		`{"dst_endpoint":{"ip":"5.6.7.8","port":80}}`)
	id, typ, label := eventNode(evt)
	if typ != "connection" {
		t.Errorf("网络事件节点类型应为 connection，得到 %q", typ)
	}
	if id != "conn:1.2.3.4:443->5.6.7.8:80" {
		t.Errorf("有 conn_tuple 时 id 应为 conn:<tuple>，得到 %q", id)
	}
	if label != "5.6.7.8:80" {
		t.Errorf("网络事件 label = %q", label)
	}
}

func TestConnLabelPriority(t *testing.T) {
	// 域名 > SNI > dst IP
	if got := connLabel(mkEvent(4003, "", "x", nil, `{"query":{"hostname":"evil.example"},"dst_endpoint":{"ip":"1.2.3.4","port":53}}`)); got != "DNS evil.example" {
		t.Errorf("有域名应优先展示 DNS，得到 %q", got)
	}
	if got := connLabel(mkEvent(4001, "", "x", nil, `{"tls":{"sni":"c2.example"},"dst_endpoint":{"ip":"1.2.3.4"}}`)); got != "c2.example" {
		t.Errorf("无域名时应展示 SNI，得到 %q", got)
	}
	if got := connLabel(mkEvent(4001, "", "x", nil, `{"dst_endpoint":{"ip":"1.2.3.4"}}`)); got != "1.2.3.4:0" {
		t.Errorf("IP 回退应为 ip:port，得到 %q", got)
	}
	// 空 raw / 损坏 → 默认
	if got := connLabel(mkEvent(4001, "", "x", nil, `{}`)); got != "connection" {
		t.Errorf("空 raw 应退回 connection，得到 %q", got)
	}
}

func TestProcessLabel(t *testing.T) {
	if got := processLabel(mkEvent(1007, "", "", nil, `{"process":{"name":"bash","pid":9}}`)); got != "bash (9)" {
		t.Errorf("有 pid 的 label = %q", got)
	}
	if got := processLabel(mkEvent(1007, "", "", nil, `{"process":{"name":"bash"}}`)); got != "bash" {
		t.Errorf("无 pid 的 label = %q", got)
	}
	if got := processLabel(mkEvent(1007, "", "", nil, `{}`)); got != "process" {
		t.Errorf("无 process 信息的 label 应退回 process，得到 %q", got)
	}
	if got := processLabel(mkEvent(1007, "", "", nil, `{oops`)); got != "process" {
		t.Errorf("损坏 raw 应退回 process，得到 %q", got)
	}
}

// 反向断言：graph 无 process_guid 时应按 event:id 兜底。
func TestEventNodeNoGUID(t *testing.T) {
	evt := mkEvent(1007, "", "", nil, `{}`)
	id, typ, _ := eventNode(evt)
	if !hasNodePrefix(id, "event:") {
		t.Errorf("无 process_guid 且非网络事件时 id 应为 event:<uuid>，得到 %q", id)
	}
	if typ != "process" {
		t.Errorf("typ = %q", typ)
	}
}

func hasNodePrefix(s, p string) bool { return len(s) > len(p) && s[:len(p)] == p }
