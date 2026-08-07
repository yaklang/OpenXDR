package correlate

import "encoding/json"

// Graph incident 事件图，存于 incidents.graph (JSONB)。
// 节点类型：asset / process / alert；边类型：hosts / triggered。
// 后续扩展（进程链、网络横移）只加节点/边类型，不改结构。
type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
	// Overflow 节点数触顶后不再进图的告警数，前端展示为 "+N more"。
	Overflow int `json:"overflow"`
}

type Node struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Label string `json:"label"`
}

type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Rel  string `json:"rel"`
}

func parseGraph(raw json.RawMessage) *Graph {
	g := &Graph{}
	_ = json.Unmarshal(raw, g)
	return g
}

func (g *Graph) raw() json.RawMessage {
	data, _ := json.Marshal(g)
	return data
}

func (g *Graph) ensureNode(id, typ, label string) {
	for _, n := range g.Nodes {
		if n.ID == id {
			return
		}
	}
	g.Nodes = append(g.Nodes, Node{ID: id, Type: typ, Label: label})
}

func (g *Graph) ensureEdge(from, to, rel string) {
	for _, e := range g.Edges {
		if e.From == from && e.To == to && e.Rel == rel {
			return
		}
	}
	g.Edges = append(g.Edges, Edge{From: from, To: to, Rel: rel})
}
