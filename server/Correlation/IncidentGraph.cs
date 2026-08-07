using System.Text.Json;

namespace OpenXDR.Server.Correlation;

/// <summary>
/// incident 事件图，存于 incidents.graph (JSONB)。
/// 节点类型：asset / process / alert；边类型：hosts / triggered。
/// 后续扩展（进程链、网络横移）只加节点/边类型，不改结构。
/// </summary>
public sealed class IncidentGraph
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };

    public List<GraphNode> Nodes { get; set; } = [];
    public List<GraphEdge> Edges { get; set; } = [];

    /// <summary>节点数触顶后不再进图的告警数，前端展示为 "+N more"。</summary>
    public int Overflow { get; set; }

    public static IncidentGraph From(JsonDocument doc) =>
        doc.Deserialize<IncidentGraph>(Json) ?? new IncidentGraph();

    public JsonDocument ToDocument() => JsonSerializer.SerializeToDocument(this, Json);

    public void EnsureNode(string id, string type, string label)
    {
        if (!Nodes.Any(n => n.Id == id))
            Nodes.Add(new GraphNode(id, type, label));
    }

    public void EnsureEdge(string from, string to, string rel)
    {
        if (!Edges.Any(e => e.From == from && e.To == to && e.Rel == rel))
            Edges.Add(new GraphEdge(from, to, rel));
    }
}

public sealed record GraphNode(string Id, string Type, string Label);

public sealed record GraphEdge(string From, string To, string Rel);
