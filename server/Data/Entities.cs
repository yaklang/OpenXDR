using System.Net;
using System.Text.Json;

namespace OpenXDR.Server.Data;

/// <summary>资产：所有事件挂靠的根实体。</summary>
public class Asset
{
    public Guid Id { get; set; }
    public required string Hostname { get; set; }
    public string? Os { get; set; }
    public IPAddress[]? IpAddrs { get; set; }
    public Guid? AgentId { get; set; }
    public DateTimeOffset FirstSeen { get; set; }
    public DateTimeOffset LastSeen { get; set; }
}

/// <summary>归一化事件：三路数据（EDR / NTA / 日志）统一进这张表，OCSF 风格。</summary>
public class Event
{
    public Guid Id { get; set; }
    public DateTimeOffset Ts { get; set; }
    public int ClassUid { get; set; }
    public required string Source { get; set; }
    public Guid? AssetId { get; set; }
    public Asset? Asset { get; set; }
    public Guid? ProcessGuid { get; set; }
    public string? Username { get; set; }
    public string? ConnTuple { get; set; }
    public required JsonDocument Raw { get; set; }
}

/// <summary>告警：规则引擎命中产物。</summary>
public class Alert
{
    public Guid Id { get; set; }
    public DateTimeOffset Ts { get; set; }
    public required string RuleId { get; set; }
    public short Severity { get; set; }
    public Guid? EventId { get; set; }
    public Event? Event { get; set; }
    public Guid? AssetId { get; set; }
    public Asset? Asset { get; set; }
    public Guid? IncidentId { get; set; }

    /// <summary>去重窗口内命中的次数；Ts 是首次，LastTs 是最近一次。</summary>
    public int Count { get; set; } = 1;
    public DateTimeOffset? LastTs { get; set; }
}

/// <summary>事件（incident）：关联引擎聚合出的攻击故事，AI 研判的对象。</summary>
public class Incident
{
    public Guid Id { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public string Status { get; set; } = "open";
    public required JsonDocument Graph { get; set; }
    public JsonDocument? AiVerdict { get; set; }
    public string? Title { get; set; }
}
