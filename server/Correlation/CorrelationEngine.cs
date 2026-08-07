using Microsoft.EntityFrameworkCore;
using OpenXDR.Server.Data;
using OpenXDR.Server.Rules;

namespace OpenXDR.Server.Correlation;

/// <summary>
/// 关联引擎：周期性把未归属的告警聚合成 incident。
/// MVP 策略：同一资产、时间窗口内的告警归入同一个 open incident。
/// </summary>
public class CorrelationEngine(
    IServiceScopeFactory scopes,
    SigmaEngine rules,
    IConfiguration cfg,
    ILogger<CorrelationEngine> log) : BackgroundService
{
    private readonly int _maxGraphNodes = cfg.GetValue("Correlation:MaxGraphNodes", 500);

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        var interval = TimeSpan.FromSeconds(cfg.GetValue("Correlation:IntervalSeconds", 10));
        var window = TimeSpan.FromMinutes(cfg.GetValue("Correlation:WindowMinutes", 30));

        while (!ct.IsCancellationRequested)
        {
            try
            {
                await CorrelateBatch(window, ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }
            catch (Exception e)
            {
                log.LogError(e, "关联批次失败");
            }
            await Task.Delay(interval, ct);
        }
    }

    private async Task CorrelateBatch(TimeSpan window, CancellationToken ct)
    {
        using var scope = scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<OpenXdrDbContext>();

        var pending = await db.Alerts
            .Where(a => a.IncidentId == null)
            .OrderBy(a => a.Ts)
            .Take(500)
            .Include(a => a.Event)
            .Include(a => a.Asset)
            .ToListAsync(ct);
        if (pending.Count == 0) return;

        // 批内同资产的告警直接命中内存里的 incident，不用回查数据库
        var byAsset = new Dictionary<Guid, Incident>();

        foreach (var alert in pending)
        {
            Incident? incident = null;
            if (alert.AssetId is Guid assetId)
                incident = byAsset.GetValueOrDefault(assetId)
                    ?? await FindOpenIncident(db, assetId, alert.Ts - window, ct);

            if (incident is null)
            {
                incident = new Incident
                {
                    Id = Guid.CreateVersion7(),
                    Graph = new IncidentGraph().ToDocument(),
                    Title = $"{rules.TitleOf(alert.RuleId) ?? alert.RuleId} @ {alert.Asset?.Hostname ?? "unknown"}",
                };
                db.Incidents.Add(incident);
            }
            if (alert.AssetId is Guid aid) byAsset[aid] = incident;

            // 已研判的 incident 收到新证据：重开，研判引擎会带新证据重新定性
            if (incident.Status == "triaged") incident.Status = "open";

            Attach(incident, alert);
            alert.IncidentId = incident.Id;
        }

        await db.SaveChangesAsync(ct);
        log.LogInformation("关联完成: {Alerts} 条告警 -> {Incidents} 个 incident",
            pending.Count, pending.Select(a => a.IncidentId).Distinct().Count());
    }

    private static Task<Incident?> FindOpenIncident(
        OpenXdrDbContext db, Guid assetId, DateTimeOffset since, CancellationToken ct) =>
        (from a in db.Alerts
         join i in db.Incidents on a.IncidentId equals i.Id
         where a.AssetId == assetId && a.Ts >= since
             && (i.Status == "open" || i.Status == "triaged")
         orderby a.Ts descending
         select i).FirstOrDefaultAsync(ct);

    private void Attach(Incident incident, Alert alert)
    {
        var graph = IncidentGraph.From(incident.Graph);

        // 风暴防线：图触顶后只累加溢出计数，不再无限膨胀
        if (graph.Nodes.Count >= _maxGraphNodes)
        {
            graph.Overflow++;
            incident.Graph = graph.ToDocument();
            return;
        }

        string? assetNode = null;
        if (alert.AssetId is Guid assetId)
        {
            assetNode = $"asset:{assetId}";
            graph.EnsureNode(assetNode, "asset", alert.Asset?.Hostname ?? "unknown");
        }

        var alertNode = $"alert:{alert.Id}";
        graph.EnsureNode(alertNode, "alert", rules.TitleOf(alert.RuleId) ?? alert.RuleId);

        if (alert.Event is { } evt)
        {
            var procNode = evt.ProcessGuid is Guid pg ? $"process:{pg}" : $"event:{evt.Id}";
            graph.EnsureNode(procNode, "process", ProcessLabel(evt));
            if (assetNode is not null) graph.EnsureEdge(assetNode, procNode, "hosts");
            graph.EnsureEdge(procNode, alertNode, "triggered");
        }
        else if (assetNode is not null)
        {
            graph.EnsureEdge(assetNode, alertNode, "triggered");
        }

        incident.Graph = graph.ToDocument();
    }

    private static string ProcessLabel(Event evt)
    {
        if (evt.Raw.RootElement.TryGetProperty("process", out var proc))
        {
            var name = proc.TryGetProperty("name", out var n) ? n.GetString() : null;
            if (name is not null)
                return proc.TryGetProperty("pid", out var pid) ? $"{name} ({pid.GetRawText()})" : name;
        }
        return "process";
    }
}
