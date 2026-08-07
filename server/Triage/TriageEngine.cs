using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using OpenXDR.Server.Data;

namespace OpenXDR.Server.Triage;

/// <summary>
/// AI 研判引擎：对关联引擎产出的 incident 做 LLM 定性，
/// 结论写回 incidents.ai_verdict，状态推进到 triaged。
/// </summary>
public class TriageEngine(
    IServiceScopeFactory scopes,
    LlmClient llm,
    IConfiguration cfg,
    ILogger<TriageEngine> log) : BackgroundService
{
    private const string SystemPrompt = """
        你是资深安全分析师，负责研判 XDR 平台聚合出的安全事件。
        输入包含事件的实体关系图（主机/进程/告警）和按时间排序的告警明细。
        只输出一个 JSON 对象，不要输出任何其他文字，结构如下：
        {
          "verdict": "malicious | suspicious | benign",
          "confidence": 0 到 100 的整数,
          "summary": "一段话说清这个事件是什么、为什么这样判定",
          "kill_chain": ["按时间顺序还原的攻击链步骤，非攻击事件则为空数组"],
          "actions": ["建议的处置动作，按优先级排序"]
        }
        研判要克制：单一低危告警、常见运维行为倾向 benign；有明确攻击链证据才给 malicious。
        """;

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        if (!llm.Enabled)
        {
            log.LogWarning("AI 研判未启用：未配置 Ai:Model");
            return;
        }

        var interval = TimeSpan.FromSeconds(cfg.GetValue("Ai:IntervalSeconds", 30));
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await TriageBatch(ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }
            catch (Exception e)
            {
                log.LogError(e, "研判批次失败");
            }
            await Task.Delay(interval, ct);
        }
    }

    private async Task TriageBatch(CancellationToken ct)
    {
        using var scope = scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<OpenXdrDbContext>();

        // 只看 status：重开的 incident（带新证据）会被重新研判，旧 verdict 被覆盖
        var incidents = await db.Incidents
            .Where(i => i.Status == "open")
            .OrderBy(i => i.CreatedAt)
            .Take(5)
            .ToListAsync(ct);

        foreach (var incident in incidents)
        {
            var answer = await llm.ChatAsync(SystemPrompt, await BuildContext(db, incident, ct), ct);
            incident.AiVerdict = ParseVerdict(incident.Id, answer);
            incident.Status = "triaged";
            // LLM 调用慢，逐个落库，中途挂了不丢已完成的研判
            await db.SaveChangesAsync(ct);
            log.LogInformation("incident {Id} 研判完成", incident.Id);
        }
    }

    private JsonDocument ParseVerdict(Guid incidentId, string answer)
    {
        var start = answer.IndexOf('{');
        var end = answer.LastIndexOf('}');
        if (start >= 0 && end > start)
        {
            try
            {
                return JsonDocument.Parse(answer[start..(end + 1)]);
            }
            catch (JsonException) { /* 落到下面的存档分支 */ }
        }
        log.LogWarning("incident {Id} 研判输出不是合法 JSON，原样存档", incidentId);
        return JsonSerializer.SerializeToDocument(new
        {
            error = "unparseable",
            raw = answer.Length > 2000 ? answer[..2000] : answer,
        });
    }

    private static async Task<string> BuildContext(
        OpenXdrDbContext db, Incident incident, CancellationToken ct)
    {
        var alerts = await db.Alerts
            .Where(a => a.IncidentId == incident.Id)
            .OrderBy(a => a.Ts)
            .Take(50)
            .Include(a => a.Event)
            .ToListAsync(ct);

        var sb = new StringBuilder();
        sb.AppendLine($"# 事件: {incident.Title}");
        sb.AppendLine($"创建时间: {incident.CreatedAt:O}");
        sb.AppendLine("## 实体关系图");
        sb.AppendLine(incident.Graph.RootElement.GetRawText());
        sb.AppendLine($"## 告警明细（{alerts.Count} 条，按时间排序）");
        foreach (var a in alerts)
        {
            var raw = a.Event?.Raw.RootElement.GetRawText() ?? "{}";
            if (raw.Length > 500) raw = raw[..500] + "…";
            sb.AppendLine($"- [{a.Ts:HH:mm:ss}] severity={a.Severity} rule={a.RuleId} event={raw}");
        }
        return sb.ToString();
    }
}
