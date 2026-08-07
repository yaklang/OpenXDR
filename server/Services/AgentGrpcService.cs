using System.Net;
using System.Text.Json;
using Grpc.Core;
using Microsoft.EntityFrameworkCore;
using OpenXDR.Server.Data;
using OpenXDR.Server.Grpc;
using OpenXDR.Server.Rules;

namespace OpenXDR.Server.Services;

public class AgentGrpcService(OpenXdrDbContext db, SigmaEngine rules, IConfiguration cfg)
    : AgentService.AgentServiceBase
{
    public override async Task<RegisterResponse> Register(RegisterRequest req, ServerCallContext ctx)
    {
        var asset = await db.Assets.FirstOrDefaultAsync(a => a.Hostname == req.Hostname);
        if (asset is null)
        {
            asset = new Asset { Id = Guid.CreateVersion7(), Hostname = req.Hostname };
            db.Assets.Add(asset);
        }
        asset.Os = req.Os;
        asset.AgentId ??= Guid.CreateVersion7();
        asset.IpAddrs = req.IpAddrs
            .Select(s => IPAddress.TryParse(s, out var ip) ? ip : null)
            .Where(ip => ip is not null)
            .ToArray()!;
        asset.LastSeen = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync();
        return new RegisterResponse { AgentId = asset.AgentId.Value.ToString() };
    }

    public override async Task<ReportAck> ReportEvents(IAsyncStreamReader<AgentEvent> stream, ServerCallContext ctx)
    {
        ulong received = 0;
        Guid? assetId = null;
        var dedupWindow = TimeSpan.FromMinutes(cfg.GetValue("Alerts:DedupWindowMinutes", 5));
        // 一条流对应一台主机，告警指纹 (rule_id, asset_id) 在流内就是 rule_id
        var dedup = new Dictionary<string, Alert>();
        await foreach (var ev in stream.ReadAllAsync(ctx.CancellationToken))
        {
            if (assetId is null && Guid.TryParse(ev.AgentId, out var agentGuid))
                assetId = (await db.Assets.FirstOrDefaultAsync(a => a.AgentId == agentGuid))?.Id;

            var evt = new Event
            {
                Id = Guid.CreateVersion7(),
                Ts = DateTimeOffset.FromUnixTimeMilliseconds(ev.TsUnixNs / 1_000_000),
                ClassUid = (int)ev.ClassUid,
                Source = "agent",
                AssetId = assetId,
                ProcessGuid = Guid.TryParse(ev.ProcessGuid, out var pg) ? pg : null,
                Username = ev.Username.Length > 0 ? ev.Username : null,
                ConnTuple = ev.ConnTuple.Length > 0 ? ev.ConnTuple : null,
                Raw = JsonDocument.Parse(ev.RawJson.Length > 0 ? ev.RawJson : "{}"),
            };
            db.Events.Add(evt);

            foreach (var rule in rules.Evaluate(evt.ClassUid, evt.Raw.RootElement))
            {
                // 风暴防线第一层：窗口内同指纹的告警只留一行，计数器累加
                if (dedup.TryGetValue(rule.Id, out var existing) && evt.Ts - existing.Ts < dedupWindow)
                {
                    if (db.Entry(existing).State == EntityState.Detached)
                        db.Alerts.Attach(existing);
                    existing.Count++;
                    existing.LastTs = evt.Ts;
                    continue;
                }
                var alert = new Alert
                {
                    Id = Guid.CreateVersion7(),
                    Ts = evt.Ts,
                    RuleId = rule.Id,
                    Severity = rule.Severity,
                    EventId = evt.Id,
                    AssetId = assetId,
                    LastTs = evt.Ts,
                };
                db.Alerts.Add(alert);
                dedup[rule.Id] = alert;
            }

            // 长连接流，攒批落库；清 tracker，否则内存随流龄无限涨
            if (++received % 500 == 0)
            {
                await db.SaveChangesAsync();
                db.ChangeTracker.Clear();
            }
        }
        await db.SaveChangesAsync();
        return new ReportAck { Received = received };
    }
}
