using Microsoft.EntityFrameworkCore;
using OpenXDR.Server.Data;
using OpenXDR.Server.Rules;

namespace OpenXDR.Server.Api;

public static class ApiEndpoints
{
    // triaged 是引擎专属状态，分析师只能在这三个之间拨
    private static readonly string[] AnalystStatuses = ["open", "closed", "false_positive"];

    public static void MapApi(this WebApplication app)
    {
        var api = app.MapGroup("/api");

        api.MapGet("/incidents", async (OpenXdrDbContext db, string? status, int limit = 50) =>
        {
            var query = db.Incidents.AsNoTracking();
            if (!string.IsNullOrEmpty(status)) query = query.Where(i => i.Status == status);
            return await query
                .OrderByDescending(i => i.CreatedAt)
                .Take(Math.Clamp(limit, 1, 200))
                .Select(i => new
                {
                    i.Id, i.CreatedAt, i.Status, i.Title, i.AiVerdict,
                    AlertCount = db.Alerts.Count(a => a.IncidentId == i.Id),
                })
                .ToListAsync();
        });

        api.MapGet("/incidents/{id:guid}", async (OpenXdrDbContext db, SigmaEngine rules, Guid id) =>
        {
            var incident = await db.Incidents.AsNoTracking().FirstOrDefaultAsync(i => i.Id == id);
            if (incident is null) return Results.NotFound();

            var alerts = await db.Alerts.AsNoTracking()
                .Where(a => a.IncidentId == id)
                .OrderBy(a => a.Ts)
                .Take(500)
                .Select(a => new
                {
                    a.Id, a.Ts, a.LastTs, a.Count, a.Severity, a.RuleId,
                    Event = a.Event == null ? null : a.Event.Raw,
                })
                .ToListAsync();

            return Results.Ok(new
            {
                incident.Id, incident.CreatedAt, incident.Status, incident.Title,
                incident.Graph, incident.AiVerdict,
                Alerts = alerts.Select(a => new
                {
                    a.Id, a.Ts, a.LastTs, a.Count, a.Severity, a.RuleId,
                    RuleTitle = rules.TitleOf(a.RuleId),
                    a.Event,
                }),
            });
        });

        api.MapPost("/incidents/{id:guid}/status", async (OpenXdrDbContext db, Guid id, StatusChange body) =>
        {
            if (!AnalystStatuses.Contains(body.Status))
                return Results.BadRequest(new { error = "status 必须是 open / closed / false_positive" });
            var updated = await db.Incidents
                .Where(i => i.Id == id)
                .ExecuteUpdateAsync(s => s.SetProperty(i => i.Status, body.Status));
            return updated == 0 ? Results.NotFound() : Results.NoContent();
        });

        api.MapGet("/assets", async (OpenXdrDbContext db) =>
            await db.Assets.AsNoTracking()
                .OrderBy(a => a.Hostname)
                .Select(a => new { a.Id, a.Hostname, a.Os, a.AgentId, a.FirstSeen, a.LastSeen })
                .ToListAsync());
    }

    public record StatusChange(string Status);
}
