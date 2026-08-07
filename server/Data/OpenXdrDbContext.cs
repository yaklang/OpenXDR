using Microsoft.EntityFrameworkCore;

namespace OpenXDR.Server.Data;

public class OpenXdrDbContext(DbContextOptions<OpenXdrDbContext> options) : DbContext(options)
{
    public DbSet<Asset> Assets => Set<Asset>();
    public DbSet<Event> Events => Set<Event>();
    public DbSet<Alert> Alerts => Set<Alert>();
    public DbSet<Incident> Incidents => Set<Incident>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<Asset>(e =>
        {
            e.HasIndex(x => x.AgentId).IsUnique();
            e.Property(x => x.FirstSeen).HasDefaultValueSql("now()");
            e.Property(x => x.LastSeen).HasDefaultValueSql("now()");
        });

        b.Entity<Event>(e =>
        {
            e.HasIndex(x => x.Ts);
            e.HasIndex(x => new { x.AssetId, x.Ts });
            e.HasIndex(x => x.ProcessGuid).HasFilter("process_guid IS NOT NULL");
        });

        b.Entity<Alert>(e =>
        {
            e.HasIndex(x => x.IncidentId);
        });

        b.Entity<Incident>(e =>
        {
            e.Property(x => x.CreatedAt).HasDefaultValueSql("now()");
            e.Property(x => x.Status).HasDefaultValue("open");
        });
    }
}
