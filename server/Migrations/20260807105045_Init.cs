using System;
using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OpenXDR.Server.Migrations
{
    /// <inheritdoc />
    public partial class Init : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "assets",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    hostname = table.Column<string>(type: "text", nullable: false),
                    os = table.Column<string>(type: "text", nullable: true),
                    ip_addrs = table.Column<IPAddress[]>(type: "inet[]", nullable: true),
                    agent_id = table.Column<Guid>(type: "uuid", nullable: true),
                    first_seen = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()"),
                    last_seen = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()")
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_assets", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "incidents",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()"),
                    status = table.Column<string>(type: "text", nullable: false, defaultValue: "open"),
                    graph = table.Column<JsonDocument>(type: "jsonb", nullable: false),
                    ai_verdict = table.Column<JsonDocument>(type: "jsonb", nullable: true),
                    title = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_incidents", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "events",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    ts = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    class_uid = table.Column<int>(type: "integer", nullable: false),
                    source = table.Column<string>(type: "text", nullable: false),
                    asset_id = table.Column<Guid>(type: "uuid", nullable: true),
                    process_guid = table.Column<Guid>(type: "uuid", nullable: true),
                    username = table.Column<string>(type: "text", nullable: true),
                    conn_tuple = table.Column<string>(type: "text", nullable: true),
                    raw = table.Column<JsonDocument>(type: "jsonb", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_events", x => x.id);
                    table.ForeignKey(
                        name: "fk_events_assets_asset_id",
                        column: x => x.asset_id,
                        principalTable: "assets",
                        principalColumn: "id");
                });

            migrationBuilder.CreateTable(
                name: "alerts",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    ts = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    rule_id = table.Column<string>(type: "text", nullable: false),
                    severity = table.Column<short>(type: "smallint", nullable: false),
                    event_id = table.Column<Guid>(type: "uuid", nullable: true),
                    asset_id = table.Column<Guid>(type: "uuid", nullable: true),
                    incident_id = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_alerts", x => x.id);
                    table.ForeignKey(
                        name: "fk_alerts_assets_asset_id",
                        column: x => x.asset_id,
                        principalTable: "assets",
                        principalColumn: "id");
                    table.ForeignKey(
                        name: "fk_alerts_events_event_id",
                        column: x => x.event_id,
                        principalTable: "events",
                        principalColumn: "id");
                });

            migrationBuilder.CreateIndex(
                name: "ix_alerts_asset_id",
                table: "alerts",
                column: "asset_id");

            migrationBuilder.CreateIndex(
                name: "ix_alerts_event_id",
                table: "alerts",
                column: "event_id");

            migrationBuilder.CreateIndex(
                name: "ix_alerts_incident_id",
                table: "alerts",
                column: "incident_id");

            migrationBuilder.CreateIndex(
                name: "ix_assets_agent_id",
                table: "assets",
                column: "agent_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_events_asset_id_ts",
                table: "events",
                columns: new[] { "asset_id", "ts" });

            migrationBuilder.CreateIndex(
                name: "ix_events_process_guid",
                table: "events",
                column: "process_guid",
                filter: "process_guid IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "ix_events_ts",
                table: "events",
                column: "ts");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "alerts");

            migrationBuilder.DropTable(
                name: "incidents");

            migrationBuilder.DropTable(
                name: "events");

            migrationBuilder.DropTable(
                name: "assets");
        }
    }
}
