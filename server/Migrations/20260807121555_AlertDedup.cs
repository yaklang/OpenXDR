using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OpenXDR.Server.Migrations
{
    /// <inheritdoc />
    public partial class AlertDedup : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "count",
                table: "alerts",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "last_ts",
                table: "alerts",
                type: "timestamp with time zone",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "count",
                table: "alerts");

            migrationBuilder.DropColumn(
                name: "last_ts",
                table: "alerts");
        }
    }
}
