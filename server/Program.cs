using Microsoft.EntityFrameworkCore;
using OpenXDR.Server.Api;
using OpenXDR.Server.Correlation;
using OpenXDR.Server.Data;
using OpenXDR.Server.Rules;
using OpenXDR.Server.Services;
using OpenXDR.Server.Triage;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();
builder.Services.AddGrpc();
builder.Services.AddSingleton(sp => SigmaEngine.LoadFrom(
    builder.Configuration["Rules:Path"] ?? "../rules",
    sp.GetRequiredService<ILogger<SigmaEngine>>()));
builder.Services.AddHostedService<CorrelationEngine>();
builder.Services.AddSingleton<LlmClient>();
builder.Services.AddHostedService<TriageEngine>();
builder.Services.AddDbContext<OpenXdrDbContext>(o => o
    .UseNpgsql(builder.Configuration.GetConnectionString("Default"))
    .UseSnakeCaseNamingConvention());

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.MapGrpcService<AgentGrpcService>();
app.MapApi();

app.Run();
