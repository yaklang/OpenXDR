using System.Net.Http.Json;
using System.Text.Json;

namespace OpenXDR.Server.Triage;

/// <summary>
/// OpenAI 兼容 chat completions 客户端。BaseUrl 可配，默认本地 Ollama——安全数据不出内网。
/// </summary>
public sealed class LlmClient(IConfiguration cfg)
{
    private readonly HttpClient _http = new()
    {
        Timeout = TimeSpan.FromSeconds(cfg.GetValue("Ai:TimeoutSeconds", 120)),
    };

    public bool Enabled => !string.IsNullOrEmpty(cfg["Ai:Model"]);

    public async Task<string> ChatAsync(string system, string user, CancellationToken ct)
    {
        var baseUrl = (cfg["Ai:BaseUrl"] ?? "http://localhost:11434/v1").TrimEnd('/');
        var request = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/chat/completions");
        if (cfg["Ai:ApiKey"] is { Length: > 0 } key)
            request.Headers.Authorization = new("Bearer", key);
        request.Content = JsonContent.Create(new
        {
            model = cfg["Ai:Model"],
            messages = new object[]
            {
                new { role = "system", content = system },
                new { role = "user", content = user },
            },
            response_format = new { type = "json_object" },
            temperature = 0.1,
        });

        var response = await _http.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        return doc.RootElement.GetProperty("choices")[0]
            .GetProperty("message").GetProperty("content").GetString() ?? "";
    }
}
