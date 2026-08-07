using System.Text.Json;
using System.Text.RegularExpressions;

namespace OpenXDR.Server.Rules;

public sealed class CompiledRule
{
    public required string Id { get; init; }
    public required string Title { get; init; }
    public short Severity { get; init; }
    public int? ClassUid { get; init; }
    public required Dictionary<string, Selection> Selections { get; init; }
    public required ConditionNode Condition { get; init; }

    public bool Matches(JsonElement raw)
    {
        var results = Selections.ToDictionary(kv => kv.Key, kv => kv.Value.Matches(raw));
        return Condition.Eval(results);
    }
}

/// <summary>Sigma selection：map 内字段是 AND，map 列表是 OR。</summary>
public sealed class Selection
{
    public required List<List<FieldTest>> Branches { get; init; }

    public bool Matches(JsonElement raw) =>
        Branches.Any(branch => branch.All(t => t.Matches(raw)));
}

/// <summary>单字段测试：值列表是 OR（带 |all 修饰符时为 AND），null 表示字段必须缺失。</summary>
public sealed class FieldTest
{
    public required string Path { get; init; }
    public required List<Regex> Patterns { get; init; }
    public bool ExpectNull { get; init; }
    public bool MatchAll { get; init; }

    public bool Matches(JsonElement raw)
    {
        var value = Resolve(raw, Path);
        if (ExpectNull) return value is null;
        if (value is null) return false;
        return MatchAll
            ? Patterns.All(p => p.IsMatch(value))
            : Patterns.Any(p => p.IsMatch(value));
    }

    private static string? Resolve(JsonElement root, string dotPath)
    {
        var current = root;
        foreach (var part in dotPath.Split('.'))
        {
            if (current.ValueKind != JsonValueKind.Object ||
                !current.TryGetProperty(part, out current))
                return null;
        }
        return current.ValueKind switch
        {
            JsonValueKind.String => current.GetString(),
            JsonValueKind.Null or JsonValueKind.Undefined => null,
            _ => current.GetRawText(),
        };
    }
}
