using System.Text.Json;
using System.Text.RegularExpressions;
using YamlDotNet.Serialization;

namespace OpenXDR.Server.Rules;

/// <summary>
/// Sigma 规则引擎。启动时加载规则目录并编译，运行期对入库事件同步匹配。
/// 支持子集：字段匹配、contains/startswith/endswith/re/all 修饰符、通配符、and/or/not 条件。
/// 不支持的规则（如 'x of y' 聚合条件）加载时告警跳过。
/// </summary>
public sealed class SigmaEngine
{
    // Sigma 标准字段名 -> OCSF raw 内的 dot path；未映射的字段名按 dot path 直接使用
    private static readonly Dictionary<string, string> FieldMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Image"] = "process.file.path",
        ["CommandLine"] = "process.cmd_line",
        ["ParentImage"] = "process.parent_process.file.path",
        ["ParentCommandLine"] = "process.parent_process.cmd_line",
        ["User"] = "actor.user.name",
    };

    private static readonly Dictionary<string, int> CategoryMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["process_creation"] = 1007,
        ["network_connection"] = 4001,
        ["dns_query"] = 4003,
    };

    private static readonly Dictionary<string, short> LevelMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["informational"] = 1, ["low"] = 2, ["medium"] = 3, ["high"] = 4, ["critical"] = 5,
    };

    private readonly List<CompiledRule> _rules;
    private readonly Dictionary<string, CompiledRule> _byId;

    private SigmaEngine(List<CompiledRule> rules)
    {
        _rules = rules;
        _byId = [];
        foreach (var r in rules) _byId.TryAdd(r.Id, r);
    }

    public int RuleCount => _rules.Count;

    public string? TitleOf(string ruleId) => _byId.GetValueOrDefault(ruleId)?.Title;

    public IEnumerable<CompiledRule> Evaluate(int classUid, JsonElement raw) =>
        _rules.Where(r => (r.ClassUid is null || r.ClassUid == classUid) && r.Matches(raw));

    public static SigmaEngine LoadFrom(string dir, ILogger logger)
    {
        var rules = new List<CompiledRule>();
        if (!Directory.Exists(dir))
        {
            logger.LogWarning("Sigma 规则目录不存在: {Dir}", Path.GetFullPath(dir));
            return new SigmaEngine(rules);
        }

        var deserializer = new DeserializerBuilder().Build();
        var files = Directory.EnumerateFiles(dir, "*.yml", SearchOption.AllDirectories)
            .Concat(Directory.EnumerateFiles(dir, "*.yaml", SearchOption.AllDirectories));
        foreach (var file in files)
        {
            try
            {
                var doc = deserializer.Deserialize<Dictionary<object, object>>(File.ReadAllText(file));
                rules.Add(Compile(doc));
            }
            catch (Exception e)
            {
                logger.LogWarning("跳过规则 {File}: {Reason}", Path.GetFileName(file), e.Message);
            }
        }
        logger.LogInformation("Sigma 规则加载完成: {Count} 条", rules.Count);
        return new SigmaEngine(rules);
    }

    private static CompiledRule Compile(Dictionary<object, object> doc)
    {
        var detection = doc["detection"] as Dictionary<object, object>
            ?? throw new FormatException("缺少 detection 段");
        var conditionText = detection["condition"]?.ToString()
            ?? throw new FormatException("缺少 condition");
        if (Regex.IsMatch(conditionText, @"\bof\b"))
            throw new NotSupportedException($"暂不支持聚合条件: '{conditionText}'");

        var selections = new Dictionary<string, Selection>();
        foreach (var (key, value) in detection)
        {
            var name = key.ToString()!;
            if (name == "condition") continue;
            selections[name] = CompileSelection(value);
        }

        int? classUid = null;
        if (doc.GetValueOrDefault("logsource") is Dictionary<object, object> logsource &&
            logsource.GetValueOrDefault("category") is { } category)
        {
            classUid = CategoryMap.TryGetValue(category.ToString()!, out var uid)
                ? uid
                : throw new NotSupportedException($"未知 logsource category: {category}");
        }

        return new CompiledRule
        {
            Id = doc.GetValueOrDefault("id")?.ToString()
                ?? doc.GetValueOrDefault("title")?.ToString()
                ?? throw new FormatException("缺少 id 和 title"),
            Title = doc.GetValueOrDefault("title")?.ToString() ?? "(untitled)",
            Severity = LevelMap.GetValueOrDefault(doc.GetValueOrDefault("level")?.ToString() ?? "medium", (short)3),
            ClassUid = classUid,
            Selections = selections,
            Condition = ConditionParser.Parse(conditionText),
        };
    }

    private static Selection CompileSelection(object? value) => value switch
    {
        Dictionary<object, object> map => new Selection { Branches = [CompileBranch(map)] },
        List<object> list when list.All(i => i is Dictionary<object, object>) =>
            new Selection { Branches = list.Select(i => CompileBranch((Dictionary<object, object>)i)).ToList() },
        _ => throw new NotSupportedException("暂不支持关键字列表 selection"),
    };

    private static List<FieldTest> CompileBranch(Dictionary<object, object> map) =>
        map.Select(kv => CompileFieldTest(kv.Key.ToString()!, kv.Value)).ToList();

    private static FieldTest CompileFieldTest(string key, object? value)
    {
        var parts = key.Split('|');
        var path = FieldMap.GetValueOrDefault(parts[0], parts[0]);
        var mods = parts.Skip(1).Select(m => m.ToLowerInvariant()).ToHashSet();

        if (value is null)
            return new FieldTest { Path = path, Patterns = [], ExpectNull = true };

        var values = value as List<object> ?? [value];
        return new FieldTest
        {
            Path = path,
            Patterns = values.Select(v => BuildRegex(v?.ToString() ?? "", mods)).ToList(),
            MatchAll = mods.Contains("all"),
        };
    }

    private static Regex BuildRegex(string value, HashSet<string> mods)
    {
        const RegexOptions opts = RegexOptions.IgnoreCase | RegexOptions.Compiled;
        if (mods.Contains("re")) return new Regex(value, opts);

        // Sigma 通配符 * ? -> 正则；修饰符决定锚点
        var escaped = Regex.Escape(value).Replace(@"\*", ".*").Replace(@"\?", ".");
        var pattern = mods.Contains("contains") ? escaped
            : mods.Contains("startswith") ? "^" + escaped
            : mods.Contains("endswith") ? escaped + "$"
            : "^" + escaped + "$";
        return new Regex(pattern, opts);
    }
}
