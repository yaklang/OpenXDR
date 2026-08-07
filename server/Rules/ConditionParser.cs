namespace OpenXDR.Server.Rules;

// Sigma condition 表达式：ident、not、and、or、括号。优先级 not > and > or。
public abstract record ConditionNode
{
    public abstract bool Eval(IReadOnlyDictionary<string, bool> selections);
}

public sealed record IdentNode(string Name) : ConditionNode
{
    public override bool Eval(IReadOnlyDictionary<string, bool> s) => s.GetValueOrDefault(Name);
}

public sealed record NotNode(ConditionNode Inner) : ConditionNode
{
    public override bool Eval(IReadOnlyDictionary<string, bool> s) => !Inner.Eval(s);
}

public sealed record AndNode(ConditionNode Left, ConditionNode Right) : ConditionNode
{
    public override bool Eval(IReadOnlyDictionary<string, bool> s) => Left.Eval(s) && Right.Eval(s);
}

public sealed record OrNode(ConditionNode Left, ConditionNode Right) : ConditionNode
{
    public override bool Eval(IReadOnlyDictionary<string, bool> s) => Left.Eval(s) || Right.Eval(s);
}

public static class ConditionParser
{
    public static ConditionNode Parse(string text)
    {
        var tokens = text.Replace("(", " ( ").Replace(")", " ) ")
            .Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var pos = 0;
        var node = ParseOr(tokens, ref pos);
        return pos == tokens.Length
            ? node
            : throw new FormatException($"condition 有多余 token: '{tokens[pos]}'");
    }

    private static ConditionNode ParseOr(string[] t, ref int pos)
    {
        var node = ParseAnd(t, ref pos);
        while (pos < t.Length && t[pos] == "or")
        {
            pos++;
            node = new OrNode(node, ParseAnd(t, ref pos));
        }
        return node;
    }

    private static ConditionNode ParseAnd(string[] t, ref int pos)
    {
        var node = ParseUnary(t, ref pos);
        while (pos < t.Length && t[pos] == "and")
        {
            pos++;
            node = new AndNode(node, ParseUnary(t, ref pos));
        }
        return node;
    }

    private static ConditionNode ParseUnary(string[] t, ref int pos)
    {
        if (pos >= t.Length) throw new FormatException("condition 意外结束");
        if (t[pos] == "not")
        {
            pos++;
            return new NotNode(ParseUnary(t, ref pos));
        }
        if (t[pos] == "(")
        {
            pos++;
            var node = ParseOr(t, ref pos);
            if (pos >= t.Length || t[pos] != ")") throw new FormatException("缺少右括号");
            pos++;
            return node;
        }
        return new IdentNode(t[pos++]);
    }
}
