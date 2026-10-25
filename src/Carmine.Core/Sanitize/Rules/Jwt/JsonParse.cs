using System.Globalization;
using System.Text;

namespace Carmine.Core.Sanitize.Rules.Jwt;

// JavaScript's JSON.parse, which System.Text.Json is stricter than. JavaScript takes duplicate keys (the last
// value wins, in the first one's place), escaped lone surrogates, numbers beyond a double (Infinity) and any
// depth, so this parser loops instead of recursing. Every number is a double, as in JavaScript, so a decoded
// claim holds the same value in both engines.
internal static class JsonParse
{
    public static bool TryParse(string text, out object? result)
    {
        result = null;
        var pos = 0;
        var open = new Stack<object>();
        var keys = new Stack<string>();
        while (true)
        {
            object? value;
            SkipSpace(text, ref pos);
            if (pos == text.Length) return false;
            if (text[pos] == '{')
            {
                pos++;
                SkipSpace(text, ref pos);
                if (!Take(text, ref pos, '}'))
                {
                    if (!TryKey(text, ref pos, out var key)) return false;
                    open.Push(new OrderedDictionary<string, object?>());
                    keys.Push(key);
                    continue;
                }
                value = new OrderedDictionary<string, object?>();
            }
            else if (text[pos] == '[')
            {
                pos++;
                SkipSpace(text, ref pos);
                if (!Take(text, ref pos, ']'))
                {
                    open.Push(new List<object?>());
                    continue;
                }
                value = new List<object?>();
            }
            else if (!TryScalar(text, ref pos, out value))
            {
                return false;
            }

            while (true)
            {
                SkipSpace(text, ref pos);
                if (open.Count == 0)
                {
                    result = value;
                    return pos == text.Length;
                }
                if (open.Peek() is List<object?> items)
                {
                    items.Add(value);
                    if (Take(text, ref pos, ',')) break;
                    if (!Take(text, ref pos, ']')) return false;
                    value = open.Pop();
                    continue;
                }
                var members = (OrderedDictionary<string, object?>)open.Peek();
                members[keys.Pop()] = value;
                if (Take(text, ref pos, ','))
                {
                    if (!TryKey(text, ref pos, out var key)) return false;
                    keys.Push(key);
                    break;
                }
                if (!Take(text, ref pos, '}')) return false;
                open.Pop();
                value = InJavaScriptOrder(members);
            }
        }
    }

    private static void SkipSpace(string text, ref int pos)
    {
        while (pos < text.Length && text[pos] is ' ' or '\t' or '\n' or '\r') pos++;
    }

    private static bool Take(string text, ref int pos, char c)
    {
        if (pos == text.Length || text[pos] != c) return false;
        pos++;
        return true;
    }

    private static bool TryKey(string text, ref int pos, out string key)
    {
        key = "";
        SkipSpace(text, ref pos);
        if (pos == text.Length || text[pos] != '"' || !TryString(text, ref pos, out key)) return false;
        SkipSpace(text, ref pos);
        return Take(text, ref pos, ':');
    }

    private static bool TryScalar(string text, ref int pos, out object? value)
    {
        value = null;
        if (text[pos] == '"')
        {
            if (!TryString(text, ref pos, out var s)) return false;
            value = s;
            return true;
        }
        if (TryLiteral(text, ref pos, "true")) value = true;
        else if (TryLiteral(text, ref pos, "false")) value = false;
        else if (!TryLiteral(text, ref pos, "null")) return TryNumber(text, ref pos, out value);
        return true;
    }

    private static bool TryLiteral(string text, ref int pos, string literal)
    {
        if (!text.AsSpan(pos).StartsWith(literal, StringComparison.Ordinal)) return false;
        pos += literal.Length;
        return true;
    }

    private static bool TryNumber(string text, ref int pos, out object? value)
    {
        value = null;
        var start = pos;
        Take(text, ref pos, '-');
        if (!Take(text, ref pos, '0'))
        {
            if (pos == text.Length || text[pos] is < '1' or > '9') return false;
            SkipDigits(text, ref pos);
        }
        if (Take(text, ref pos, '.') && !SkipDigits(text, ref pos)) return false;
        if (pos < text.Length && text[pos] is 'e' or 'E')
        {
            pos++;
            if (!Take(text, ref pos, '+')) Take(text, ref pos, '-');
            if (!SkipDigits(text, ref pos)) return false;
        }
        // Correctly rounded, and out of range gives Infinity or 0, as JavaScript's number parsing does.
        value = double.Parse(text.AsSpan(start, pos - start), NumberStyles.Float, CultureInfo.InvariantCulture);
        return true;
    }

    private static bool SkipDigits(string text, ref int pos)
    {
        var start = pos;
        while (pos < text.Length && char.IsAsciiDigit(text[pos])) pos++;
        return pos > start;
    }

    private static bool TryString(string text, ref int pos, out string value)
    {
        value = "";
        var s = new StringBuilder();
        for (pos++; pos < text.Length; pos++)
        {
            var c = text[pos];
            if (c == '"')
            {
                pos++;
                value = s.ToString();
                return true;
            }
            if (c < ' ') return false;
            if (c != '\\')
            {
                s.Append(c);
                continue;
            }
            if (++pos == text.Length) return false;
            switch (text[pos])
            {
                case '"': s.Append('"'); break;
                case '\\': s.Append('\\'); break;
                case '/': s.Append('/'); break;
                case 'b': s.Append('\b'); break;
                case 'f': s.Append('\f'); break;
                case 'n': s.Append('\n'); break;
                case 'r': s.Append('\r'); break;
                case 't': s.Append('\t'); break;
                case 'u' when pos + 4 < text.Length && !text.AsSpan(pos + 1, 4).ContainsAnyExcept("0123456789abcdefABCDEF"):
                    s.Append((char)int.Parse(text.AsSpan(pos + 1, 4), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture));
                    pos += 4;
                    break;
                default: return false;
            }
        }
        return false;
    }

    // JavaScript lists an object's array-index keys (0 to 2^32 - 2, written without leading zeros) first, in
    // numeric order, then the other keys in the order they were added.
    private static OrderedDictionary<string, object?> InJavaScriptOrder(OrderedDictionary<string, object?> members)
    {
        if (!members.Keys.Any(IsArrayIndex)) return members;
        var ordered = new OrderedDictionary<string, object?>(members.Count);
        foreach (var (key, value) in members.Where(m => IsArrayIndex(m.Key)).OrderBy(m => uint.Parse(m.Key, CultureInfo.InvariantCulture)))
        {
            ordered.Add(key, value);
        }
        foreach (var (key, value) in members.Where(m => !IsArrayIndex(m.Key))) ordered.Add(key, value);
        return ordered;
    }

    private static bool IsArrayIndex(string key) =>
        key.Length is > 0 and <= 10 && key.All(char.IsAsciiDigit) && (key == "0" || key[0] != '0')
            && ulong.Parse(key, CultureInfo.InvariantCulture) < uint.MaxValue;
}
