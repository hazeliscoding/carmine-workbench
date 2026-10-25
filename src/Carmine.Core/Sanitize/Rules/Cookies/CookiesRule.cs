using System.Text.RegularExpressions;

namespace Carmine.Core.Sanitize.Rules.Cookies;

public static partial class CookiesRule
{
    public static Rule Rule { get; } = new("cookies", RuleBy.Context, Find);

    // A Cookie or Set-Cookie header name, optionally quoted as a JSON or Python key (escaped when the JSON
    // sits inside a log string, or a Python b'' string), then a colon and an optional opening quote or Go
    // map bracket.
    [GeneratedRegex($$"""{{Shared.StartIgnoreCase}}(?:[bBrRuUfF]{0,2}(\\?["']))?([Ss][Ee][Tt]-[Cc][Oo][Oo][Kk][Ii][Ee]|[Cc][Oo][Oo][Kk][Ii][Ee])(?(1)\1)[ \t]*:[ \t]*\[?(?:[bBrRuUfF]{0,2}\\?["'])?""")]
    private static partial Regex Header();

    [GeneratedRegex($$"""(?<![^{{Shared.Space}}])(?:-b[ \t]*|--cookie(?:=|[ \t]+))["']?""")]
    private static partial Regex Curl();

    // One name=value pair. The name is an RFC 6265 token, and the value can't hold whitespace, quotes, commas,
    // semicolons or backslashes, except for a pair of double quotes around the whole value.
    [GeneratedRegex($$"""\G[ \t]*([^{{Shared.Space}}=;,"'\\[\]()<>@:/?{}]+)=("?)([^{{Shared.Space}};,"'\\[\]]*)\2""")]
    private static partial Regex Pair();

    [GeneratedRegex("""\G[ \t]*;""")]
    private static partial Regex NextPair();

    // Set-Cookie attributes such as Path and Expires. The comma in "Expires=Thu, 24 Sep …" comes before a digit.
    [GeneratedRegex("""\G(?:[ \t]*;[ \t]*[^;,\r\n\\'"]*(?:,[ \t]*[0-9][^;,\r\n\\'"]*)?)*""")]
    private static partial Regex Attributes();

    // What can come between two cookies of one header: list brackets, commas and quotes, as in Node's
    // [ 'a=1; Path=/', 'b=2' ], or the ", " that joins repeated Set-Cookie headers.
    [GeneratedRegex("""\G(?:[ \t,[\]]|[bBrRuUfF]{0,2}\\?["'])*""")]
    private static partial Regex Gap();

    [GeneratedRegex("""^[A-Za-z0-9_.-]+\z""")]
    private static partial Regex PlainValue();

    private static List<Finding> Find(string text) =>
    [
        .. Header().Matches(text).SelectMany(m => Pairs(text, m.Index + m.Length, m.Groups[2].Value.ToLowerInvariant() == "set-cookie")),
        .. Curl().Matches(text).SelectMany(m => Pairs(text, m.Index + m.Length, false)),
    ];

    private static List<Finding> Pairs(string text, int at, bool setCookie)
    {
        var found = new List<Finding>();
        for (var pos = at; ;)
        {
            var p = Pair().Match(text, Skip(Gap(), text, pos));
            if (!p.Success) break;
            var name = p.Groups[1].Value;
            var value = p.Groups[3];
            if (value.Length > 0 && !IsPlainShort(value.Value)) found.Add(new Finding(value.Index, value.Index + value.Length, $"cookie:{name}", $"{name} cookie"));
            pos = Skip(setCookie ? Attributes() : NextPair(), text, p.Index + p.Length);
        }
        return found;
    }

    private static int Skip(Regex pattern, string text, int from)
    {
        var match = pattern.Match(text, from);
        return match.Success ? match.Index + match.Length : from;
    }

    // Preferences such as theme=dark or lang=en-US help debugging and grant nothing.
    private static bool IsPlainShort(string value) => value.Length < 8 && PlainValue().IsMatch(value);
}
