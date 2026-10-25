using System.Text;
using System.Text.RegularExpressions;

namespace Carmine.Core.Sanitize.Rules.Jwt;

public static partial class JwtRule
{
    public static Rule Rule { get; } = new("jwt", RuleBy.Format, Find);

    // Base64url segments joined by dots: three for a signed token (the signature is empty for alg "none"),
    // five for an encrypted one (the key segment is empty for alg "dir"). Decoding the header is the real
    // test, so hostnames and version strings that fit this shape are rejected there.
    [GeneratedRegex($$"""{{Shared.Start}}[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]*){2,}""")]
    private static partial Regex Candidate();

    private static List<Finding> Find(string text) => [.. Candidate().Matches(text).SelectMany(m => TokensIn(m.Value, m.Index))];

    // A run of dotted segments can start with something else, such as a hostname glued on with a dot, so each
    // segment gets a turn as the header.
    private static List<Finding> TokensIn(string run, int at)
    {
        var parts = run.Split('.');
        var found = new List<Finding>();
        var offset = at;
        for (var i = 0; i + 2 < parts.Length;)
        {
            if (ParseSegment(parts[i]) is not OrderedDictionary<string, object?> header || !(header.TryGetValue("alg", out var alg) && alg is string))
            {
                offset += parts[i].Length + 1;
                i++;
                continue;
            }
            // An encrypted token keeps every segment it has, even when cut short; its payload can't be read.
            var encrypted = header.TryGetValue("enc", out var enc) && enc is string;
            var count = Math.Min(encrypted ? 5 : 3, parts.Length - i);
            var token = string.Join('.', parts, i, count);
            var claims = encrypted ? null : ParseSegment(parts[i + 1]) as OrderedDictionary<string, object?>;
            found.Add(new Finding(offset, offset + token.Length, "jwt", encrypted ? "JWE" : "JWT", new DecodedJwt(header, claims ?? new())));
            offset += token.Length + 1;
            i += count;
        }
        return found;
    }

    // atob, then TextDecoder (which drops a leading byte order mark and turns invalid UTF-8 into U+FFFD), then
    // JSON.parse. Null where any of them throws.
    private static object? ParseSegment(string segment)
    {
        if (Shared.Atob(segment.Replace('-', '+').Replace('_', '/')) is not { } bytes) return null;
        var bom = bytes is [0xEF, 0xBB, 0xBF, ..] ? 3 : 0;
        return JsonParse.TryParse(Encoding.UTF8.GetString(bytes, bom, bytes.Length - bom), out var value) ? value : null;
    }
}
