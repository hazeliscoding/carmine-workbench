using System.Buffers;
using System.Text.RegularExpressions;

namespace Carmine.Core.Sanitize.Rules;

// The patterns are ported from JavaScript and must match exactly what JavaScript matches, so they spell out
// what .NET reads differently: \w is [A-Za-z0-9_], \d is [0-9], \s is Space, . is [^\n\r\u2028\u2029], an
// end-of-input $ is \z, and the i flag becomes [Aa] classes, because .NET's IgnoreCase also lets k match the
// Kelvin sign. A sticky (y) pattern starts with \G and is matched from a start position. JavaScript's \1
// matches nothing when its group took no part, where .NET's fails, so such a backreference is (?(1)\1).
internal static partial class Shared
{
    // JavaScript's \s, which is also what its trim() drops. .NET's \s also matches U+0085 and misses U+FEFF.
    public const string Space =
        "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff";

    public static readonly SearchValues<char> Spaces = SearchValues.Create(Space);

    // Where a token may start: not inside a word, but right after an escape such as \n in a JSON-escaped log
    // line, or after a URL-encoded character such as %3D. Nothing starts right after \ or %, so the n of \n
    // or the 3D of %3D is never read as part of a token.
    public const string Start = """(?:(?<![A-Za-z0-9_\\%-])|(?<=\\[nrt]|%[0-9A-Fa-f]{2}))""";

    // Start inside a pattern that JavaScript matches case-insensitively, where \n also matches \N.
    public const string StartIgnoreCase = """(?:(?<![A-Za-z0-9_\\%-])|(?<=\\[nrtNRT]|%[0-9A-Fa-f]{2}))""";

    // Where a bare value ends early: a common HTML tag such as <br>, any closing tag, a label from an earlier
    // pass, or a < or > with no more value after it, as in <https://…?token=T>. Other angle brackets can sit
    // inside a password, so they don't end it. Only case-insensitive patterns use it, so tags match in any case.
    public const string ValueStop =
        $$"""<(?:[Aa]|[Bb]|[Ii]|[Pp]|[Bb][Rr]|[Hh][Rr]|[Tt][Dd]|[Tt][Hh]|[Tt][Rr]|[Ll][Ii]|[Uu][Ll]|[Oo][Ll]|[Ee][Mm]|[Dd][Ii][Vv]|[Pp][Rr][Ee]|[Ss][Pp][Aa][Nn]|[Cc][Oo][Dd][Ee]|[Ss][Tt][Rr][Oo][Nn][Gg]|[Tt][Aa][Bb][Ll][Ee]|[Tt][Bb][Oo][Dd][Yy]|[Tt][Hh][Ee][Aa][Dd]|[Bb][Oo][Dd][Yy]|[Hh][Tt][Mm][Ll]|[Hh][Ee][Aa][Dd])(?![A-Za-z0-9_])[^<>]*>|</[A-Za-z][A-Za-z0-9_:.-]*>|<[^<>{{Space}}]+#[0-9]+>|[<>](?=[{{Space}}'"`,;&(){}[\]\\<>]|\z)""";

    private static readonly HashSet<string> CodeWords =
    [
        "await", "new", "typeof", "function", "async", "require", "import", "return", "yield", "string", "number", "boolean",
        "any", "unknown", "never", "void", "object", "str", "int", "float", "bool", "bytes", "dict", "list",
    ];

    [GeneratedRegex("""^[A-Za-z_$.]+\z""")]
    private static partial Regex CalleeShape();

    [GeneratedRegex("""([a-z0-9])([A-Z])""")]
    private static partial Regex CamelHump();

    [GeneratedRegex("""[^a-z0-9]+""")]
    private static partial Regex NotLowerAlphanumeric();

    [GeneratedRegex("""^[A-Za-z_$]+(?:\.[A-Za-z_$]+)+\z""")]
    private static partial Regex DottedIdentifier();

    // A bare identifier right before ( or [ is code that reads a secret, as in getToken() or os.environ["X"].
    // Tokens carry digits, so Bearer T(expired) still counts. Identifiers are mostly lowercase, while a random
    // run of letters is about half uppercase.
    public static bool IsCallee(string value) =>
        CalleeShape().IsMatch(value) && (double)value.Count(char.IsAsciiLetterUpper) / value.Length < 0.4;

    // X- is a legacy header prefix that says nothing about the value. Names reach here only through ASCII
    // patterns, so ToLowerInvariant lowers them as JavaScript's toLowerCase does.
    public static string KindFromName(string name)
    {
        var words = NotLowerAlphanumeric().Split(CamelHump().Replace(name, "$1-$2").ToLowerInvariant()).Where(w => w.Length > 0);
        var kind = string.Join('-', words);
        return kind.StartsWith("x-", StringComparison.Ordinal) ? kind[2..] : kind;
    }

    // For values whose name alone isn't proof, so prose such as "Authorization: denied for usr_034" stays.
    public static bool LooksLikeCredential(string value) =>
        !LooksLikeCode(value) && ((value.Length >= 8 && value.Any(char.IsAsciiDigit)) || value.Length >= 20);

    // Code that reads a secret instead of holding one: const token = await getToken(), password: string,
    // this.configuration.secret. Real tokens carry digits or dashes in their dotted parts.
    public static bool LooksLikeCode(string value) => CodeWords.Contains(AsciiLower(value)) || DottedIdentifier().IsMatch(value);

    // What JavaScript's i flag (without u) treats as one letter: only A-Z and a-z fold together.
    public static string AsciiLower(string value) =>
        string.Create(value.Length, value, static (chars, source) =>
        {
            for (var i = 0; i < source.Length; i++) chars[i] = char.IsAsciiLetterUpper(source[i]) ? (char)(source[i] | 0x20) : source[i];
        });

    // For a sticky pattern, which starts with \G.
    public static string? MatchAt(Regex pattern, string text, int at)
    {
        var match = pattern.Match(text, at);
        return match.Success ? match.Value : null;
    }

    // JavaScript's atob, which follows WHATWG's forgiving base64: whitespace is ignored, padding is optional,
    // and the unused bits of the last character may be set. Null where atob throws.
    public static byte[]? Atob(string data)
    {
        var chars = data.Where(c => c is not ('\t' or '\n' or '\f' or '\r' or ' ')).ToArray();
        var length = chars.Length;
        if (length % 4 == 0 && length > 0 && chars[length - 1] == '=') length -= length > 1 && chars[length - 2] == '=' ? 2 : 1;
        if (length % 4 == 1) return null;

        var bytes = new List<byte>(length / 4 * 3 + 2);
        var buffer = 0;
        var bits = 0;
        for (var i = 0; i < length; i++)
        {
            var sextet = chars[i] switch
            {
                >= 'A' and <= 'Z' => chars[i] - 'A',
                >= 'a' and <= 'z' => chars[i] - 'a' + 26,
                >= '0' and <= '9' => chars[i] - '0' + 52,
                '+' => 62,
                '/' => 63,
                _ => -1,
            };
            if (sextet < 0) return null;
            buffer = (buffer << 6) | sextet;
            bits += 6;
            if (bits == 24)
            {
                bytes.Add((byte)(buffer >> 16));
                bytes.Add((byte)(buffer >> 8));
                bytes.Add((byte)buffer);
                buffer = 0;
                bits = 0;
            }
        }
        if (bits == 12) bytes.Add((byte)(buffer >> 4));
        if (bits == 18)
        {
            bytes.Add((byte)(buffer >> 10));
            bytes.Add((byte)(buffer >> 2));
        }
        return [.. bytes];
    }
}
