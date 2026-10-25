using System.Text;
using System.Text.RegularExpressions;
using Carmine.Core.Sanitize;

namespace Carmine.Tests.Sanitize;

// Fake secrets are built at test time, so the repo never holds a string that GitHub secret scanning or a
// vendor's partner program would match. Prefixes are split for the same reason. The values are the ones
// the TypeScript engine's testing/fixtures.ts built, character for character.
internal static partial class Fakes
{
    private const string Upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private const string Digits = "0123456789";
    private const string Alnum = Upper + "abcdefghijklmnopqrstuvwxyz" + Digits;
    private const string B64Url = Alnum + "-_";
    private const string B64 = Alnum + "+/";

    private static readonly Dictionary<string, Func<int, string>> Builders = new()
    {
        ["jwt"] = n => Jwt("""{"alg":"RS256","typ":"JWT","kid":"orders-2026-09"}""", n, Chars($"jwt{n}", 43, B64Url)),
        ["jwt-none"] = n => Jwt("""{"alg":"none","typ":"JWT"}""", n, ""),
        // Encrypted, with alg "dir" and so an empty key segment, as NextAuth session cookies are.
        ["jwe"] = n => string.Join('.', Base64Url("""{"alg":"dir","enc":"A256GCM"}"""), "", Chars($"iv{n}", 16, B64Url), Chars($"ct{n}", 60, B64Url), Chars($"tag{n}", 22, B64Url)),
        ["private-key"] = n => Pem("RSA ", n, "\n"),
        // As it sits inside a JSON string, such as a Google service-account file: newlines escaped as \n.
        ["private-key-json"] = n => Pem("", n, "\\n"),
        // Indented under a YAML key.
        ["private-key-yaml"] = n => Pem("EC ", n, "\n    "),
        // Pasted without its END line.
        ["private-key-truncated"] = n => Pem("OPENSSH ", n, "\n", withEnd: false),
        // Flattened onto one line, as an env var often is.
        ["private-key-one-line"] = n => Pem("", n, " "),
        // With a log prefix on every line after the first.
        ["private-key-logged"] = n => Pem("RSA ", n, "\n07:19:02 "),
        // Split across Python string literals that are concatenated.
        ["private-key-python"] = n => Pem("", n, "\\n\"\n    \""),
        // A kubeconfig client-key-data value: the whole PEM block in base64.
        ["private-key-base64"] = n => Convert.ToBase64String(Encoding.ASCII.GetBytes(Pem("RSA ", n, "\n"))),
        ["pgp-private-key"] = n => string.Join('\n',
        [
            "-----BEGIN PGP " + "PRIVATE KEY BLOCK-----",
            "Comment: https://gnupg.org",
            "",
            .. Lines(Chars($"pgp{n}", 300, B64)),
            "=" + Chars($"crc{n}", 4, B64),
            "-----END PGP " + "PRIVATE KEY BLOCK-----",
        ]),
        ["aws-access-key-id"] = n => "AK" + "IA" + Chars($"aws{n}", 16, Upper + Digits),
        ["aws-secret-access-key"] = n => Chars($"awss{n}", 40, B64),
        ["github-token"] = n => "gh" + "p_" + Chars($"gh{n}", 36),
        ["stripe-key"] = n => string.Join('_', "sk", "live", Chars($"stripe{n}", 24)),
        ["slack-token"] = n => string.Join('-', "xo" + "xb", Chars($"sa{n}", 12, Digits), Chars($"sb{n}", 12, Digits), Chars($"sc{n}", 24)),
        ["slack-refresh-token"] = n => string.Join('-', "xo" + "xe", "1", Chars($"sr{n}", 60)),
        // The path after https://hooks.slack.com/services/, which is the secret part of the URL.
        ["slack-webhook"] = n => $"T{Chars($"wa{n}", 8, Upper + Digits)}/B{Chars($"wb{n}", 10, Upper + Digits)}/{Chars($"wc{n}", 24)}",
        ["google-api-key"] = n => "AI" + "za" + Chars($"gk{n}", 35, B64Url),
        ["google-token"] = n => "ya" + "29." + Chars($"gt{n}", 60, B64Url),
    };

    // {{secret:value}} marks a literal secret; {{fake:name}} or {{fake:name:n}} builds one. Other {{…}} is input.
    [GeneratedRegex("""\{\{(secret|fake):([^}]+)\}\}""")]
    private static partial Regex Placeholder();

    public static string Fake(string spec)
    {
        var parts = spec.Split(':');
        if (!Builders.TryGetValue(parts[0], out var build)) throw new ArgumentException($"unknown fake: {spec}", nameof(spec));
        return build(parts.Length > 1 ? int.Parse(parts[1], System.Globalization.CultureInfo.InvariantCulture) : 1);
    }

    public static (string Text, List<string> Secrets) Expand(string text)
    {
        var secrets = new List<string>();
        var expanded = Placeholder().Replace(text, m =>
        {
            var value = m.Groups[1].Value == "secret" ? m.Groups[2].Value : Fake(m.Groups[2].Value);
            if (!secrets.Contains(value)) secrets.Add(value);
            return value;
        });
        return (expanded, secrets);
    }

    public static List<string> Leaks(string text, IEnumerable<string> secrets) => [.. secrets.Where(secret => text.Contains(secret, StringComparison.Ordinal))];

    public static List<string> Undeclared(IEnumerable<Change> changes, ICollection<string> secrets) =>
        [.. changes.Select(change => change.Value).Distinct().Where(value => !secrets.Contains(value))];

    // Seeded (FNV-1a into mulberry32), so a fixture builds the same values on every run. JavaScript's
    // Math.imul, | 0 and >>> wrap at 32 bits, as unchecked uint arithmetic does.
    private static string Chars(string seed, int length, string alphabet = Alnum)
    {
        unchecked
        {
            var state = 2166136261;
            foreach (var c in seed) state = (state ^ c) * 16777619;
            var s = new StringBuilder(length);
            while (s.Length < length)
            {
                state += 0x6d2b79f5;
                var t = (state ^ (state >> 15)) * (1 | state);
                t ^= t + ((t ^ (t >> 7)) * (61 | t));
                s.Append(alphabet[(int)((t ^ (t >> 14)) % (uint)alphabet.Length)]);
            }
            return s.ToString();
        }
    }

    private static string Base64Url(string json) => Convert.ToBase64String(Encoding.ASCII.GetBytes(json)).Replace('+', '-').Replace('/', '_').TrimEnd('=');

    private static string Jwt(string header, int n, string signature)
    {
        var claims = $$"""{"iss":"https://auth.example.com","sub":"usr_0{{33 + n}}","aud":"orders-api","scope":"orders:read","iat":1790234340,"exp":1790237940}""";
        return $"{Base64Url(header)}.{Base64Url(claims)}.{signature}";
    }

    private static string Pem(string type, int n, string newline, bool withEnd = true)
    {
        string Armor(string edge) => $"-----{edge} {type}PRIVATE KEY-----";
        return string.Join(newline, [Armor("BEGIN"), .. Lines(Chars($"pem{type}{n}", 300, B64)), .. withEnd ? [Armor("END")] : Array.Empty<string>()]);
    }

    private static IEnumerable<string> Lines(string body) => body.Chunk(64).Select(chunk => new string(chunk));
}
