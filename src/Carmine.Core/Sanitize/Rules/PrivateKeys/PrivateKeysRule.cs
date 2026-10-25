using System.Text.RegularExpressions;

namespace Carmine.Core.Sanitize.Rules.PrivateKeys;

public static partial class PrivateKeysRule
{
    public static Rule Rule { get; } = new("private-keys", RuleBy.Format, Find);

    [GeneratedRegex("""-----BEGIN ((?:[A-Z0-9]+ )*)PRIVATE KEY( BLOCK)?-----""")]
    private static partial Regex Begin();

    // The key itself is a long base64 run. Lines can be flattened, prefixed by a log or split into string
    // literals, so the body isn't checked line by line; docs that name both armor lines have no such run.
    [GeneratedRegex("""[A-Za-z0-9+/]{40,}""")]
    private static partial Regex KeyMaterial();

    // One more whole base64 line, for a block pasted without its END line.
    [GeneratedRegex("""\G(?:\r?\n|(?:\\r)?\\n)[ \t]*[A-Za-z0-9+/=]{16,}[ \t]*(?=\r?\n|(?:\\r)?\\n|["']|\z)""")]
    private static partial Regex NextLine();

    // A PEM block that was itself base64-encoded, as kubeconfig client-key-data is: "-----BEGIN " encodes to
    // LS0tLS1CRUdJTi. Certificates encode the same way, so the decoded start decides.
    [GeneratedRegex($$"""{{Shared.Start}}LS0tLS1CRUdJTi[A-Za-z0-9+/]*={0,2}""")]
    private static partial Regex Base64Pem();

    private static List<Finding> Find(string text)
    {
        var begins = Begin().Matches(text);
        return [.. begins.SelectMany((m, i) => Block(text, m, i + 1 < begins.Count ? begins[i + 1].Index : text.Length)), .. Base64Blocks(text)];
    }

    // Looks for END only up to the next BEGIN, so a paste full of armor lines stays linear.
    private static List<Finding> Block(string text, Match begin, int limit)
    {
        var start = begin.Index;
        var bodyStart = start + begin.Length;
        var endArmor = $"-----END {begin.Groups[1].Value}PRIVATE KEY{begin.Groups[2].Value}-----";
        var reason = $"{begin.Groups[1].Value}private key";
        var endAt = text.IndexOf(endArmor, bodyStart, limit - bodyStart, StringComparison.Ordinal);
        if (endAt != -1 && KeyMaterial().IsMatch(text.AsSpan(bodyStart, endAt - bodyStart)))
        {
            return [new Finding(start, endAt + endArmor.Length, "private-key", reason)];
        }
        var end = bodyStart;
        for (var line = NextLine().Match(text, end); line.Success; line = NextLine().Match(text, end)) end = line.Index + line.Length;
        // The armor line alone, as in docs that mention it, holds no key.
        return end > bodyStart ? [new Finding(start, end, "private-key", reason)] : [];
    }

    private static IEnumerable<Finding> Base64Blocks(string text) =>
        from Match m in Base64Pem().Matches(text)
        let head = Shared.Atob(m.Value[..Math.Min(80, m.Length)])
        where head is not null && head.AsSpan().IndexOf("PRIVATE KEY"u8) >= 0
        select new Finding(m.Index, m.Index + m.Length, "private-key", "base64 private key");
}
