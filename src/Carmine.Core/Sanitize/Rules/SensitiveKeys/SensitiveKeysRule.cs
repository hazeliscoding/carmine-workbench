using System.Text.RegularExpressions;

namespace Carmine.Core.Sanitize.Rules.SensitiveKeys;

public static partial class SensitiveKeysRule
{
    public static Rule Rule { get; } = new("sensitive-keys", RuleBy.Context, Find);

    // A key, optionally quoted (escaped when the JSON sits inside a log string, or a Python b'' string) or
    // written as a --flag, then an assignment: = : := or =>. An = followed by another = is a comparison, and a
    // name right after ${ is a shell default such as ${TOKEN:-unset}. As with Start, a key may follow an
    // escape such as \t but not a lone backslash. Right after :// is a URL's user name (https://token:…@host),
    // which url-params reads.
    [GeneratedRegex("""(?:(?<![A-Za-z0-9_.$\\%-])|(?<=\\[nrt]))(?<!\$\{|://)(?:--)?(?:[bBrRuUfF]{0,2}(\\?["']))?([A-Za-z_][A-Za-z0-9_.-]*)(?(1)\1)[ \t]*(:=|=>|:|=(?!=))[ \t]*""")]
    private static partial Regex Key();

    // Python's b'', f'' and similar string prefixes.
    [GeneratedRegex("""\G[bBrRuUfF]{1,2}(?=\\?["'`])""")]
    private static partial Regex StringPrefix();

    // The closing quote may be missing when a log cuts the JSON off mid-value; the value then runs to the line
    // end. Backticks are JavaScript template strings.
    [GeneratedRegex("""\G(["'`])((?:\\[^\n\r\u2028\u2029]|(?!\1)[^\\\r\n])*)(?:\1|(?=[\r\n]|\z))""")]
    private static partial Regex Quoted();

    // Quoted with escaped quotes, as JSON inside a log string is.
    [GeneratedRegex("""\G\\(["'])((?:(?!\\\1)[^\r\n])*)(?:\\\1|(?=[\r\n]|\z))""")]
    private static partial Regex EscapedQuoted();

    // A shell or template reference is taken whole so the engine can skip it. A value starting with < is a tag
    // or a label.
    [GeneratedRegex($$"""\G(?:\$\([^)]*\)|\$\{[^}]*\}|\{\{[^}]*\}\}|(?!<)(?:(?!{{Shared.ValueStop}})[^{{Shared.Space}},;&'"(){}[\]\\])+)""")]
    private static partial Regex Bare();

    // Matched against the key lowercased with separators removed, so api_key, apiKey and API-KEY all match.
    // Only the plural "credentials": AWS's Credential= is a key ID and a scope.
    [GeneratedRegex("""(?:password|passwd|passphrase|pass|secret|token|apikey|privatekey|secretkey|secretaccesskey|accountkey|signingkey|encryptionkey|masterkey|sessionid|credentials)\z|^pwd\z""")]
    private static partial Regex Sensitive();

    // Pagination cursors and token_type end like secrets but grant nothing, and bypass or compass only end in "pass".
    [GeneratedRegex("""(?:tokentype|(?:next|page|continuation|pagination)token|bypass|compass)\z""")]
    private static partial Regex NotSensitive();

    // A flag value such as docker's --secret id=npmrc,src=… is a spec that names the secret, not the secret.
    // Only these keys, because base64 with one = of padding looks the same.
    [GeneratedRegex("""^(?:id|src|source|type|env|target|dst|destination)=""")]
    private static partial Regex Spec();

    // A command-line flag with its value after a space, as in docker login --password …
    [GeneratedRegex($$"""(?<![^{{Shared.Space}}])--([A-Za-z][A-Za-z0-9_-]*)[ \t]+(?=[^{{Shared.Space}}-])""")]
    private static partial Regex Flag();

    // A YAML block scalar indicator (| or >, with optional chomping), the value on the lines below.
    [GeneratedRegex("""\G[|>][+-]?[ \t]*(?=\r?\n)""")]
    private static partial Regex Block();

    [GeneratedRegex("""^-?[0-9]+(?:\.[0-9]+)?\z""")]
    private static partial Regex JsonNumber();

    private static List<Finding> Find(string text) =>
    [
        .. Key().Matches(text).Select(m => (Key: m.Groups[2].Value, Separator: m.Groups[3].Value, At: m.Index + m.Length))
            .Concat(Flag().Matches(text).Select(m => (Key: m.Groups[1].Value, Separator: " ", At: m.Index + m.Length)))
            .SelectMany(k => ValueOf(text, k.Key, k.Separator, k.At)),
    ];

    private static List<Finding> ValueOf(string text, string key, string separator, int from)
    {
        var normalized = new string([.. key.ToLowerInvariant().Where(char.IsAsciiLetterOrDigit)]);
        if (!Sensitive().IsMatch(normalized) || NotSensitive().IsMatch(normalized)) return [];
        var prefix = StringPrefix().Match(text, from);
        var at = from + (prefix.Success ? prefix.Length : 0);
        var kind = Shared.KindFromName(key.Split('.')[^1]);
        var reason = $"{key} value";

        if (separator == ":" && Block().IsMatch(text, at)) return BlockValue(text, at, kind, reason);
        var quoted = EscapedQuoted().Match(text, at);
        if (!quoted.Success) quoted = Quoted().Match(text, at);
        if (quoted.Success)
        {
            var value = quoted.Groups[2];
            return value.Length > 0 && !(separator == " " && Spec().IsMatch(value.Value))
                ? [new Finding(value.Index, value.Index + value.Length, kind, reason)]
                : [];
        }
        var bare = Shared.MatchAt(Bare(), text, at);
        if (string.IsNullOrEmpty(bare) || (separator == " " && Spec().IsMatch(bare))) return [];
        var end = at + bare.Length;
        // A JSON number is a flag or a count. Code such as os.environ["X"] or os.Getenv("X") reads the
        // secret from somewhere else.
        var call = end < text.Length && text[end] is '(' or '[' && Shared.IsCallee(bare);
        if ((separator == ":" && JsonNumber().IsMatch(bare)) || call || Shared.LooksLikeCode(bare)) return [];
        return [new Finding(at, end, kind, reason)];
    }

    // The lines after the key that are indented deeper than it, from the first content to the last.
    private static List<Finding> BlockValue(string text, int from, string kind, string reason)
    {
        var keyIndent = IndentOf(text, text.LastIndexOf('\n', from - 1) + 1, from);
        var start = -1;
        var end = -1;
        for (var pos = text.IndexOf('\n', from) + 1; pos > 0 && pos < text.Length;)
        {
            var next = text.IndexOf('\n', pos);
            var lineEnd = next == -1 ? text.Length : next;
            if (lineEnd > pos && text[lineEnd - 1] == '\r') lineEnd--;
            // JavaScript's trim(), which drops a different set of characters than .NET's Trim().
            if (text.AsSpan(pos, lineEnd - pos).ContainsAnyExcept(Shared.Spaces))
            {
                var indent = IndentOf(text, pos, lineEnd);
                if (indent <= keyIndent) break;
                if (start == -1) start = pos + indent;
                end = lineEnd;
            }
            pos = next + 1;
        }
        return start == -1 ? [] : [new Finding(start, end, kind, reason)];
    }

    private static int IndentOf(string text, int from, int to)
    {
        var i = from;
        while (i < to && text[i] is ' ' or '\t') i++;
        return i - from;
    }
}
