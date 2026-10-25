using System.Text.RegularExpressions;

namespace Carmine.Core.Sanitize.Rules.AuthorizationHeaders;

public static partial class AuthorizationHeadersRule
{
    public static Rule Rule { get; } = new("authorization-headers", RuleBy.Context, Find);

    // Bearer and the like, whose credential needs no further proof once the scheme is named.
    private static readonly HashSet<string> Schemes =
        ["bearer", "basic", "token", "bot", "ssws", "apikey", "api-key", "key", "negotiate", "ntlm", "hmac", "dpop", "jwt", "sharedkey", "mac"];

    private static readonly HashSet<string> SecretParams = ["response", "signature", "oauth_signature", "oauth_token", "token"];

    // A header name, optionally quoted as a JSON or Python key (escaped when the JSON sits inside a log
    // string, or a Python b'' string), then a separator and an optional opening quote or Go map bracket. It
    // matches only up to the value, so the next header on the same line is still found. The separator is a
    // colon, or = and => as in PowerShell and Ruby hashes; := is an assignment in code (token := …). Right
    // after :// is a URL's user name (https://x-access-token:…@host), which url-params reads.
    [GeneratedRegex($$"""{{Shared.Start}}(?<!://)(?:[bBrRuUfF]{0,2}(\\?["']))?([A-Za-z][A-Za-z0-9_-]*)(?(1)\1)[ \t]*(?::(?!=)|=>|=(?![=>]))[ \t]*\[?(?:[bBrRuUfF]{0,2}\\?["'`])?""")]
    private static partial Regex Header();

    // A shell or template reference is taken whole so the engine can skip it; anything else runs up to
    // whitespace, a quote, a delimiter, a bracket, an escape, an HTML tag or a label. A value that opens an
    // object or array, or starts with <, isn't a credential.
    [GeneratedRegex($$"""\G(?:\$\([^)]*\)|\$\{[^}]*\}|\{\{[^}]*\}\}|(?!<)(?:(?!{{Shared.ValueStop}})[^{{Shared.Space}}'"`,;{}()[\]\\])+)""")]
    private static partial Regex CredentialValue();

    [GeneratedRegex($$"""\G[A-Za-z][A-Za-z0-9_-]*[ \t]+(?=[^{{Shared.Space}}])""")]
    private static partial Regex Scheme();

    // Names that hold a credential. Most other *-key headers (X-Cache-Key, Sort-Key, X-Stripe-Publishable-Key)
    // don't, and their values then spread through the paste as copies.
    [GeneratedRegex("""(?:^|-)(?:api-?key|access-key|auth-key|functions-key|subscription-key|token|secret)\z""")]
    private static partial Regex KeyHeader();

    [GeneratedRegex("""^(?:idempotency-key|sec-websocket-key)\z|(?:page|next|continuation)-token\z""")]
    private static partial Regex NotKeyHeader();

    // Schemes whose credentials are name=value parameters. Only these parameters carry the secret.
    [GeneratedRegex("""^(?:digest|oauth|aws4-[A-Za-z0-9_-]+)\z""")]
    private static partial Regex ParamScheme();

    [GeneratedRegex($$"""(?<![A-Za-z0-9_-])([A-Za-z0-9_-]+)=(?:\\?"((?:(?!\\?")[^\r\n])*)\\?"|([^{{Shared.Space}},"'\\]+))""")]
    private static partial Regex Param();

    // Header APIs that don't write Name: value, such as setRequestHeader("Authorization", "Bearer …") or
    // name/value pairs, still put the scheme right before the credential.
    [GeneratedRegex($$"""{{Shared.StartIgnoreCase}}([Bb][Ee][Aa][Rr][Ee][Rr]|[Bb][Aa][Ss][Ii][Cc])[ \t]+""")]
    private static partial Regex SchemeAnywhere();

    // user:password flags of curl and HTTPie (-a, --auth). Short flags take the value attached or after
    // spaces; long ones after = or spaces.
    [GeneratedRegex($$"""(?<![^{{Shared.Space}}])(?:(-u|-U|-a)[ \t]*|(--user|--proxy-user|--auth)(?:=|[ \t]+))(["']?)""")]
    private static partial Regex CurlUser();

    // With -A bearer, HTTPie's -a takes a token instead of user:password.
    [GeneratedRegex("""(?:-[Aa]|--[Aa][Uu][Tt][Hh]-[Tt][Yy][Pp][Ee])[ \t=]+[Bb][Ee][Aa][Rr][Ee][Rr](?![A-Za-z0-9_])""")]
    private static partial Regex HttpieBearer();

    // mysql takes its password attached to -p. Other tools use -p for a port, so only mysql and mariadb lines,
    // and never a port mapping such as docker's -p3306:3306.
    [GeneratedRegex($$"""(?<![^{{Shared.Space}}])-p(["']?)([^{{Shared.Space}}'"]+)\1""")]
    private static partial Regex MysqlPassword();

    [GeneratedRegex("""(?<![A-Za-z0-9_])(?:mysql|mariadb)[A-Za-z0-9_]*(?![A-Za-z0-9_])""")]
    private static partial Regex Mysql();

    [GeneratedRegex("""^[0-9]+(?::[0-9]+)+\z""")]
    private static partial Regex PortMapping();

    [GeneratedRegex($$"""(?<![^{{Shared.Space}}])--oauth2-bearer(?:=|[ \t]+)["']?""")]
    private static partial Regex CurlBearer();

    // A colon followed by // is a URL scheme (redis-cli -u redis://host), not user:password.
    [GeneratedRegex($$"""\G[^":{{Shared.Space}}]*:(?!//)([^"\r\n]+)""")]
    private static partial Regex DoubleQuotedUserPass();

    [GeneratedRegex($$"""\G[^':{{Shared.Space}}]*:(?!//)([^'\r\n]+)""")]
    private static partial Regex SingleQuotedUserPass();

    [GeneratedRegex($$"""\G[^{{Shared.Space}}:'"]*:(?!//)([^{{Shared.Space}}]+)""")]
    private static partial Regex UnquotedUserPass();

    [GeneratedRegex("""^[0-9]+:[0-9]+\z""")]
    private static partial Regex UidGid();

    [GeneratedRegex("""\G[Tt][Oo][Kk][Ee][Nn]=""")]
    private static partial Regex TokenParam();

    [GeneratedRegex("""^[A-Za-z0-9+/]+=*\z""")]
    private static partial Regex Base64Shape();

    private static List<Finding> Find(string text) =>
        [.. Headers(text), .. SchemesAnywhere(text), .. CurlUsers(text), .. CurlBearers(text), .. MysqlPasswords(text)];

    private static IEnumerable<Finding> MysqlPasswords(string text) =>
        from Match m in MysqlPassword().Matches(text)
        where Mysql().IsMatch(LineBefore(text, m.Index)) && !PortMapping().IsMatch(m.Groups[2].Value)
        select new Finding(m.Groups[2].Index, m.Groups[2].Index + m.Groups[2].Length, "password", "mysql -p password");

    // Gated, so prose such as "Bearer tokens expire" or "Basic auth is disabled" stays.
    private static IEnumerable<Finding> SchemesAnywhere(string text) =>
        from Match m in SchemeAnywhere().Matches(text)
        let scheme = m.Groups[1].Value.ToLowerInvariant()
        from finding in Credential(text, m.Index + m.Length, scheme, $"{m.Groups[1].Value} credential",
            scheme == "basic" ? IsBasicCredential : Shared.LooksLikeCredential)
        select finding;

    // Base64 of user:password.
    private static bool IsBasicCredential(string value) =>
        Base64Shape().IsMatch(value) && Shared.Atob(value) is { } bytes && bytes.AsSpan().Contains((byte)':');

    private static IEnumerable<Finding> Headers(string text)
    {
        foreach (Match m in Header().Matches(text))
        {
            var name = m.Groups[2].Value;
            var lower = name.ToLowerInvariant();
            var at = m.Index + m.Length;
            var reason = $"{name} header";
            if (lower is "authorization" or "proxy-authorization")
            {
                foreach (var finding in Authorization(text, at, reason)) yield return finding;
            }
            else if (KeyHeader().IsMatch(lower) && !NotKeyHeader().IsMatch(lower))
            {
                foreach (var finding in Credential(text, at, Shared.KindFromName(name), reason, Shared.LooksLikeCredential)) yield return finding;
            }
        }
    }

    private static List<Finding> Authorization(string text, int at, string reason)
    {
        var scheme = Shared.MatchAt(Scheme(), text, at);
        var name = scheme?.TrimEnd(' ', '\t').ToLowerInvariant() ?? "";
        // Authorization = new AuthenticationHeaderValue(…) or = await getHeader() is code, not a scheme.
        if (scheme is null || Shared.LooksLikeCode(name)) return Credential(text, at, "authorization", reason, Shared.LooksLikeCredential);
        var rest = at + scheme.Length;
        if (ParamScheme().IsMatch(name)) return Params(text, rest, name.StartsWith("aws4-", StringComparison.Ordinal) ? "aws-signature" : name, reason);
        if (name == "token" && TokenParam().IsMatch(text, rest)) return Params(text, rest, name, reason);
        return Credential(text, rest, name, reason, value => Schemes.Contains(name) || Shared.LooksLikeCredential(value));
    }

    private static List<Finding> Params(string text, int from, string kind, string reason)
    {
        var found = new List<Finding>();
        // The slice keeps the parameters' lookbehind from seeing the scheme, as in JavaScript.
        foreach (Match p in Param().Matches(text[from..ParamsEnd(text, from)]))
        {
            var value = p.Groups[2].Success ? p.Groups[2] : p.Groups[3];
            if (SecretParams.Contains(Shared.AsciiLower(p.Groups[1].Value)) && value.Length > 0)
            {
                found.Add(new Finding(from + value.Index, from + value.Index + value.Length, kind, reason));
            }
        }
        return found;
    }

    // The end of the header's line: a line break, an escaped \r or \n, or the end of the text.
    private static int ParamsEnd(string text, int from)
    {
        for (var i = from; i < text.Length; i++)
        {
            if (text[i] is '\r' or '\n' || (text[i] == '\\' && i + 1 < text.Length && text[i + 1] is 'r' or 'n')) return i;
        }
        return text.Length;
    }

    private static IEnumerable<Finding> CurlUsers(string text)
    {
        foreach (Match m in CurlUser().Matches(text))
        {
            var flag = m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value;
            var at = m.Index + m.Length;
            var httpie = flag is "-a" or "--auth";
            if (httpie && HttpieBearer().IsMatch(LineAround(text, m.Index)))
            {
                foreach (var finding in Credential(text, at, "bearer", $"{flag} bearer token")) yield return finding;
                continue;
            }
            var userPass = m.Groups[3].Value switch
            {
                "\"" => DoubleQuotedUserPass(),
                "'" => SingleQuotedUserPass(),
                _ => UnquotedUserPass(),
            };
            var u = userPass.Match(text, at);
            // docker and ps take -u uid:gid, and rsync's -a (archive) is followed by host:/path.
            if (!u.Success || UidGid().IsMatch(u.Value) || (httpie && u.Groups[1].Value.StartsWith('/'))) continue;
            yield return new Finding(u.Groups[1].Index, u.Groups[1].Index + u.Groups[1].Length, "password", $"{flag} password");
        }
    }

    // JavaScript's lastIndexOf('\n', -1) still looks at index 0, but the slice is empty either way.
    private static string LineBefore(string text, int at) => at == 0 ? "" : text[(text.LastIndexOf('\n', at - 1) + 1)..at];

    private static string LineAround(string text, int at)
    {
        var end = text.IndexOf('\n', at);
        return LineBefore(text, at) + text[at..(end == -1 ? text.Length : end)];
    }

    private static IEnumerable<Finding> CurlBearers(string text) =>
        from Match m in CurlBearer().Matches(text)
        from finding in Credential(text, m.Index + m.Length, "bearer", "curl --oauth2-bearer")
        select finding;

    private static List<Finding> Credential(string text, int at, string kind, string reason, Func<string, bool>? accept = null)
    {
        var value = Shared.MatchAt(CredentialValue(), text, at);
        var end = at + (value?.Length ?? 0);
        if (string.IsNullOrEmpty(value) || (end < text.Length && text[end] == '(' && Shared.IsCallee(value)) || !(accept?.Invoke(value) ?? true)) return [];
        return [new Finding(at, end, kind, reason)];
    }
}
