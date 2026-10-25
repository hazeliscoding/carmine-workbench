using System.Text.RegularExpressions;

namespace Carmine.Core.Sanitize.Rules.UrlParams;

public static partial class UrlParamsRule
{
    public static Rule Rule { get; } = new("url-params", RuleBy.Context, Find);

    // access_token, id_token, refresh_token, token, code, client_secret, api_key, apikey, password, pass, pwd,
    // secret, auth, sig, signature, x-amz-signature, x-amz-security-token and x-goog-signature, in any case.
    private const string Names =
        "[Aa][Cc][Cc][Ee][Ss][Ss]_[Tt][Oo][Kk][Ee][Nn]|[Ii][Dd]_[Tt][Oo][Kk][Ee][Nn]|[Rr][Ee][Ff][Rr][Ee][Ss][Hh]_[Tt][Oo][Kk][Ee][Nn]"
        + "|[Tt][Oo][Kk][Ee][Nn]|[Cc][Oo][Dd][Ee]|[Cc][Ll][Ii][Ee][Nn][Tt]_[Ss][Ee][Cc][Rr][Ee][Tt]|[Aa][Pp][Ii]_[Kk][Ee][Yy]"
        + "|[Aa][Pp][Ii][Kk][Ee][Yy]|[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Pp][Aa][Ss][Ss]|[Pp][Ww][Dd]|[Ss][Ee][Cc][Rr][Ee][Tt]"
        + "|[Aa][Uu][Tt][Hh]|[Ss][Ii][Gg]|[Ss][Ii][Gg][Nn][Aa][Tt][Uu][Rr][Ee]|[Xx]-[Aa][Mm][Zz]-[Ss][Ii][Gg][Nn][Aa][Tt][Uu][Rr][Ee]"
        + "|[Xx]-[Aa][Mm][Zz]-[Ss][Ee][Cc][Uu][Rr][Ii][Tt][Yy]-[Tt][Oo][Kk][Ee][Nn]|[Xx]-[Gg][Oo][Oo][Gg]-[Ss][Ii][Gg][Nn][Aa][Tt][Uu][Rr][Ee]";

    // Names that also carry ordinary values (code=SKU-12345, auth=required), so their value must look random.
    private static readonly HashSet<string> Generic = ["code", "auth", "sig", "signature"];

    // A parameter at the start of a query, fragment or form body, or after a separator. Requiring one of these
    // before the name keeps logfmt such as "status code=500" out. JavaScript's m flag starts a line after
    // \r, \u2028 and \u2029 too.
    [GeneratedRegex($$"""(?<=^|[\n\r\u2028\u2029?&#;'"])({{Names}})=([^{{Shared.Space}}&#;'"<>)\]]+)""")]
    private static partial Regex Param();

    // user:password@host after ://. The user name stays. Anchoring on :// rather than the scheme keeps the
    // scan linear on long dotted text.
    [GeneratedRegex($$"""://[^{{Shared.Space}}/:@'"]*:([^{{Shared.Space}}/@'"]+)@""")]
    private static partial Regex UserInfo();

    private static List<Finding> Find(string text) =>
    [
        .. from Match m in Param().Matches(text)
           let name = m.Groups[1].Value
           where !Generic.Contains(name.ToLowerInvariant()) || LooksRandom(m.Groups[2].Value)
           let kind = name.ToLowerInvariant()
           select new Finding(m.Groups[2].Index, m.Groups[2].Index + m.Groups[2].Length,
               (kind.StartsWith("x-", StringComparison.Ordinal) ? kind[2..] : kind).Replace('_', '-'), $"{name} parameter"),
        .. from Match m in UserInfo().Matches(text)
           select new Finding(m.Groups[1].Index, m.Groups[1].Index + m.Groups[1].Length, "password", "password in URL"),
    ];

    // Authorization codes and signatures are long, or mix digits with upper- and lowercase letters.
    private static bool LooksRandom(string value) =>
        value.Length >= 16
        || (value.Length >= 10 && value.Any(char.IsAsciiDigit) && value.Any(char.IsAsciiLetterLower) && value.Any(char.IsAsciiLetterUpper));
}
