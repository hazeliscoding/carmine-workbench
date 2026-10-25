using Carmine.Core.Sanitize.Rules.AuthorizationHeaders;
using Carmine.Core.Sanitize.Rules.Cookies;
using Carmine.Core.Sanitize.Rules.Jwt;
using Carmine.Core.Sanitize.Rules.KnownSecretFormats;
using Carmine.Core.Sanitize.Rules.PrivateKeys;
using Carmine.Core.Sanitize.Rules.SensitiveKeys;
using Carmine.Core.Sanitize.Rules.UrlParams;

namespace Carmine.Core.Sanitize.Rules;

public static class RuleList
{
    /// <summary>The rules <see cref="Engine.Sanitize"/> runs by default.</summary>
    /// <remarks>
    /// Order breaks ties between findings of the same <see cref="RuleBy"/> on the same span: the earlier rule
    /// wins, so the more specific rule comes first.
    /// </remarks>
    public static IReadOnlyList<Rule> All { get; } =
    [
        JwtRule.Rule,
        PrivateKeysRule.Rule,
        KnownSecretFormatsRule.Rule,
        AuthorizationHeadersRule.Rule,
        CookiesRule.Rule,
        UrlParamsRule.Rule,
        SensitiveKeysRule.Rule,
    ];
}
