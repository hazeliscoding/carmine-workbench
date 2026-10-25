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
    // Order breaks ties between context findings on the same span: the more specific name wins.
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
