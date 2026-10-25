using System.Text.RegularExpressions;

namespace Carmine.Core.Sanitize.Rules.KnownSecretFormats;

public static partial class KnownSecretFormatsRule
{
    public static Rule Rule { get; } = new("known-secret-formats", RuleBy.Format, Find);

    // Vendor prefixes and lengths, bounded so a match can't start or end inside a longer word.
    private const string End = """(?![A-Za-z0-9_-])""";

    // Stripe pk_ keys are publishable and left alone.
    private static readonly (string Kind, string Reason, Regex Pattern)[] Formats =
    [
        ("aws-access-key-id", "AWS access key ID", AwsAccessKeyId()),
        ("github-token", "GitHub token", GitHubToken()),
        ("stripe-key", "Stripe secret key", StripeKey()),
        ("slack-token", "Slack token", SlackToken()),
        ("google-api-key", "Google API key", GoogleApiKey()),
        ("google-token", "Google OAuth token", GoogleToken()),
        ("slack-webhook", "Slack webhook", SlackWebhook()),
    ];

    // AWS key IDs are uppercase letters and digits, so anything else bounds them, as in AKIA…_backup.csv.
    [GeneratedRegex("""(?:(?<![A-Z0-9\\%])|(?<=%[0-9A-Fa-f]{2}))(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])""")]
    private static partial Regex AwsAccessKeyId();

    [GeneratedRegex($$"""{{Shared.Start}}(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{80,255}){{End}}""")]
    private static partial Regex GitHubToken();

    [GeneratedRegex($$"""{{Shared.Start}}(?:(?:(?:sk|rk)_(?:live|test)_|whsec_)[A-Za-z0-9]{16,255}){{End}}""")]
    private static partial Regex StripeKey();

    [GeneratedRegex($$"""{{Shared.Start}}(?:(?:xox[abposre]|xapp)-[A-Za-z0-9-]{10,255}){{End}}""")]
    private static partial Regex SlackToken();

    [GeneratedRegex($$"""{{Shared.Start}}(?:AIza[A-Za-z0-9_-]{35}){{End}}""")]
    private static partial Regex GoogleApiKey();

    [GeneratedRegex($$"""{{Shared.Start}}(?:ya29\.[A-Za-z0-9_-]{20,}){{End}}""")]
    private static partial Regex GoogleToken();

    // The path after the host is the secret; the host stays so a reader knows what it was.
    [GeneratedRegex("""(?<=hooks\.slack\.com/services/)T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+""")]
    private static partial Regex SlackWebhook();

    private static List<Finding> Find(string text) =>
    [
        .. from format in Formats
           from Match m in format.Pattern.Matches(text)
           select new Finding(m.Index, m.Index + m.Length, format.Kind, format.Reason),
    ];
}
