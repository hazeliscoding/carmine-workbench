namespace Carmine.Core.Sanitize;

/// <summary>
/// A JWT's header and claims, with the values JavaScript's <c>JSON.parse</c> gives: <see langword="null"/>,
/// <see cref="bool"/>, <see cref="double"/> for every number, <see cref="string"/>, <c>List&lt;object?&gt;</c>
/// and <c>OrderedDictionary&lt;string, object?&gt;</c>.
/// </summary>
/// <remarks>
/// Keys keep JavaScript's order: array-index keys (0 to 4294967294, no leading zeros) first, ascending, then
/// the rest as written. A duplicate key keeps its first position and its last value.
/// </remarks>
/// <param name="Claims">Empty for an encrypted token, or when the payload isn't a JSON object.</param>
public record DecodedJwt(IReadOnlyDictionary<string, object?> Header, IReadOnlyDictionary<string, object?> Claims);

/// <summary>A span a rule wants removed.</summary>
/// <param name="Start">UTF-16 index into the text the rule was given.</param>
/// <param name="End">Exclusive. An empty span is ignored.</param>
/// <param name="Kind">The label's prefix, such as <c>jwt</c> or <c>cookie:sid</c>. A value found more than once
/// keeps the kind of its first finding everywhere.</param>
/// <param name="Reason">Why the value was removed, as the findings list shows it.</param>
/// <param name="Jwt">Set only for a JWT. The engine lists it in <see cref="SanitizeResult.Jwts"/> unless the
/// finding merges into another format finding, such as a PEM block around it.</param>
public sealed record Finding(int Start, int End, string Kind, string Reason, DecodedJwt? Jwt = null);

/// <summary>What a rule recognises. When findings overlap, format findings win over context findings.</summary>
public enum RuleBy
{
    /// <summary>The value itself, such as a JWT, a PEM block or a vendor's key prefix.</summary>
    Format,

    /// <summary>Where a value sits, such as an <c>Authorization</c> header, a <c>password</c> key or a flag.</summary>
    Context,
}

/// <param name="Name">Shown as <see cref="Change.Rule"/>. A rule in <see cref="Rules.RuleList.All"/> is named
/// after its folder in kebab case, such as <c>known-secret-formats</c>, because the fixture tests find its cases
/// by that name.</param>
/// <param name="Find">Must be pure. Findings can overlap and come in any order, but on the same span the first
/// one returned wins.</param>
public sealed record Rule(string Name, RuleBy By, Func<string, IReadOnlyList<Finding>> Find);

/// <summary>One replaced span of the input.</summary>
/// <param name="Label">Such as <c>jwt#1</c>, without the angle brackets the output puts around it.</param>
/// <param name="Rule">The rule that found the value. For a copy, the rule of the value's first finding.</param>
/// <param name="Reason">For a copy, <c>same value as jwt#1</c>.</param>
/// <param name="Line">1-based line of <paramref name="Start"/>. Only <c>\n</c> ends a line.</param>
/// <param name="Start">UTF-16 index into the input.</param>
/// <param name="End">Exclusive. The span can be wider than <paramref name="Value"/> when an overlapping finding
/// was merged in.</param>
/// <param name="Value">The secret itself. Keep it in memory: never log it or write it anywhere.</param>
public sealed record Change(string Label, string Kind, string Rule, string Reason, int Line, int Start, int End, string Value);

/// <param name="Label">As in <see cref="Change.Label"/>.</param>
public sealed record LabeledJwt(string Label, IReadOnlyDictionary<string, object?> Header, IReadOnlyDictionary<string, object?> Claims)
    : DecodedJwt(Header, Claims);

/// <param name="Changes">In input order. They hold the removed secrets, as <see cref="Change.Value"/> says.</param>
/// <param name="Jwts">One per JWT label, in label order.</param>
public sealed record SanitizeResult(string Output, IReadOnlyList<Change> Changes, IReadOnlyList<LabeledJwt> Jwts);
