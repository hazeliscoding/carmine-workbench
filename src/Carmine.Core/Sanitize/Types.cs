namespace Carmine.Core.Sanitize;

// The values are what JavaScript's JSON.parse gives: null, bool, double, string, List<object?> and
// OrderedDictionary<string, object?>, whose keys keep JavaScript's order (integer keys first, ascending).
public record DecodedJwt(IReadOnlyDictionary<string, object?> Header, IReadOnlyDictionary<string, object?> Claims);

public sealed record Finding(int Start, int End, string Kind, string Reason, DecodedJwt? Jwt = null);

// Format rules recognise the value itself; context rules recognise where a value sits.
public enum RuleBy
{
    Format,
    Context,
}

public sealed record Rule(string Name, RuleBy By, Func<string, IReadOnlyList<Finding>> Find);

// Start and End are the replaced span. It can be wider than Value when an overlapping finding was merged in.
public sealed record Change(string Label, string Kind, string Rule, string Reason, int Line, int Start, int End, string Value);

public sealed record LabeledJwt(string Label, IReadOnlyDictionary<string, object?> Header, IReadOnlyDictionary<string, object?> Claims)
    : DecodedJwt(Header, Claims);

public sealed record SanitizeResult(string Output, IReadOnlyList<Change> Changes, IReadOnlyList<LabeledJwt> Jwts);
