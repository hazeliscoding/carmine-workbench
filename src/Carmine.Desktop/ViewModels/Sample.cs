namespace Carmine.Desktop.ViewModels;

public sealed record Finding(string Label, string Kind, string Where, int Line, string Value);

public sealed record Field(string Key, string Value, bool IsNumber, string? Note = null, bool Alert = false);

public sealed record JwtExplain(string Label, string Alg, bool Expired, IReadOnlyList<Field> Header, IReadOnlyList<Field> Claims);

public sealed record Segment(string Text, bool Hit);

public enum DiffOp
{
    Same,
    Del,
    Add,
}

public sealed record SourceLine(int Number, IReadOnlyList<Segment> Parts)
{
    public string Text => string.Concat(Parts.Select(p => p.Text));
}

public sealed record DiffLine(DiffOp Op, int? A, int? B, IReadOnlyList<Segment> Parts)
{
    public bool IsDel => Op == DiffOp.Del;

    public bool IsAdd => Op == DiffOp.Add;

    public string Text => string.Concat(Parts.Select(p => p.Text));
}

public sealed record Sample(
    string Format,
    string Input,
    string Output,
    IReadOnlyList<Finding> Findings,
    JwtExplain Jwt,
    IReadOnlyList<SourceLine> MarkedInput,
    IReadOnlyList<DiffLine> Diff)
{
    // Canned sample for the static screen; M2 builds all of this from the engine's output.
    // Secret values are cut short with … so they are not real secrets and do not match secret scanners.
    public static Sample Canned { get; } = Build();

    private static Sample Build()
    {
        IReadOnlyList<Segment>[] marked =
        [
            [new("curl https://api.example.com/v1/orders \\", false)],
            [new("  -H 'Authorization: Bearer ", false), new("eyJhbGciOiJSUzI1NiIs…", true), new("' \\", false)],
            [new("  -H 'X-Api-Key: ", false), new("3f9a8c2e…", true), new("' \\", false)],
            [new("  -b 'sid=", false), new("9f3e1c7a…", true), new("; theme=dark'", false)],
        ];

        return new Sample(
            Format: "curl",
            Input: string.Join('\n',
                "curl https://api.example.com/v1/orders \\",
                "  -H 'Authorization: Bearer eyJhbGciOiJSUzI1NiIs…' \\",
                "  -H 'X-Api-Key: 3f9a8c2e…' \\",
                "  -b 'sid=9f3e1c7a…; theme=dark'"),
            Output: string.Join('\n',
                "curl https://api.example.com/v1/orders \\",
                "  -H 'Authorization: Bearer <jwt#1>' \\",
                "  -H 'X-Api-Key: <api-key#2>' \\",
                "  -b 'sid=<cookie:sid#3>; theme=dark'",
                "",
                "# jwt#1 · RS256 · signature removed",
                "#   sub  usr_034",
                "#   aud  orders-api",
                "#   exp  2026.09.24 08:19 (expired 12m ago)"),
            Findings:
            [
                new("jwt#1", "JWT", "Authorization header", 2, "eyJhbGciOiJSUzI1NiIs…"),
                new("api-key#2", "API key", "X-Api-Key header", 3, "3f9a8c2e…"),
                new("cookie:sid#3", "Cookie", "sid cookie", 4, "9f3e1c7a…"),
            ],
            Jwt: new JwtExplain(
                Label: "jwt#1",
                Alg: "RS256",
                Expired: true,
                Header:
                [
                    new("alg", "RS256", false),
                    new("typ", "JWT", false),
                    new("kid", "orders-2026-09", false),
                ],
                Claims:
                [
                    new("iss", "https://auth.example.com", false, "Issuer"),
                    new("sub", "usr_034", false, "Subject"),
                    new("aud", "orders-api", false, "Audience"),
                    new("scope", "orders:read", false),
                    new("iat", "1790234340", true, "2026.09.24 07:19"),
                    new("exp", "1790237940", true, "2026.09.24 08:19 · expired 12m ago", Alert: true),
                ]),
            MarkedInput: [.. marked.Select((parts, i) => new SourceLine(i + 1, parts))],
            Diff:
            [
                new(DiffOp.Same, 1, 1, marked[0]),
                new(DiffOp.Del, 2, null, marked[1]),
                new(DiffOp.Del, 3, null, marked[2]),
                new(DiffOp.Del, 4, null, marked[3]),
                new(DiffOp.Add, null, 2, [new("  -H 'Authorization: Bearer ", false), new("<jwt#1>", true), new("' \\", false)]),
                new(DiffOp.Add, null, 3, [new("  -H 'X-Api-Key: ", false), new("<api-key#2>", true), new("' \\", false)]),
                new(DiffOp.Add, null, 4, [new("  -b 'sid=", false), new("<cookie:sid#3>", true), new("; theme=dark'", false)]),
                new(DiffOp.Add, null, 5, []),
                new(DiffOp.Add, null, 6, [new("# jwt#1 · RS256 · signature removed", false)]),
                new(DiffOp.Add, null, 7, [new("#   sub  usr_034", false)]),
                new(DiffOp.Add, null, 8, [new("#   aud  orders-api", false)]),
                new(DiffOp.Add, null, 9, [new("#   exp  2026.09.24 08:19 (expired 12m ago)", false)]),
            ]);
    }
}
