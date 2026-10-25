using System.Text;
using Carmine.Core.Sanitize;
using Carmine.Core.Sanitize.Rules;

namespace Carmine.Tests.Sanitize;

public class FixtureTests
{
    // The build copies each rule's cases to Rules/<Rule>/fixtures/ and the engine's own to fixtures/.
    private static readonly Dictionary<string, string> CasePaths = FindCases();

    // An empty label keeps xUnit from appending the argument, so the test reads "jwt/curl-bearer".
    public static IEnumerable<TheoryDataRow<string>> Cases() =>
        CasePaths.Keys.Order(StringComparer.Ordinal).Select(name => new TheoryDataRow<string>(name) { TestDisplayName = name, Label = "" });

    public static TheoryData<string> RuleNames() => [.. RuleList.All.Select(rule => rule.Name)];

    [Fact]
    public void Finds_the_fixture_cases() => Assert.Contains("engine/log-no-secrets", CasePaths.Keys);

    [Theory]
    [MemberData(nameof(Cases))]
    public void Fixture(string name)
    {
        var (secrets, expected, result) = Run(name);
        var leaks = Fakes.Leaks(expected, secrets);
        Assert.True(leaks.Count == 0, $"declared secrets in the expected output: {string.Join(", ", leaks)}");
        Assert.Equal(expected, result.Output);
        var undeclared = Fakes.Undeclared(result.Changes, secrets);
        Assert.True(undeclared.Count == 0, $"removed values the fixture does not declare: {string.Join(", ", undeclared)}");
        Assert.Equal(result.Output, Engine.Sanitize(result.Output).Output);
    }

    [Theory]
    [MemberData(nameof(RuleNames))]
    public void Each_rule_has_a_case_where_it_removes_something(string rule)
    {
        var own = CasePaths.Keys.Where(name => name.StartsWith($"{rule}/", StringComparison.Ordinal));
        Assert.Contains(own, name => Run(name).Result.Changes.Any(change => change.Rule == rule));
    }

    [Fact]
    public void Expands_placeholders_and_declares_their_values_as_secrets()
    {
        var (text, secrets) = Fakes.Expand("a={{secret:s3cr3tvalue}} b={{fake:github-token}} c={{fake:github-token:2}}");
        var (one, two) = (Fakes.Fake("github-token"), Fakes.Fake("github-token:2"));
        Assert.Equal($"a=s3cr3tvalue b={one} c={two}", text);
        Assert.Equal(["s3cr3tvalue", one, two], secrets);
    }

    [Fact]
    public void Builds_the_same_fake_for_the_same_name_and_number_and_a_different_one_for_another_number()
    {
        Assert.Equal(Fakes.Fake("jwt:1"), Fakes.Fake("jwt"));
        Assert.NotEqual(Fakes.Fake("jwt"), Fakes.Fake("jwt:2"));
    }

    [Fact]
    public void Leaves_other_double_brace_text_alone()
    {
        var (text, secrets) = Fakes.Expand("Bearer {{token}}");
        Assert.Equal("Bearer {{token}}", text);
        Assert.Empty(secrets);
    }

    [Fact]
    public void Rejects_an_unknown_fake() => Assert.Contains("nope", Assert.Throws<ArgumentException>(() => Fakes.Expand("{{fake:nope}}")).Message);

    [Fact]
    public void Finds_a_declared_secret_left_in_the_output() =>
        Assert.Equal(["s3cr3tvalue"], Fakes.Leaks("Bearer s3cr3tvalue", ["s3cr3tvalue", "other"]));

    [Fact]
    public void Finds_a_removed_value_the_fixture_did_not_declare()
    {
        static Change Removed(string value) => new("x#1", "x", "x", "x", 1, 0, 0, value);
        Assert.Equal(["hunter2"], Fakes.Undeclared([Removed("s3cr3tvalue"), Removed("hunter2"), Removed("hunter2")], ["s3cr3tvalue"]));
    }

    private static (List<string> Secrets, string Expected, SanitizeResult Result) Run(string name)
    {
        var path = CasePaths[name];
        var (text, secrets) = Fakes.Expand(Read($"{path}.in.txt"));
        var expected = File.Exists($"{path}.out.txt") ? Read($"{path}.out.txt") : text;
        return (secrets, expected, Engine.Sanitize(text));
    }

    // Byte for byte: no BOM handling and no newline translation, so the CRLF cases keep their CRs.
    private static string Read(string path) => new UTF8Encoding(false).GetString(File.ReadAllBytes(path));

    // "jwt/curl-bearer" for Rules/Jwt/fixtures/curl-bearer.in.txt, "engine/log-no-secrets" for fixtures/log-no-secrets.in.txt.
    private static Dictionary<string, string> FindCases()
    {
        var cases = new Dictionary<string, string>();
        foreach (var path in Directory.EnumerateFiles(AppContext.BaseDirectory, "*.in.txt", SearchOption.AllDirectories))
        {
            var parts = Path.GetRelativePath(AppContext.BaseDirectory, path).Split(Path.DirectorySeparatorChar);
            var owner = parts switch
            {
                ["fixtures", _] => "engine",
                ["Rules", var folder, "fixtures", _] => string.Concat(folder.Select((c, i) => i > 0 && char.IsAsciiLetterUpper(c) ? $"-{c}" : $"{c}")).ToLowerInvariant(),
                _ => null,
            };
            if (owner is not null) cases.Add($"{owner}/{parts[^1][..^".in.txt".Length]}", path[..^".in.txt".Length]);
        }
        return cases;
    }
}
