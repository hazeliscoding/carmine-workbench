using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using Carmine.Core.Sanitize;

namespace Carmine.Tests.Sanitize;

public partial class EngineTests
{
    private static readonly Rule Header = StandIn("header", RuleBy.Context, HeaderPattern(), "bearer");
    private static readonly Rule Kv = StandIn("kv", RuleBy.Context, KvPattern(), "key");
    private static readonly Rule Quoted = StandIn("quoted", RuleBy.Context, QuotedPattern(), "secret");
    private static readonly Rule Token = StandIn("token", RuleBy.Format, TokenPattern());

    [GeneratedRegex("""Auth: [A-Za-z0-9_]+ ([^\r\n]+)""")]
    private static partial Regex HeaderPattern();

    [GeneratedRegex("""key=([^ \t\r\n]+)""")]
    private static partial Regex KvPattern();

    [GeneratedRegex("""
        "secret": "([^"]*)"
        """)]
    private static partial Regex QuotedPattern();

    [GeneratedRegex("""(tok_[A-Za-z0-9_]+)""")]
    private static partial Regex TokenPattern();

    [GeneratedRegex("""auth=([^ \t\r\n]+)""")]
    private static partial Regex CookiePattern();

    [GeneratedRegex("""key=([A-Za-z0-9_]{3})""")]
    private static partial Regex ShortPattern();

    [GeneratedRegex("""(eyJ[A-Za-z0-9_]+)""")]
    private static partial Regex JwtPattern();

    // Stand-in rules: each reports capture group 1 of its pattern.
    private static Rule StandIn(string name, RuleBy by, Regex pattern, string? kind = null, Func<string, DecodedJwt>? jwt = null) =>
        new(name, by, text =>
        [
            .. from Match m in pattern.Matches(text)
               let value = m.Groups[1]
               select new Finding(value.Index, value.Index + value.Length, kind ?? name, $"{name} value", jwt?.Invoke(value.Value)),
        ]);

    [Fact]
    public void Replaces_a_finding_with_a_typed_numbered_label_and_reports_the_change()
    {
        var result = Engine.Sanitize("GET /\nAuth: Bearer s3cr3tvalue\n", [Header]);
        Assert.Equal("GET /\nAuth: Bearer <bearer#1>\n", result.Output);
        Assert.Equal([new Change("bearer#1", "bearer", "header", "header value", 2, 19, 30, "s3cr3tvalue")], result.Changes);
    }

    [Fact]
    public void Leaves_text_without_findings_unchanged()
    {
        var result = Engine.Sanitize("plain text", [Header]);
        Assert.Equal("plain text", result.Output);
        Assert.Empty(result.Changes);
        Assert.Empty(result.Jwts);
    }

    [Fact]
    public void Numbers_labels_across_kinds_in_order_of_appearance() =>
        Assert.Equal("<token#1> key=<key#2> <token#3>", Engine.Sanitize("tok_aaaaaaaa key=first tok_bbbbbbbb", [Kv, Token]).Output);

    [Fact]
    public void Gives_a_repeated_value_the_same_label() =>
        Assert.Equal("key=<key#1> key=<key#1>", Engine.Sanitize("key=abc key=abc", [Kv]).Output);

    [Fact]
    public void Gives_every_copy_of_a_value_of_8_or_more_characters_the_same_label_even_where_no_rule_matches()
    {
        var result = Engine.Sanitize("log: retry with s3cr3tvalue\nAuth: Bearer s3cr3tvalue\nid=xs3cr3tvaluex", [Header]);
        Assert.Equal("log: retry with <bearer#1>\nAuth: Bearer <bearer#1>\nid=x<bearer#1>x", result.Output);
        Assert.Equal(
            [("bearer#1", 1, "same value as bearer#1"), ("bearer#1", 2, "header value"), ("bearer#1", 3, "same value as bearer#1")],
            result.Changes.Select(c => (c.Label, c.Line, c.Reason)));
    }

    [Fact]
    public void Numbers_a_value_by_its_first_copy_when_the_copy_comes_before_the_rule_match() =>
        Assert.Equal(
            "<bearer#1> <token#2>\nAuth: Bearer <bearer#1>",
            Engine.Sanitize("s3cr3tvalue tok_aaaaaaaa\nAuth: Bearer s3cr3tvalue", [Header, Token]).Output);

    [Fact]
    public void Leaves_copies_of_values_under_8_characters_alone() =>
        Assert.Equal("Auth: Bearer <bearer#1>\npassword hunter2", Engine.Sanitize("Auth: Bearer hunter2\npassword hunter2", [Header]).Output);

    [Fact]
    public void Lets_a_format_finding_win_over_a_context_finding_on_the_same_span()
    {
        var result = Engine.Sanitize("Auth: Bearer tok_abcdefgh", [Header, Token]);
        Assert.Equal("Auth: Bearer <token#1>", result.Output);
        Assert.Equal([new Change("token#1", "token", "token", "token value", 1, 13, 25, "tok_abcdefgh")], result.Changes);
    }

    [Fact]
    public void Replaces_the_union_when_a_context_finding_contains_a_format_finding()
    {
        var result = Engine.Sanitize("\"secret\": \"Bearer tok_abcdefgh\"", [Quoted, Token]);
        Assert.Equal("\"secret\": \"<token#1>\"", result.Output);
        Assert.Equal([new Change("token#1", "token", "token", "token value", 1, 11, 30, "tok_abcdefgh")], result.Changes);
    }

    [Fact]
    public void Keeps_each_label_when_a_context_finding_overlaps_two_format_findings_and_removes_what_lies_between()
    {
        Rule[] rules = [Quoted, Token];
        var once = Engine.Sanitize("\"secret\": \"lead9xyz tok_aaaaaaaa|tok_bbbbbbbb|leftover9\"", rules).Output;
        Assert.Equal("\"secret\": \"<token#1>|<token#2>\"", once);
        Assert.Equal(once, Engine.Sanitize(once, rules).Output);
    }

    [Fact]
    public void Replaces_the_merged_text_wherever_it_repeats_not_only_the_specific_value()
    {
        var cookie = StandIn("cookie", RuleBy.Context, CookiePattern(), "cookie:auth");
        var input = "auth=tok_aaaaaaaa|s3cr3tvalue\nretry tok_aaaaaaaa|s3cr3tvalue";
        Assert.Equal("auth=<token#1>\nretry <token#1>", Engine.Sanitize(input, [cookie, Token]).Output);
    }

    [Fact]
    public void Keeps_a_copy_span_inside_the_input_when_a_longer_value_shares_its_start()
    {
        var result = Engine.Sanitize("key=s3cr3tvalueLONGER\nkey=s3cr3tvalue\nlog s3cr3tvalue", [Kv]);
        Assert.Equal((42, 53), (result.Changes[^1].Start, result.Changes[^1].End));
    }

    [Fact]
    public void Keeps_up_with_a_2_MB_input_on_a_single_line()
    {
        var input = string.Join(' ', Enumerable.Range(0, 80_000).Select(i => $"key=s3cr3t{i.ToString("x8", CultureInfo.InvariantCulture)}"));
        var started = Stopwatch.StartNew();
        Assert.Equal(80_000, Engine.Sanitize(input, [Kv]).Changes.Count);
        Assert.InRange(started.ElapsedMilliseconds, 0, 3000);
    }

    [Fact]
    public void Keeps_up_with_a_1_MB_input_full_of_findings()
    {
        var input = string.Join('\n', Enumerable.Range(0, 40_000).Select(i => $"key=s3cr3t{i.ToString("x8", CultureInfo.InvariantCulture)}"));
        var started = Stopwatch.StartNew();
        var result = Engine.Sanitize(input, [Kv]);
        Assert.Equal(40_000, result.Changes.Count);
        Assert.InRange(started.ElapsedMilliseconds, 0, 3000);
    }

    [Fact]
    public void Lets_the_longer_span_win_between_rules_of_the_same_rank()
    {
        var shortRule = StandIn("short", RuleBy.Context, ShortPattern());
        Assert.Equal("key=<key#1>", Engine.Sanitize("key=abcdef", [shortRule, Kv]).Output);
    }

    [Theory]
    [InlineData("$TOKEN")]
    [InlineData("${TOKEN}")]
    [InlineData("$(cat token.txt)")]
    [InlineData("%TOKEN%")]
    [InlineData("{{token}}")]
    [InlineData("<token>")]
    [InlineData("<jwt#1>")]
    [InlineData("***")]
    [InlineData("[REDACTED]")]
    [InlineData("[FILTERED]")]
    public void Leaves_the_reference_alone(string reference)
    {
        var input = $"Auth: Bearer {reference}";
        Assert.Equal(input, Engine.Sanitize(input, [Header]).Output);
    }

    [Theory]
    [InlineData("null")]
    [InlineData("undefined")]
    [InlineData("true")]
    [InlineData("False")]
    [InlineData("None")]
    [InlineData("nil")]
    public void Leaves_the_empty_value_alone(string empty)
    {
        var input = $"Auth: Bearer {empty}";
        Assert.Equal(input, Engine.Sanitize(input, [Header]).Output);
    }

    [Fact]
    public void Keeps_CRLF_line_endings_and_counts_lines_across_them()
    {
        var result = Engine.Sanitize("a\r\nb\r\nAuth: Bearer s3cr3tvalue\r\n", [Header]);
        Assert.Equal("a\r\nb\r\nAuth: Bearer <bearer#1>\r\n", result.Output);
        Assert.Equal(3, result.Changes[0].Line);
    }

    [Fact]
    public void Returns_each_labeled_JWT_once_with_its_decoded_header_and_claims()
    {
        var jwt = StandIn("jwt", RuleBy.Format, JwtPattern(), "jwt", value =>
            new DecodedJwt(new OrderedDictionary<string, object?> { ["alg"] = "none" }, new OrderedDictionary<string, object?> { ["sub"] = value[3..] }));
        var result = Engine.Sanitize("eyJaaaaaaaa eyJaaaaaaaa eyJbbbbbbbb", [jwt]);
        Assert.Equal("<jwt#1> <jwt#1> <jwt#2>", result.Output);
        Assert.Equal(
            [("jwt#1", """{"alg":"none"}""", """{"sub":"aaaaaaaa"}"""), ("jwt#2", """{"alg":"none"}""", """{"sub":"bbbbbbbb"}""")],
            result.Jwts.Select(j => (j.Label, JsonSerializer.Serialize(j.Header), JsonSerializer.Serialize(j.Claims))));
    }

    [Fact]
    public void Changes_nothing_when_run_on_its_own_output()
    {
        Rule[] rules = [Header, Kv, Token];
        var once = Engine.Sanitize("tok_aaaaaaaa key=first\nAuth: Bearer s3cr3tvalue", rules).Output;
        Assert.Equal("<token#1> key=<key#2>\nAuth: Bearer <bearer#3>", once);
        Assert.Equal(once, Engine.Sanitize(once, rules).Output);
    }
}
