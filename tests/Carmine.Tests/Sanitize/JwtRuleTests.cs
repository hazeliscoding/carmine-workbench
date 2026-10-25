using System.Text;
using System.Text.Json;
using Carmine.Core.Sanitize.Rules.Jwt;

namespace Carmine.Tests.Sanitize;

public class JwtRuleTests
{
    private static string B64Url(string text) => Convert.ToBase64String(Encoding.UTF8.GetBytes(text)).Replace('+', '-').Replace('/', '_').TrimEnd('=');

    private static string Json(object value) => JsonSerializer.Serialize(value);

    [Fact]
    public void Decodes_the_header_and_claims_of_the_token_it_finds()
    {
        var token = Fakes.Fake("jwt");
        var found = Assert.Single(JwtRule.Rule.Find($"Bearer {token}"));
        Assert.Equal((7, 7 + token.Length, "jwt", "JWT"), (found.Start, found.End, found.Kind, found.Reason));
        Assert.Equal("""{"alg":"RS256","typ":"JWT","kid":"orders-2026-09"}""", Json(found.Jwt!.Header));
        Assert.Equal(
            """{"iss":"https://auth.example.com","sub":"usr_034","aud":"orders-api","scope":"orders:read","iat":1790234340,"exp":1790237940}""",
            Json(found.Jwt.Claims));
        Assert.IsType<double>(found.Jwt.Claims["iat"]);
    }

    [Fact]
    public void Finds_an_unsigned_token_with_alg_none()
    {
        var token = Fakes.Fake("jwt-none");
        Assert.EndsWith(".", token, StringComparison.Ordinal);
        Assert.Equal([(6, 6 + token.Length, (object?)"none")], JwtRule.Rule.Find($"token {token} rejected").Select(f => (f.Start, f.End, f.Jwt?.Header["alg"])));
    }

    [Fact]
    public void Decodes_UTF8_claims()
    {
        var token = $"{B64Url("""{"alg":"HS256"}""")}.{B64Url("""{"name":"Zoë Ångström"}""")}.c2lnbmF0dXJl";
        var claims = JwtRule.Rule.Find(token)[0].Jwt!.Claims;
        Assert.Equal("Zoë Ångström", Assert.Single(claims, c => c.Key == "name").Value);
    }

    [Fact]
    public void Keeps_an_empty_claims_object_when_the_payload_is_not_JSON()
    {
        var token = $"{B64Url("""{"alg":"HS256"}""")}.{B64Url("not json")}.c2lnbmF0dXJl";
        var jwt = JwtRule.Rule.Find(token)[0].Jwt!;
        Assert.Equal(("""{"alg":"HS256"}""", "{}"), (Json(jwt.Header), Json(jwt.Claims)));
    }

    [Fact]
    public void Takes_all_five_segments_of_an_encrypted_token_and_keeps_its_claims_empty()
    {
        var token = Fakes.Fake("jwe");
        Assert.Equal(
            [(8, 8 + token.Length, "JWE", """{"alg":"dir","enc":"A256GCM"}""", "{}")],
            JwtRule.Rule.Find($"session={token}; Path=/").Select(f => (f.Start, f.End, f.Reason, Json(f.Jwt!.Header), Json(f.Jwt.Claims))));
    }

    [Theory]
    [InlineData("msg\\t")]
    [InlineData("line\\n")]
    [InlineData("id_token%3D")]
    [InlineData("%22")]
    public void Finds_a_token_right_after_an_escape_or_a_URL_encoded_character(string before)
    {
        var token = Fakes.Fake("jwt");
        Assert.Equal([token.Length], JwtRule.Rule.Find($"{before}{token}%22").Select(f => f.End - f.Start));
    }

    [Fact]
    public void Finds_a_token_glued_to_a_preceding_word_with_a_dot()
    {
        var token = Fakes.Fake("jwt");
        Assert.Equal([(15, 15 + token.Length)], JwtRule.Rule.Find($"orders.example.{token}").Select(f => (f.Start, f.End)));
    }

    [Fact]
    public void Skips_three_part_base64url_strings_whose_header_has_no_alg()
    {
        var token = $"{B64Url("""{"typ":"JWT","x":1}""")}.{B64Url("""{"sub":"a"}""")}.c2lnbmF0dXJl";
        Assert.Empty(JwtRule.Rule.Find(token));
    }
}
