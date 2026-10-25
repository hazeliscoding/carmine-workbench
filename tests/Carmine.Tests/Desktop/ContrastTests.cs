using System.Globalization;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace Carmine.Tests.Desktop;

// Every text and focus color pair the UI uses must pass WCAG 2.2 AA, in both themes.
public partial class ContrastTests
{
    private static readonly string[] Text = ["TextPrimary", "TextSecondary", "TextMeta", "TextLink", "Amber", "DirectiveRed", "Authorized"];
    private static readonly string[] Surfaces = ["SurfacePage", "SurfaceCard", "SurfaceInset"];

    // (foreground, background, minimum ratio): 4.5 for text (SC 1.4.3), 3 for focus indicators (SC 1.4.11).
    private static readonly (string Fg, string Bg, double Min)[] Pairs =
    [
        .. Text.SelectMany(fg => Surfaces.Select(bg => (fg, bg, 4.5))),
        .. Surfaces.Select(bg => ("Auburn", bg, 3.0)),
        .. new[] { "TextPrimary", "TextSecondary", "TextLink" }.SelectMany(fg => new[] { (fg, "DiffDelBg", 4.5), (fg, "DiffAddBg", 4.5) }),
        ("TextPrimary", "MarkBg", 4.5),
        // The focus outline is drawn inside the Sanitized region, where the diff colors run to its edge.
        ("Auburn", "DiffDelBg", 3.0),
        ("Auburn", "DiffAddBg", 3.0),
    ];

    private static readonly XNamespace X = "http://schemas.microsoft.com/winfx/2006/xaml";

    // The tokens before the AA fixes, as ROADMAP.md lists them for directive//01.
    private const string Original = """
        <ResourceDictionary xmlns="https://github.com/avaloniaui" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
          <ResourceDictionary.ThemeDictionaries>
            <ResourceDictionary x:Key="Light">
              <SolidColorBrush x:Key="Paper" Color="#F2EDE2" />
              <StaticResource x:Key="SurfacePage" ResourceKey="Paper" />
              <SolidColorBrush x:Key="TextMeta" Color="#7D7460" />
              <SolidColorBrush x:Key="Amber" Color="#A17B22" />
              <SolidColorBrush x:Key="Auburn" Color="#7E4A33" />
              <SolidColorBrush x:Key="DirectiveRed" Color="#9E2B2B" />
            </ResourceDictionary>
            <ResourceDictionary x:Key="Dark">
              <SolidColorBrush x:Key="Paper" Color="#191712" />
              <StaticResource x:Key="SurfacePage" ResourceKey="Paper" />
              <SolidColorBrush x:Key="TextMeta" Color="#8A8271" />
              <SolidColorBrush x:Key="Amber" Color="#C09A3E" />
              <SolidColorBrush x:Key="Auburn" Color="#7E4A33" />
              <SolidColorBrush x:Key="DirectiveRed" Color="#B84740" />
            </ResourceDictionary>
          </ResourceDictionary.ThemeDictionaries>
        </ResourceDictionary>
        """;

    [Fact]
    public void Contrast_measures_the_known_extremes()
    {
        Assert.Equal(21, Contrast((0, 0, 0), (255, 255, 255)), 10);
        Assert.Equal(1, Contrast((9, 9, 9), (9, 9, 9)), 10);
    }

    [Fact]
    public void Resolve_follows_StaticResource_aliases_and_rejects_unknown_tokens()
    {
        var theme = new Dictionary<string, string> { ["A"] = "#FFFFFF", ["B"] = "{StaticResource A}", ["C"] = "{StaticResource Missing}" };
        Assert.Equal((255, 255, 255), Resolve(theme, "B"));
        Assert.Throws<KeyNotFoundException>(() => Resolve(theme, "C"));
    }

    [Fact]
    public void The_check_catches_the_four_directive01_failures()
    {
        (string, string, double)[] pairs = [.. new[] { "TextMeta", "Amber", "DirectiveRed" }.Select(fg => (fg, "SurfacePage", 4.5)), ("Auburn", "SurfacePage", 3.0)];
        Assert.Equal(
            ["Light TextMeta 3.96", "Light Amber 3.34", "Dark DirectiveRed 3.42", "Dark Auburn 2.48"],
            Failures(ParseThemes(Original), pairs).Select(f => $"{f.Theme} {f.Fg} {f.Ratio.ToString(CultureInfo.InvariantCulture)}"));
    }

    [Fact]
    public void The_app_tokens_pass_in_both_themes()
    {
        var themes = ParseThemes(File.ReadAllText(TokensPath()));
        Assert.Equal(["Light", "Dark"], themes.Keys);
        Assert.Empty(Failures(themes, Pairs));
    }

    private static string TokensPath()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (!File.Exists(Path.Combine(dir.FullName, "Carmine.slnx")))
        {
            dir = dir.Parent ?? throw new DirectoryNotFoundException("Carmine.slnx is not above the test output.");
        }

        return Path.Combine(dir.FullName, "src", "Carmine.Desktop", "Themes", "Tokens.axaml");
    }

    // Each theme dictionary's colors by key: a brush's hex color, or an alias written as {StaticResource Key}.
    private static Dictionary<string, Dictionary<string, string>> ParseThemes(string xaml) =>
        XDocument.Parse(xaml).Descendants()
            .Where(e => e.Name.LocalName == "ResourceDictionary" && e.Attribute(X + "Key") is not null)
            .ToDictionary(
                theme => theme.Attribute(X + "Key")!.Value,
                theme => theme.Elements()
                    .Where(e => e.Name.LocalName is "SolidColorBrush" or "StaticResource")
                    .ToDictionary(
                        e => e.Attribute(X + "Key")!.Value,
                        e => e.Name.LocalName == "SolidColorBrush" ? e.Attribute("Color")!.Value : $"{{StaticResource {e.Attribute("ResourceKey")!.Value}}}"));

    private static (int R, int G, int B) Resolve(IReadOnlyDictionary<string, string> theme, string key)
    {
        if (!theme.TryGetValue(key, out var value))
        {
            throw new KeyNotFoundException($"unknown token {key}");
        }

        if (Alias().Match(value) is { Success: true } alias)
        {
            return Resolve(theme, alias.Groups[1].Value);
        }

        var hex = Hex().Match(value);
        Assert.True(hex.Success, $"cannot resolve color \"{value}\" of {key}");
        int Channel(int i) => int.Parse(hex.Groups[1].Value.AsSpan(i, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        return (Channel(0), Channel(2), Channel(4));
    }

    private static double Luminance((int R, int G, int B) rgb)
    {
        static double Linear(int c)
        {
            var s = c / 255.0;
            return s <= 0.04045 ? s / 12.92 : Math.Pow((s + 0.055) / 1.055, 2.4);
        }

        return (0.2126 * Linear(rgb.R)) + (0.7152 * Linear(rgb.G)) + (0.0722 * Linear(rgb.B));
    }

    private static double Contrast((int, int, int) a, (int, int, int) b)
    {
        var (la, lb) = (Luminance(a), Luminance(b));
        return (Math.Max(la, lb) + 0.05) / (Math.Min(la, lb) + 0.05);
    }

    private static IEnumerable<(string Theme, string Fg, string Bg, double Ratio, double Min)> Failures(
        Dictionary<string, Dictionary<string, string>> themes, IEnumerable<(string Fg, string Bg, double Min)> pairs) =>
        from theme in themes
        from pair in pairs
        let ratio = Contrast(Resolve(theme.Value, pair.Fg), Resolve(theme.Value, pair.Bg))
        where ratio < pair.Min
        select (theme.Key, pair.Fg, pair.Bg, Math.Floor(ratio * 100) / 100, pair.Min);

    [GeneratedRegex(@"^\{StaticResource (\w+)\}$")]
    private static partial Regex Alias();

    [GeneratedRegex("^#([0-9A-Fa-f]{6})$")]
    private static partial Regex Hex();
}
