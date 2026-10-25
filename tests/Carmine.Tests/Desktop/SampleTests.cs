using Carmine.Desktop.ViewModels;

namespace Carmine.Tests.Desktop;

// The canned sample's diff and marks are written out by hand, where the Angular screen computed them.
public class SampleTests
{
    private static readonly Sample Sample = Sample.Canned;

    [Fact]
    public void The_diff_rebuilds_the_input_and_the_output()
    {
        Assert.Equal(Sample.Input, string.Join('\n', Sample.Diff.Where(l => !l.IsAdd).Select(l => l.Text)));
        Assert.Equal(Sample.Output, string.Join('\n', Sample.Diff.Where(l => !l.IsDel).Select(l => l.Text)));
        Assert.Equal(Sample.Input, string.Join('\n', Sample.MarkedInput.Select(l => l.Text)));
    }

    [Fact]
    public void The_marks_are_each_secret_removed_and_each_label_added()
    {
        static IEnumerable<string> Hits(IEnumerable<IReadOnlyList<Segment>> lines) => lines.SelectMany(parts => parts).Where(p => p.Hit).Select(p => p.Text);

        Assert.Equal(Sample.Findings.Select(f => f.Value), Hits(Sample.MarkedInput.Select(l => l.Parts)));
        Assert.Equal(Sample.Findings.Select(f => f.Value), Hits(Sample.Diff.Where(l => l.IsDel).Select(l => l.Parts)));
        Assert.Equal(Sample.Findings.Select(f => $"<{f.Label}>"), Hits(Sample.Diff.Where(l => l.IsAdd).Select(l => l.Parts)));
    }

    [Fact]
    public void The_output_keeps_no_secret_value()
    {
        Assert.All(Sample.Findings, f => Assert.Contains(f.Value, Sample.Input, StringComparison.Ordinal));
        Assert.All(Sample.Findings, f => Assert.DoesNotContain(f.Value, Sample.Output, StringComparison.Ordinal));
        Assert.All(Sample.Findings, f => Assert.EndsWith("…", f.Value, StringComparison.Ordinal));
    }

    [Fact]
    public void The_screen_text_matches_the_Angular_screen()
    {
        var model = new MainWindowViewModel();
        Assert.Equal("3 secrets removed, review before sharing", model.Summary);
        Assert.Equal("curl · 162 B · 4 ln", model.InputMeta);
        Assert.Equal("3 findings · 1 JWT", model.Status);
        Assert.Equal(["01", "02", "03"], model.Findings.Select(f => f.Number));
        Assert.Equal("API KEY", model.Findings[1].Kind);
        Assert.Equal("X-Api-Key header · line 3", model.Findings[1].Where);
    }
}
