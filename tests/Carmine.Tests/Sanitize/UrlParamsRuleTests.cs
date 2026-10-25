using System.Diagnostics;
using Carmine.Core.Sanitize.Rules.UrlParams;

namespace Carmine.Tests.Sanitize;

public class UrlParamsRuleTests
{
    [Fact]
    public void Scans_200_KB_of_dotted_text_quickly()
    {
        var text = string.Concat(Enumerable.Repeat("a.", 100_000));
        var started = Stopwatch.StartNew();
        UrlParamsRule.Rule.Find(text);
        Assert.InRange(started.ElapsedMilliseconds, 0, 500);
    }
}
