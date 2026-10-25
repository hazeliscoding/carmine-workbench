using System.Diagnostics;
using Carmine.Core.Sanitize.Rules.PrivateKeys;

namespace Carmine.Tests.Sanitize;

public class PrivateKeysRuleTests
{
    [Fact]
    public void Scans_many_BEGIN_lines_without_an_END_quickly()
    {
        var armor = string.Join(' ', "-----BEGIN", "PRIVATE KEY-----");
        var text = string.Concat(Enumerable.Repeat($"{armor}\n", 35_000));
        var started = Stopwatch.StartNew();
        PrivateKeysRule.Rule.Find(text);
        Assert.InRange(started.ElapsedMilliseconds, 0, 500);
    }
}
