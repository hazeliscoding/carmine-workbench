using System.Diagnostics.CodeAnalysis;
using System.Text.RegularExpressions;

namespace Carmine.Tests.Guards;

internal sealed record Ban(string Name, Regex Pattern)
{
    public Ban(string name, [StringSyntax(StringSyntaxAttribute.Regex)] string pattern) : this(name, new Regex(pattern)) { }
}

internal sealed record Hit(string File, int Line, string Name)
{
    public override string ToString() => $"{File}:{Line}  {Name}";
}

internal static class SourceScan
{
    public static IEnumerable<Hit> Find(string file, string text, IEnumerable<Ban> bans) =>
        bans.SelectMany(ban => ban.Pattern.Matches(text).Select(match => new Hit(file, text.AsSpan(0, match.Index).Count('\n') + 1, ban.Name)))
            .OrderBy(hit => hit.Line);
}
