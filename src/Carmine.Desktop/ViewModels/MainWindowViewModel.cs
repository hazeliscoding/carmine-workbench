using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;

namespace Carmine.Desktop.ViewModels;

public sealed record FindingRow(string Number, string Kind, string Tag, string Where);

public sealed class MainWindowViewModel : ObservableObject
{
    public Sample Sample { get; } = Sample.Canned;

    // The kind is shown in capitals, as CSS text-transform did; Avalonia has no text transform.
    public IReadOnlyList<FindingRow> Findings { get; } =
        [.. Sample.Canned.Findings.Select((f, i) => new FindingRow($"{i + 1:00}", f.Kind.ToUpperInvariant(), $"<{f.Label}>", $"{f.Where} · line {f.Line}"))];

    public string Summary => $"{Sample.Findings.Count} secrets removed, review before sharing";

    public string InputMeta => $"{Sample.Format} · {Encoding.UTF8.GetByteCount(Sample.Input)} B · {Sample.Input.Split('\n').Length} ln";

    public string JwtTag => $"<{Sample.Jwt.Label}>";

    public string JwtMeta => $"{Sample.Jwt.Alg} · signature removed";

    public string Status => $"{Sample.Findings.Count} findings · 1 JWT";

    public string Version { get; } = typeof(MainWindowViewModel).Assembly.GetName().Version?.ToString(3) ?? "";
}
