using Avalonia.Controls.Documents;
using Avalonia.Data.Converters;
using Carmine.Desktop.ViewModels;

namespace Carmine.Desktop.Views;

public static class SegmentConverters
{
    // A hit becomes a Run with the "hit" class, so each view styles its own marks.
    public static readonly FuncValueConverter<IReadOnlyList<Segment>, InlineCollection> Inlines = new(parts =>
    {
        var inlines = new InlineCollection();
        foreach (var part in parts ?? [])
        {
            var run = new Run(part.Text);
            if (part.Hit)
            {
                run.Classes.Add("hit");
            }

            inlines.Add(run);
        }

        return inlines;
    });
}
