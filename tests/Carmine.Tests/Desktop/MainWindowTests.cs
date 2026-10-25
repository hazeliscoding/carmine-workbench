using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Controls.Documents;
using Avalonia.Data;
using Avalonia.Headless;
using Avalonia.Input;
using Avalonia.Logging;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Platform;
using Avalonia.Styling;
using Avalonia.Threading;
using Avalonia.VisualTree;
using Carmine.Desktop;
using Carmine.Desktop.ViewModels;
using Carmine.Desktop.Views;

namespace Carmine.Tests.Desktop;

public partial class MainWindowTests
{
    private static readonly string[] Regions = ["Findings", "Input", "Sanitized", "JWT", "Status"];

    private static readonly BindingErrors Errors = new();

    private static readonly HeadlessUnitTestSession Session = Start();

    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>()
            .UseSkia()
            .UseHarfBuzz()
            .UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = false });

    [Fact]
    public Task The_window_names_each_region_without_binding_errors() => OnWindow(window =>
    {
        var names = window.GetVisualDescendants().Select(v => AutomationProperties.GetName((Control)v)).ToHashSet();
        Assert.All(Regions, region => Assert.Contains(region, names));

        // The diff's colors and signs are hidden from screen readers, so its lines say what changed.
        Assert.Contains("Removed:   -H 'X-Api-Key: 3f9a8c2e…' \\", names);
        Assert.Contains("Added:   -H 'X-Api-Key: <api-key#2>' \\", names);
        Assert.Empty(Errors.Messages);
    });

    [Fact]
    public Task The_binding_error_check_catches_a_broken_binding() => OnWindow(
        _ => Assert.NotEmpty(Errors.Messages),
        () => new Window { DataContext = new object(), Content = new TextBlock { [!TextBlock.TextProperty] = new ReflectionBinding("Missing") } });

    [Fact]
    public Task Tab_moves_through_the_regions_in_reading_order() => OnWindow(window =>
    {
        var order = new List<string?>();
        for (var i = 0; i < 5; i++)
        {
            window.KeyPressQwerty(PhysicalKey.Tab, RawInputModifiers.None);
            window.KeyReleaseQwerty(PhysicalKey.Tab, RawInputModifiers.None);
            Dispatcher.UIThread.RunJobs();
            order.Add(window.FocusManager?.GetFocusedElement() is Control focused ? AutomationProperties.GetName(focused) : null);
        }

        Assert.Equal(["Findings", "Input", "Sanitized", "JWT", "Findings"], order);
    });

    [Fact]
    public Task Keyboard_focus_is_outlined_in_the_token_focus_color() => OnWindow(window =>
    {
        window.KeyPressQwerty(PhysicalKey.Tab, RawInputModifiers.None);
        window.KeyReleaseQwerty(PhysicalKey.Tab, RawInputModifiers.None);
        var findings = (Control)window.FocusManager!.GetFocusedElement()!;
        Assert.True(window.TryFindResource("Auburn", ThemeVariant.Light, out var auburn));

        var frame = Render(window);
        var edge = findings.TranslatePoint(new Point(1, findings.Bounds.Height / 2), window)!.Value;
        Assert.Equal(((ISolidColorBrush)auburn!).Color, Pixel(frame, edge));
    });

    [Fact]
    public Task The_window_never_calls_the_output_clean() => OnWindow(window =>
    {
        var text = window.GetVisualDescendants().OfType<TextBlock>()
            .Select(t => t.Text ?? string.Concat(t.Inlines?.OfType<Run>().Select(r => r.Text) ?? []));
        Assert.Matches(Clean(), "The output is clean.");
        Assert.DoesNotContain(text, t => Clean().IsMatch(t));
    });

    private static HeadlessUnitTestSession Start()
    {
        // Binding errors are only logged, so the sink is what turns them into a failure.
        Logger.Sink = Errors;
        return HeadlessUnitTestSession.StartNew(typeof(MainWindowTests));
    }

    private static Task OnWindow(Action<Window> test, Func<Window>? create = null) => Session.Dispatch(() =>
    {
        Application.Current!.RequestedThemeVariant = ThemeVariant.Light;
        Errors.Messages.Clear();
        var window = create?.Invoke() ?? new MainWindow { DataContext = new MainWindowViewModel(), Width = 1280, Height = 800 };
        window.Show();
        Dispatcher.UIThread.RunJobs();
        try
        {
            test(window);
        }
        finally
        {
            window.Close();
        }
    }, TestContext.Current.CancellationToken);

    private static Bitmap Render(Window window)
    {
        Dispatcher.UIThread.RunJobs();
        return window.CaptureRenderedFrame() ?? throw new InvalidOperationException("No frame was rendered.");
    }

    private static Color Pixel(Bitmap frame, Point at)
    {
        var bytes = new byte[4];
        var pinned = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        try
        {
            frame.CopyPixels(new PixelRect((int)at.X, (int)at.Y, 1, 1), pinned.AddrOfPinnedObject(), 4, 4);
        }
        finally
        {
            pinned.Free();
        }

        return frame.Format == PixelFormats.Rgba8888 ? Color.FromRgb(bytes[0], bytes[1], bytes[2]) : Color.FromRgb(bytes[2], bytes[1], bytes[0]);
    }

    [GeneratedRegex(@"\bclean\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex Clean();

    private sealed class BindingErrors : ILogSink
    {
        public ConcurrentQueue<string> Messages { get; } = new();

        public bool IsEnabled(LogEventLevel level, string area) => level >= LogEventLevel.Warning && area == LogArea.Binding;

        public void Log(LogEventLevel level, string area, object? source, string messageTemplate) => Log(level, area, source, messageTemplate, []);

        public void Log(LogEventLevel level, string area, object? source, string messageTemplate, params object?[] propertyValues)
        {
            if (IsEnabled(level, area))
            {
                Messages.Enqueue($"{source}: {messageTemplate} {string.Join(", ", propertyValues)}");
            }
        }
    }
}
