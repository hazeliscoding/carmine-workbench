using Avalonia;

namespace Carmine.Desktop;

internal static class Program
{
    [STAThread]
    public static int Main(string[] args) => BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);

    // Also used by the Avalonia designer.
    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .LogToTrace();
}
