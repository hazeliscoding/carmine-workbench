using Avalonia;
using Avalonia.Headless;
using Avalonia.Media.Imaging;
using Avalonia.Styling;
using Avalonia.Threading;
using Carmine.Desktop;
using Carmine.Desktop.ViewModels;
using Carmine.Desktop.Views;

namespace Carmine.Screenshots;

internal static class Program
{
    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>()
            .UseSkia()
            .UseHarfBuzz()
            .UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = false });

    public static int Main(string[] args)
    {
        var output = Path.GetFullPath(args.FirstOrDefault() ?? "screenshots");
        Directory.CreateDirectory(output);
        BuildAvaloniaApp().SetupWithoutStarting();

        foreach (var (theme, name) in new[] { (ThemeVariant.Light, "screenshot-light.png"), (ThemeVariant.Dark, "screenshot-dark.png") })
        {
            Application.Current!.RequestedThemeVariant = theme;

            // The size of the Angular app's README screenshots, so the two can be compared.
            var window = new MainWindow { DataContext = new MainWindowViewModel(), Width = 1280, Height = 800 };
            window.Show();
            Settle(TimeSpan.FromSeconds(1));
            var frame = window.CaptureRenderedFrame() ?? throw new InvalidOperationException("No frame was rendered.");
            frame.Save(Path.Combine(output, name), new PngBitmapEncoderOptions());
            window.Close();
            Console.WriteLine($"  {name}");
        }

        Console.WriteLine($"Screenshots written to {output}");
        return 0;
    }

    private static void Settle(TimeSpan time)
    {
        var until = DateTime.UtcNow + time;
        while (DateTime.UtcNow < until)
        {
            Dispatcher.UIThread.RunJobs();
            AvaloniaHeadlessPlatform.ForceRenderTimerTick();
            Thread.Sleep(15);
        }
    }
}
