using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace Carmine.Tests.Guards;

public sealed partial class NetworkGuardTests
{
    private const string Updater = "src/Carmine.Desktop/Services/Updates.cs";

    // Comments and strings count too. Skipping them takes a lexer for every C# string form, and a slip there
    // would hide code; a false positive only costs a reworded comment.
    private static readonly Ban[] Apis =
    [
        new("System.Net", @"\bSystem\.Net\b"),
        // System.Net.Http is an implicit using, so these need no using line.
        new("HTTP client", @"\b(?:HttpClient|HttpMessage|DelegatingHandler)\w*|\b\w*HttpHandler\b"),
        new("WebRequest or WebClient", @"\b\w*(?:WebRequest|WebClient)\b"),
        new("HttpListener", @"\bHttpListener\w*"),
        new("socket", @"\b\w*Socket\w*"),
        new("TCP or UDP", @"\b\w*(?:Tcp|Udp)[A-Z]\w*"),
        new("DNS", @"\bDns\w*"),
        new("network stream", @"\b(?:NetworkStream|SslStream|NegotiateStream)\b"),
        new("QUIC", @"\bQuic[A-Z]\w*"),
        new("SMTP", @"\bSmtp[A-Z]\w*"),
        new("network information", @"\b(?:Ping|NetworkInterface|NetworkChange)\b"),
        // A pipe name can be \\server\pipe\name, which Windows opens over SMB.
        new("pipe stream", @"\bSystem\.IO\.Pipes\b|\b\w*Pipe\w*Stream\b"),
        // XmlReader, XDocument.Load and DTDs fetch http URIs through System.Xml's resolver.
        new("System.Xml", @"\bSystem\.Xml\b"),
        new("remote registry", @"\bOpenRemoteBaseKey\b"),
        // A child process can open a URL (xdg-open, open, start) or run curl.
        new("process", @"\bProcess(?:StartInfo)?\b|\bShellExecute\w*"),
        new("URL opener", @"\bI?Launcher\b|\bLaunch\w*Async\b|\bOpenUr[il]\w*|\bHyperlinkButton\b|\bNavigateUri\b"),
        new("web view", @"\b\w*WebView\w*"),
        // Native code can call WinHTTP, libcurl or ShellExecute where this scan can't see it.
        new("native interop", @"\b(?:DllImport|LibraryImport|NativeLibrary|ComImport|GetTypeFromProgID|GetTypeFromCLSID)\b"),
        // The XAML previewer's TCP transport.
        new("Avalonia.Remote", @"\bAvalonia\.Remote\b"),
        new("Velopack update check", @"\bUpdateManager\b|\bVelopack\.Sources\b"),
    ];

    // Any scheme but avares://, and UNC paths, which Windows opens over SMB.
    private static readonly Ban RemoteAsset = new("URI outside the app", @"\b(?!avares://)[A-Za-z][\w+.-]*://|\\\\[^\\\s""']+\\");

    // xmlns values name XAML namespaces and are never fetched.
    [GeneratedRegex(@"\bxmlns(?::[\w.-]+)?\s*=\s*(?:""[^""]*""|'[^']*')")]
    private static partial Regex XmlnsAttribute();

    private const string NativeAotCompiler = "The NativeAOT compiler and the .NET runtime it links in. Only code the app calls is linked, and the source scan rules out network calls.";
    private const string SkiaNatives = "Skia's native library for one platform; it draws and has no network code.";
    private const string HarfBuzzNatives = "HarfBuzz's native library for one platform; it shapes text and has no network code.";

    // Every package in the app's restore graph, transitive ones included, and why it can't reach the network.
    private static readonly Dictionary<string, string> Allowed = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Avalonia"] = "The UI framework.",
        ["Avalonia.Desktop"] = "Picks the Windows, macOS or X11 backend at startup.",
        ["Avalonia.Themes.Fluent"] = "Styles for the built-in controls.",
        ["Avalonia.Skia"] = "Avalonia's renderer on Skia.",
        ["Avalonia.HarfBuzz"] = "Avalonia's text shaping on HarfBuzz.",
        ["Avalonia.Win32"] = "The Windows backend.",
        ["Avalonia.Native"] = "The macOS backend.",
        ["Avalonia.X11"] = "The Linux backend.",
        ["Avalonia.Angle.Windows.Natives"] = "ANGLE, OpenGL ES on Direct3D, for the Windows backend.",
        ["MicroCom.Runtime"] = "In-process COM-style calls between Avalonia and its native Windows and macOS code.",
        ["Avalonia.FreeDesktop"] = "Linux desktop integration (theme, input methods, file dialogs) over the D-Bus session bus, which is local IPC.",
        ["Avalonia.FreeDesktop.AtSpi"] = "Linux screen-reader support; it only connects to the accessibility bus's Unix socket (UnixDomainSocketEndPoint).",
        ["Tmds.DBus.Protocol"] = "The D-Bus client behind Avalonia.FreeDesktop. It dials the bus address the user's session sets, a Unix socket on standard desktops; Carmine never sets one.",
        ["Avalonia.Remote.Protocol"] = "The XAML previewer's messages. Only Avalonia.DesignerSupport, which the IDE's previewer host loads, starts its TCP transport; app code can't name it, and the win-x64 NativeAOT build trims it out.",
        ["SkiaSharp"] = "Skia bindings for 2D drawing.",
        ["SkiaSharp.NativeAssets.Win32"] = SkiaNatives,
        ["SkiaSharp.NativeAssets.Linux"] = SkiaNatives,
        ["SkiaSharp.NativeAssets.macOS"] = SkiaNatives,
        ["SkiaSharp.NativeAssets.WebAssembly"] = SkiaNatives,
        ["HarfBuzzSharp"] = "HarfBuzz bindings for text shaping.",
        ["HarfBuzzSharp.NativeAssets.Win32"] = HarfBuzzNatives,
        ["HarfBuzzSharp.NativeAssets.Linux"] = HarfBuzzNatives,
        ["HarfBuzzSharp.NativeAssets.macOS"] = HarfBuzzNatives,
        ["HarfBuzzSharp.NativeAssets.WebAssembly"] = HarfBuzzNatives,
        ["CommunityToolkit.Mvvm"] = "Observable properties and commands, generated at compile time.",
        ["Avalonia.BuildServices"] = "Build only. Its AvaloniaStats target sends telemetry from the build machine, so Directory.Build.targets replaces it with an empty one; see Avalonia_build_telemetry_never_runs.",
        ["Microsoft.NET.ILLink.Tasks"] = "Build only: the SDK's trimmer and trim analyzers.",
        ["Microsoft.DotNet.ILCompiler"] = NativeAotCompiler,
        ["runtime.win-x64.Microsoft.DotNet.ILCompiler"] = NativeAotCompiler,
        ["runtime.linux-x64.Microsoft.DotNet.ILCompiler"] = NativeAotCompiler,
        ["runtime.osx-x64.Microsoft.DotNet.ILCompiler"] = NativeAotCompiler,
        ["runtime.osx-arm64.Microsoft.DotNet.ILCompiler"] = NativeAotCompiler,
    };

    internal static IEnumerable<Hit> Scan(string file, string text)
    {
        if (file == Updater)
        {
            return [];
        }

        var hits = SourceScan.Find(file, text, Apis);
        return file.EndsWith(".axaml", StringComparison.Ordinal)
            ? hits.Concat(SourceScan.Find(file, XmlnsAttribute().Replace(text, xmlns => new string(' ', xmlns.Length)), [RemoteAsset]))
            : hits;
    }

    internal static IEnumerable<string> Unlisted(string assetsJson) =>
        Repo.Libraries(assetsJson).Where(library => library.Type == "package" && !Allowed.ContainsKey(library.Name)).Select(library => library.Name);

    // MSBuild runs the last definition of a target, so an override only holds if it comes after the package's.
    internal static IEnumerable<string> TelemetryTargets(XDocument project)
    {
        var tasks = project.Descendants()
            .Where(element => element.Name.LocalName == "UsingTask" && ((string?)element.Attribute("AssemblyFile") ?? "").Contains("Avalonia.BuildServices", StringComparison.OrdinalIgnoreCase))
            .Select(element => ((string?)element.Attribute("TaskName") ?? "").Split('.')[^1])
            .ToHashSet();
        return project.Descendants()
            .Where(element => element.Name.LocalName == "Target")
            .GroupBy(target => (string?)target.Attribute("Name") ?? "")
            .Where(definitions => definitions.Last().Descendants().Any(step => tasks.Contains(step.Name.LocalName)))
            .Select(definitions => definitions.Key);
    }

    [Fact]
    public void Nothing_outside_the_updater_reaches_the_network_or_opens_a_URL() =>
        Assert.Empty(Repo.SourceFiles("src", ".cs", ".axaml").SelectMany(file => Scan(file, Repo.Read(file))).Select(hit => hit.ToString()));

    [Fact]
    public void Every_package_the_app_restores_is_on_the_allowlist() =>
        Assert.Empty(Unlisted(Repo.Assets("src/Carmine.Desktop")));

    [Fact]
    public async Task Avalonia_build_telemetry_never_runs()
    {
        var cancel = TestContext.Current.CancellationToken;
        var preprocessed = Path.GetTempFileName();
        try
        {
            var msbuild = new ProcessStartInfo("dotnet", ["msbuild", "src/Carmine.Desktop/Carmine.Desktop.csproj", $"-pp:{preprocessed}", "-nologo"])
            {
                WorkingDirectory = Repo.Root,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            // The CLI itself sends telemetry unless told not to.
            msbuild.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";
            msbuild.Environment["DOTNET_NOLOGO"] = "1";
            using var run = Process.Start(msbuild)!;
            var output = run.StandardOutput.ReadToEndAsync(cancel);
            var errors = run.StandardError.ReadToEndAsync(cancel);
            await run.WaitForExitAsync(cancel);
            if (run.ExitCode != 0)
            {
                Assert.Fail($"dotnet msbuild -pp exited with {run.ExitCode}:\n{await output}\n{await errors}");
            }

            Assert.Empty(TelemetryTargets(XDocument.Load(preprocessed)));
        }
        finally
        {
            File.Delete(preprocessed);
        }
    }

    [Theory]
    [InlineData("var client = new System.Net.Http.HttpClient();", "System.Net")]
    [InlineData("var client = new global::System.Net.Http.HttpClient();", "HTTP client")]
    [InlineData("using Web = System.Net.Http.HttpClient;", "System.Net")]
    [InlineData("using Http = System.Net.Http;", "System.Net")]
    [InlineData("global using System.Net.Http;", "System.Net")]
    [InlineData("global using Web = System.Net.Http.HttpClient;", "System.Net")]
    [InlineData("HttpClient client = new();", "HTTP client")]
    [InlineData("private readonly HttpClient _client = new();", "HTTP client")]
    [InlineData("using var invoker = new HttpMessageInvoker(new SocketsHttpHandler());", "HTTP client")]
    [InlineData("var request = WebRequest.Create(url);", "WebRequest or WebClient")]
    [InlineData("using var web = new WebClient();", "WebRequest or WebClient")]
    [InlineData("var listener = new HttpListener();", "HttpListener")]
    [InlineData("var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);", "socket")]
    [InlineData("using var ws = new ClientWebSocket();", "socket")]
    [InlineData("var tcp = new TcpClient(host, 443);", "TCP or UDP")]
    [InlineData("var server = new TcpListener(endpoint);", "TCP or UDP")]
    [InlineData("var udp = new UdpClient();", "TCP or UDP")]
    [InlineData("var transport = new BsonTcpTransport();", "TCP or UDP")]
    [InlineData("var addresses = Dns.GetHostAddresses(host);", "DNS")]
    [InlineData("var tls = new SslStream(inner);", "network stream")]
    [InlineData("await using var quic = await QuicConnection.ConnectAsync(options);", "QUIC")]
    [InlineData("new SmtpClient(host).Send(message);", "SMTP")]
    [InlineData("var reply = new Ping().Send(host);", "network information")]
    [InlineData("var online = NetworkInterface.GetIsNetworkAvailable();", "network information")]
    [InlineData("using var pipe = new NamedPipeClientStream(server, name);", "pipe stream")]
    [InlineData("using System.IO.Pipes;", "pipe stream")]
    [InlineData("using System.Xml.Linq;", "System.Xml")]
    [InlineData("using var hive = RegistryKey.OpenRemoteBaseKey(RegistryHive.CurrentUser, host);", "remote registry")]
    [InlineData("Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });", "process")]
    [InlineData("using var open = System.Diagnostics.Process.Start(\"xdg-open\", url);", "process")]
    [InlineData("await TopLevel.GetTopLevel(this)!.Launcher.LaunchUriAsync(uri);", "URL opener")]
    [InlineData("<HyperlinkButton NavigateUri=\"{Binding Link}\" />", "URL opener")]
    [InlineData("<NativeWebView Source=\"{Binding Page}\" />", "web view")]
    [InlineData("[DllImport(\"winhttp.dll\")] private static extern nint WinHttpOpen();", "native interop")]
    [InlineData("[LibraryImport(\"libcurl\")] private static partial int curl_easy_perform(nint handle);", "native interop")]
    [InlineData("var curl = NativeLibrary.Load(\"libcurl.so.4\");", "native interop")]
    [InlineData("var xhr = Activator.CreateInstance(Type.GetTypeFromProgID(\"MSXML2.XMLHTTP\")!);", "native interop")]
    [InlineData("using Avalonia.Remote.Protocol;", "Avalonia.Remote")]
    [InlineData("using var updates = new UpdateManager(source);", "Velopack update check")]
    [InlineData("using Velopack.Sources;", "Velopack update check")]
    public void Flags_each_network_and_URL_opening_spelling(string code, string ban) =>
        Assert.Contains(ban, Scan("src/Carmine.Desktop/Leak.cs", code).Select(hit => hit.Name));

    [Theory]
    [InlineData("// Set-Cookie attributes such as Path and Expires; HttpOnly and Secure stay.")]
    [InlineData("var id = Environment.ProcessId;")]
    [InlineData("private static string Preprocess(string text) => text;")]
    [InlineData("var sample = \"curl https://api.example.com/v1/items\";")]
    [InlineData("<TextBlock Text=\"LOCAL · IN MEMORY ONLY\" />")]
    public void Lets_lookalikes_through(string code) =>
        Assert.Empty(Scan("src/Carmine.Desktop/Fine.cs", code));

    [Fact]
    public void Reports_the_file_and_line() =>
        Assert.Equal(
            ["src/Carmine.Desktop/Leak.cs:3  HTTP client"],
            Scan("src/Carmine.Desktop/Leak.cs", "namespace Carmine.Desktop;\n\ninternal sealed class Leak { private readonly HttpClient _client = new(); }\n").Select(hit => hit.ToString()));

    [Fact]
    public void Allows_network_code_in_the_updater_only()
    {
        const string code = """
            using Velopack.Sources;

            var updates = new UpdateManager(new GithubSource(url, null, false));
            var client = new System.Net.Http.HttpClient();
            """;

        Assert.Empty(Scan(Updater, code));
        Assert.NotEmpty(Scan("src/Carmine.Desktop/Services/Updater.cs", code));
        Assert.NotEmpty(Scan("src/Carmine.Core/Services/Updates.cs", code));
    }

    private const string Window = """
        <Window xmlns="https://github.com/avaloniaui"
                xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
          <Image Source="avares://CarmineWorkbench/Assets/mark.png" />
        </Window>
        """;

    [Fact]
    public void Allows_xmlns_and_avares_URIs_in_AXAML() =>
        Assert.Empty(Scan("src/Carmine.Desktop/Views/Fine.axaml", Window));

    [Theory]
    [InlineData("<Image Source=\"https://cdn.example.com/mark.png\" />")]
    [InlineData("<TextBlock FontFamily=\"https://fonts.example.com/inter.ttf#Inter\" />")]
    [InlineData("<Image Source=\"file://files.example.com/share/mark.png\" />")]
    [InlineData(@"<Image Source=""\\files.example.com\share\mark.png"" />")]
    public void Flags_a_remote_asset_in_AXAML(string element) =>
        Assert.Equal(
            ["src/Carmine.Desktop/Views/Leak.axaml:3  URI outside the app"],
            Scan("src/Carmine.Desktop/Views/Leak.axaml", Window.Replace("<Image Source=\"avares://CarmineWorkbench/Assets/mark.png\" />", element, StringComparison.Ordinal)).Select(hit => hit.ToString()));

    [Fact]
    public void Rejects_a_package_missing_from_the_allowlist()
    {
        const string assets = """
            {
              "libraries": {
                "Avalonia/12.1.3": { "type": "package" },
                "Contoso.Telemetry/1.0.0": { "type": "package" },
                "Carmine.Core/0.0.0": { "type": "project" }
              }
            }
            """;

        Assert.Equal(["Contoso.Telemetry"], Unlisted(assets));
    }

    [Fact]
    public void Flags_build_telemetry_unless_an_empty_target_comes_last()
    {
        const string package = """
            <UsingTask TaskName="AvaloniaStatsTask" AssemblyFile="tools\Avalonia.BuildServices.dll" />
            <Target Name="AvaloniaStats" BeforeTargets="CoreCompile"><AvaloniaStatsTask ProjectName="Carmine" /></Target>
            """;
        const string empty = """<Target Name="AvaloniaStats" />""";

        Assert.Equal(["AvaloniaStats"], TelemetryTargets(XDocument.Parse($"<Project>{package}</Project>")));
        Assert.Equal(["AvaloniaStats"], TelemetryTargets(XDocument.Parse($"<Project>{empty}{package}</Project>")));
        Assert.Empty(TelemetryTargets(XDocument.Parse($"<Project>{package}{empty}</Project>")));
    }
}
