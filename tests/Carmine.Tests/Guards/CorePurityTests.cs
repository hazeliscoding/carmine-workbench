using System.Xml.Linq;

namespace Carmine.Tests.Guards;

public sealed class CorePurityTests
{
    private const string Core = "src/Carmine.Core";

    // As in NetworkGuardTests, comments and strings count.
    private static readonly Ban[] Effects =
    [
        new("System.IO", @"\bSystem\.IO\b"),
        // System.IO is an implicit using, so these classes need no using line. Matching only a member access
        // (Path.Combine) keeps prose such as "attributes such as Path and Expires" out.
        StaticClass("File"),
        StaticClass("Directory"),
        StaticClass("Path"),
        StaticClass("Console"),
        StaticClass("Environment"),
        new("file or stream type", @"\b(?:FileStream|FileInfo|DirectoryInfo|DriveInfo|FileSystemInfo|FileSystemWatcher|StreamReader|StreamWriter|BinaryReader|BinaryWriter|RandomAccess|SafeFileHandle|MemoryMappedFile|IsolatedStorage\w*)\b"),
        new("System.Net", @"\bSystem\.Net\b"),
        new("process", @"\bProcess(?:StartInfo)?\b"),
        new("native interop", @"\bSystem\.Runtime\.InteropServices\b|\b(?:DllImport|LibraryImport|NativeLibrary|ComImport|Marshal)\b"),
        new("Microsoft.Win32", @"\bMicrosoft\.Win32\b"),
        new("UI", @"\bAvalonia\b|\bSystem\.Windows\b"),
        new("code loading", @"\bSystem\.Reflection\.Emit\b|\bSystem\.Runtime\.Loader\b|\bAssemblyLoadContext\b|\bAssembly\s*\.\s*Load\w*|\bActivator\b|\bType\s*\.\s*GetType\b"),
    ];

    // The SDK adds it to every IsAotCompatible project for the trim analyzers; nothing of it ships.
    private static readonly string[] SdkPackages = ["Microsoft.NET.ILLink.Tasks"];

    private static Ban StaticClass(string name) => new(name, $@"(?<![\w.]){name}\s*\.[A-Z]");

    internal static IEnumerable<Hit> Scan(string file, string text) => SourceScan.Find(file, text, Effects);

    internal static IEnumerable<string> Restored(string assetsJson) =>
        Repo.Libraries(assetsJson).Where(library => !SdkPackages.Contains(library.Name)).Select(library => library.Name);

    internal static IEnumerable<string> References(string project) =>
        XDocument.Parse(project).Descendants()
            .Where(element => element.Name.LocalName is "PackageReference" or "ProjectReference" or "Reference" or "FrameworkReference")
            .Select(element => $"{element.Name.LocalName} {element.Attribute("Include")?.Value}");

    [Fact]
    public void The_engine_project_references_no_package_or_project() =>
        Assert.Empty(References(Repo.Read($"{Core}/Carmine.Core.csproj")));

    // Directory.Build.props or Directory.Packages.props could still add a package to every project.
    [Fact]
    public void The_engine_restores_no_package_or_project() =>
        Assert.Empty(Restored(Repo.Assets(Core)));

    [Fact]
    public void No_engine_file_does_IO_interop_or_UI() =>
        Assert.Empty(Repo.SourceFiles(Core, ".cs").SelectMany(file => Scan(file, Repo.Read(file))).Select(hit => hit.ToString()));

    [Theory]
    [InlineData("using System.IO;", "System.IO")]
    [InlineData("var text = System.IO.File.ReadAllText(name);", "System.IO")]
    [InlineData("global using static System.IO.File;", "System.IO")]
    [InlineData("using Disk = System.IO.File;", "System.IO")]
    [InlineData("var text = File.ReadAllText(name);", "File")]
    [InlineData("var text = File\n    .ReadAllText(name);", "File")]
    [InlineData("Directory.CreateDirectory(folder);", "Directory")]
    [InlineData("var full = Path.GetFullPath(name);", "Path")]
    [InlineData("Console.Error.WriteLine(input);", "Console")]
    [InlineData("var home = Environment.GetEnvironmentVariable(\"HOME\");", "Environment")]
    [InlineData("var lines = text.Split(Environment.NewLine);", "Environment")]
    [InlineData("using var log = new StreamWriter(name);", "file or stream type")]
    [InlineData("FileStream log = new(name, FileMode.Create);", "file or stream type")]
    [InlineData("var client = new System.Net.Http.HttpClient();", "System.Net")]
    [InlineData("System.Diagnostics.Process.Start(\"curl\");", "process")]
    [InlineData("using Run = System.Diagnostics.Process;", "process")]
    [InlineData("[DllImport(\"libc\")] private static extern int getpid();", "native interop")]
    [InlineData("[LibraryImport(\"libc\")] private static partial int getpid();", "native interop")]
    [InlineData("using System.Runtime.InteropServices;", "native interop")]
    [InlineData("var buffer = Marshal.AllocHGlobal(16);", "native interop")]
    [InlineData("using Microsoft.Win32;", "Microsoft.Win32")]
    [InlineData("using Avalonia.Controls;", "UI")]
    [InlineData("using System.Windows.Input;", "UI")]
    [InlineData("using System.Reflection.Emit;", "code loading")]
    [InlineData("var plugin = Assembly.LoadFrom(name);", "code loading")]
    [InlineData("var context = new AssemblyLoadContext(name);", "code loading")]
    [InlineData("var rule = Activator.CreateInstance(Type.GetType(name)!);", "code loading")]
    public void Flags_each_effect_spelling(string code, string ban) =>
        Assert.Contains(ban, Scan($"{Core}/Sanitize/Leak.cs", code).Select(hit => hit.Name));

    [Fact]
    public void Lets_engine_code_through()
    {
        const string engine = """
            using System.Text;
            using System.Text.Json;
            using System.Text.RegularExpressions;

            namespace Carmine.Core.Sanitize.Rules;

            // Set-Cookie attributes such as Path and Expires. The comma in "Expires=Thu, 24 Sep …" comes before a digit.
            internal static partial class CookiesRule
            {
                [GeneratedRegex(@"[ \t]*;[ \t]*Path=/", RegexOptions.CultureInvariant)]
                private static partial Regex Attributes();

                public static string Label(string kind, int number) => new StringBuilder().Append('<').Append(kind).Append('#').Append(number).Append('>').ToString();

                public static int Depth(Finding finding) => finding.Path.Split('/').Length;

                public static JsonElement Claims(string json) => JsonDocument.Parse(json).RootElement.Clone();
            }
            """;

        Assert.Empty(Scan($"{Core}/Sanitize/Rules/Cookies/CookiesRule.cs", engine));
    }

    [Theory]
    [InlineData("""<ItemGroup><PackageReference Include="Contoso.Json" /></ItemGroup>""", "PackageReference Contoso.Json")]
    [InlineData("""<ItemGroup><ProjectReference Include="..\Carmine.Desktop\Carmine.Desktop.csproj" /></ItemGroup>""", @"ProjectReference ..\Carmine.Desktop\Carmine.Desktop.csproj")]
    [InlineData("""<ItemGroup><FrameworkReference Include="Microsoft.AspNetCore.App" /></ItemGroup>""", "FrameworkReference Microsoft.AspNetCore.App")]
    public void Flags_a_reference_in_the_engine_project(string items, string reference) =>
        Assert.Equal([reference], References($"""<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><IsAotCompatible>true</IsAotCompatible></PropertyGroup>{items}</Project>"""));

    [Fact]
    public void Flags_a_package_or_project_in_the_engine_restore()
    {
        const string assets = """
            {
              "libraries": {
                "Microsoft.NET.ILLink.Tasks/10.0.10": { "type": "package" },
                "Contoso.Json/1.0.0": { "type": "package" },
                "Carmine.Desktop/0.0.0": { "type": "project" }
              }
            }
            """;

        Assert.Equal(["Contoso.Json", "Carmine.Desktop"], Restored(assets));
    }
}
