using System.Text.Json;

namespace Carmine.Tests.Guards;

internal static class Repo
{
    public static string Root { get; } = FindRoot();

    private static string FindRoot()
    {
        for (var folder = new DirectoryInfo(AppContext.BaseDirectory); folder is not null; folder = folder.Parent)
        {
            if (File.Exists(Path.Combine(folder.FullName, "Carmine.slnx")))
            {
                return folder.FullName;
            }
        }

        throw new InvalidOperationException($"No Carmine.slnx above {AppContext.BaseDirectory}.");
    }

    public static IEnumerable<string> SourceFiles(string folder, params string[] extensions) =>
        Directory.EnumerateFiles(Path.Combine(Root, folder), "*", SearchOption.AllDirectories)
            .Select(file => Path.GetRelativePath(Root, file).Replace('\\', '/'))
            .Where(file => extensions.Contains(Path.GetExtension(file)) && !file.Split('/').Any(part => part is "bin" or "obj"))
            .Order(StringComparer.Ordinal);

    public static string Read(string file) => File.ReadAllText(Path.Combine(Root, file));

    public static string Assets(string project)
    {
        var path = Path.Combine(Root, project, "obj", "project.assets.json");
        return File.Exists(path) ? File.ReadAllText(path) : throw new InvalidOperationException($"{path} is missing. Run dotnet restore first.");
    }

    public static List<(string Name, string Type)> Libraries(string assetsJson)
    {
        using var assets = JsonDocument.Parse(assetsJson);
        return [.. assets.RootElement.GetProperty("libraries").EnumerateObject()
            .Select(library => (library.Name[..library.Name.IndexOf('/')], library.Value.GetProperty("type").GetString() ?? ""))];
    }
}
