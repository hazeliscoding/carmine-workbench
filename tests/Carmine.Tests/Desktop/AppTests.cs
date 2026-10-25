using Carmine.Desktop;

namespace Carmine.Tests.Desktop;

public class AppTests
{
    // avares:// resource URIs and the published executable both carry this name.
    [Fact]
    public void The_desktop_assembly_is_named_CarmineWorkbench() =>
        Assert.Equal("CarmineWorkbench", typeof(App).Assembly.GetName().Name);
}
