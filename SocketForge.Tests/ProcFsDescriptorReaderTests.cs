using AwesomeAssertions;
using SocketForge.Linux;
using Xunit;

namespace SocketForge.Tests;

public sealed class ProcFsDescriptorReaderTests : IDisposable
{
    private readonly string _procRoot = Path.Combine(Path.GetTempPath(), "socketforge_fd_" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_procRoot))
        {
            Directory.Delete(_procRoot, recursive: true);
        }
    }

    [Fact]
    public void ListProcessIds_WhenRootHoldsNumericAndNamedDirectories_ReturnsOnlyProcessIds()
    {
        // Arrange
        Directory.CreateDirectory(Path.Combine(_procRoot, "42"));
        Directory.CreateDirectory(Path.Combine(_procRoot, "7"));
        Directory.CreateDirectory(Path.Combine(_procRoot, "net"));
        File.WriteAllText(Path.Combine(_procRoot, "99"), string.Empty);
        var reader = new ProcFsDescriptorReader(_procRoot);

        // Act
        var processIds = reader.ListProcessIds();

        // Assert
        processIds.Should().BeEquivalentTo([7, 42]);
    }

    [Fact]
    public void ListProcessIds_WhenRootDoesNotExist_ReturnsEmptyList()
    {
        // Arrange
        var reader = new ProcFsDescriptorReader(_procRoot);

        // Act
        var processIds = reader.ListProcessIds();

        // Assert
        processIds.Should().BeEmpty();
    }

    [Fact]
    public void ReadSocketDescriptors_WhenProcessHasNoFdDirectory_ReturnsEmptyList()
    {
        // Arrange
        Directory.CreateDirectory(Path.Combine(_procRoot, "42"));
        var reader = new ProcFsDescriptorReader(_procRoot);

        // Act
        var descriptors = reader.ReadSocketDescriptors(42);

        // Assert
        descriptors.Should().BeEmpty();
    }

    [Fact]
    public void ReadSocketDescriptors_WhenDescriptorsAreNotSocketLinks_ReturnsEmptyList()
    {
        // Arrange
        var fdDirectory = Path.Combine(_procRoot, "42", "fd");
        Directory.CreateDirectory(fdDirectory);
        File.WriteAllText(Path.Combine(fdDirectory, "0"), string.Empty);
        var reader = new ProcFsDescriptorReader(_procRoot);

        // Act
        var descriptors = reader.ReadSocketDescriptors(42);

        // Assert
        descriptors.Should().BeEmpty();
    }

    [Fact]
    public void ReadSocketInode_WhenDescriptorWasClosed_ReturnsNull()
    {
        // Arrange
        var reader = new ProcFsDescriptorReader(_procRoot);

        // Act
        var inode = reader.ReadSocketInode(Path.Combine(_procRoot, "42", "fd", "3"));

        // Assert
        inode.Should().BeNull();
    }
}
