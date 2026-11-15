using AwesomeAssertions;
using SocketForge.Linux;
using Xunit;

namespace SocketForge.Tests;

public sealed class SocketOwnerTableTests
{
    private readonly FakeProcDescriptors _proc = new();

    [Fact]
    public void ResolveOwners_WhenOwnersStillHoldTheirSockets_DoesNotReadDescriptorDirectoriesAgain()
    {
        // Arrange
        _proc.Hold(100, "3", "1001").Hold(200, "4", "2001").Hold(300, "5", "3001");
        var table = new SocketOwnerTable(_proc);
        table.ResolveOwners(Inodes("1001", "2001"), CancellationToken.None);
        _proc.ForgetReads();

        // Act
        var owners = table.ResolveOwners(Inodes("1001", "2001"), CancellationToken.None);

        // Assert
        owners.Should().Equal(new Dictionary<string, int> { ["1001"] = 100, ["2001"] = 200 });
        _proc.ReadProcessIds.Should().BeEmpty();
    }

    [Fact]
    public void ResolveOwners_WhenSocketHasNoReadableOwner_DoesNotSearchItAgain()
    {
        // Arrange: inode 9001 belongs to a process whose descriptors cannot be read
        _proc.Hold(100, "3", "1001");
        var table = new SocketOwnerTable(_proc);
        table.ResolveOwners(Inodes("1001", "9001"), CancellationToken.None);
        _proc.ForgetReads();

        // Act
        var owners = table.ResolveOwners(Inodes("1001", "9001"), CancellationToken.None);

        // Assert
        owners.Should().Equal(new Dictionary<string, int> { ["1001"] = 100 });
        _proc.ReadProcessIds.Should().BeEmpty();
    }

    [Fact]
    public void ResolveOwners_WhenNewProcessAppears_ReadsOnlyThatProcess()
    {
        // Arrange
        _proc.Hold(100, "3", "1001").Hold(200, "4", "2001");
        var table = new SocketOwnerTable(_proc);
        table.ResolveOwners(Inodes("1001", "2001"), CancellationToken.None);
        _proc.Hold(300, "7", "3001");
        _proc.ForgetReads();

        // Act
        var owners = table.ResolveOwners(Inodes("1001", "2001", "3001"), CancellationToken.None);

        // Assert
        owners.Should().Equal(new Dictionary<string, int> { ["1001"] = 100, ["2001"] = 200, ["3001"] = 300 });
        _proc.ReadProcessIds.Should().Equal(300);
    }

    [Fact]
    public void ResolveOwners_WhenSeveralProcessesHoldTheSameSocket_AttributesItToTheHighestPid()
    {
        // Arrange: 100 and 200 share inode 5001 after a fork, as a full walk of /proc would see them
        _proc.Hold(100, "3", "5001").Hold(200, "3", "5001");
        var table = new SocketOwnerTable(_proc);

        // Act
        var owners = table.ResolveOwners(Inodes("5001"), CancellationToken.None);

        // Assert
        owners.Should().Equal(new Dictionary<string, int> { ["5001"] = 200 });
    }

    [Fact]
    public void ResolveOwners_WhenOwnerClosedSocketStillHeldByAnotherProcess_AttributesItToTheRemainingHolder()
    {
        // Arrange: 200 owns the shared inode 5001, then closes it
        _proc.Hold(100, "3", "5001").Hold(200, "3", "5001");
        var table = new SocketOwnerTable(_proc);
        table.ResolveOwners(Inodes("5001"), CancellationToken.None);
        _proc.Close(200, "3");

        // Act
        var owners = table.ResolveOwners(Inodes("5001"), CancellationToken.None);

        // Assert
        owners.Should().Equal(new Dictionary<string, int> { ["5001"] = 100 });
    }

    [Fact]
    public void ResolveOwners_WhenOwnerExitedAndItsPidWasReused_DoesNotAttributeTheSocketToTheNewProcess()
    {
        // Arrange: 100 exits, 200 still holds 5001, and a new process takes pid 100 with other sockets
        _proc.Hold(100, "3", "5001").Hold(200, "8", "5001");
        var table = new SocketOwnerTable(_proc);
        table.ResolveOwners(Inodes("5001"), CancellationToken.None);
        _proc.Exit(100).Hold(100, "3", "6001");

        // Act
        var owners = table.ResolveOwners(Inodes("5001", "6001"), CancellationToken.None);

        // Assert
        owners.Should().Equal(new Dictionary<string, int> { ["5001"] = 200, ["6001"] = 100 });
    }

    [Fact]
    public void ResolveOwners_WhenOwnerExitedAndNoProcessHoldsTheSocket_ReportsNoOwner()
    {
        // Arrange
        _proc.Hold(100, "3", "5001").Hold(200, "4", "2001");
        var table = new SocketOwnerTable(_proc);
        table.ResolveOwners(Inodes("5001", "2001"), CancellationToken.None);
        _proc.Exit(100);

        // Act
        var owners = table.ResolveOwners(Inodes("5001", "2001"), CancellationToken.None);

        // Assert
        owners.Should().Equal(new Dictionary<string, int> { ["2001"] = 200 });
    }

    [Fact]
    public void ResolveOwners_WhenExistingProcessOpensNewSocket_FindsItsOwner()
    {
        // Arrange
        _proc.Hold(100, "3", "1001").Hold(200, "4", "2001");
        var table = new SocketOwnerTable(_proc);
        table.ResolveOwners(Inodes("1001", "2001"), CancellationToken.None);
        _proc.Hold(200, "9", "2002");

        // Act
        var owners = table.ResolveOwners(Inodes("1001", "2001", "2002"), CancellationToken.None);

        // Assert
        owners.Should().Equal(new Dictionary<string, int> { ["1001"] = 100, ["2001"] = 200, ["2002"] = 200 });
    }

    [Fact]
    public void ResolveOwners_WhenDescriptorNumberIsReusedForAnotherSocket_DoesNotKeepTheOldOwner()
    {
        // Arrange: 200 owns the shared inode 5001 on fd 3, closes it and opens a new socket on fd 3
        _proc.Hold(100, "3", "5001").Hold(200, "3", "5001");
        var table = new SocketOwnerTable(_proc);
        table.ResolveOwners(Inodes("5001"), CancellationToken.None);
        _proc.Hold(200, "3", "7001");

        // Act
        var owners = table.ResolveOwners(Inodes("5001", "7001"), CancellationToken.None);

        // Assert
        owners.Should().Equal(new Dictionary<string, int> { ["5001"] = 100, ["7001"] = 200 });
    }

    [Fact]
    public void ResolveOwners_WhenNewProcessInheritsSocketWithoutReadableOwner_AttributesItToThatProcess()
    {
        // Arrange: inode 9001 is held only by an unreadable process, then handed to a new readable process
        _proc.Hold(100, "3", "1001");
        var table = new SocketOwnerTable(_proc);
        table.ResolveOwners(Inodes("1001", "9001"), CancellationToken.None);
        _proc.Hold(400, "3", "9001");

        // Act
        var owners = table.ResolveOwners(Inodes("1001", "9001"), CancellationToken.None);

        // Assert
        owners.Should().Equal(new Dictionary<string, int> { ["1001"] = 100, ["9001"] = 400 });
    }

    [Fact]
    public void ResolveOwners_WhenLowerPidHolderIsReadAgain_KeepsTheSharedSocketOnTheHighestPid()
    {
        // Arrange: 100 and 200 share 5001; 100 then opens 1002, which makes the table read 100 again
        _proc.Hold(100, "3", "5001").Hold(200, "3", "5001");
        var table = new SocketOwnerTable(_proc);
        table.ResolveOwners(Inodes("5001"), CancellationToken.None);
        _proc.Hold(100, "4", "1002");
        table.ResolveOwners(Inodes("5001", "1002"), CancellationToken.None);

        // Act
        var owners = table.ResolveOwners(Inodes("5001", "1002"), CancellationToken.None);

        // Assert
        owners.Should().Equal(new Dictionary<string, int> { ["5001"] = 200, ["1002"] = 100 });
    }

    [Fact]
    public void ResolveOwners_WhenProcessListingFails_KeepsConfirmedOwners()
    {
        // Arrange
        _proc.Hold(100, "3", "1001");
        var table = new SocketOwnerTable(_proc);
        table.ResolveOwners(Inodes("1001"), CancellationToken.None);
        _proc.FailListing = true;

        // Act
        var owners = table.ResolveOwners(Inodes("1001"), CancellationToken.None);

        // Assert
        owners.Should().Equal(new Dictionary<string, int> { ["1001"] = 100 });
    }

    [Fact]
    public void ResolveOwners_WhenUnownedSocketIsLaterHeldByKnownProcess_FindsItWithinTheRetryPeriod()
    {
        // Arrange: 9001 has no readable holder, then reaches the known process 100 (descriptor passing)
        _proc.Hold(100, "3", "1001");
        var table = new SocketOwnerTable(_proc);
        table.ResolveOwners(Inodes("1001", "9001"), CancellationToken.None);
        _proc.Hold(100, "4", "9001");

        // Act
        IReadOnlyDictionary<string, int> owners = new Dictionary<string, int>();
        for (var scan = 0; scan < SocketOwnerTable.UnownedRetryPeriod; scan++)
        {
            owners = table.ResolveOwners(Inodes("1001", "9001"), CancellationToken.None);
        }

        // Assert
        owners.Should().Equal(new Dictionary<string, int> { ["1001"] = 100, ["9001"] = 100 });
    }

    [Fact]
    public void ResolveOwners_WhenCancelled_ThrowsOperationCanceledException()
    {
        // Arrange
        _proc.Hold(100, "3", "1001");
        var table = new SocketOwnerTable(_proc);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        // Act
        var act = () => table.ResolveOwners(Inodes("1001"), cancellation.Token);

        // Assert
        act.Should().Throw<OperationCanceledException>();
    }

    private static HashSet<string> Inodes(params string[] inodes) => new(inodes, StringComparer.Ordinal);
}
