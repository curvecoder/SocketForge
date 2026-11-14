using System.Net;
using System.Net.Sockets;
using AwesomeAssertions;
using ProcessForge.Contracts;
using ProcessForge.Models;
using SocketForge.Models;
using SocketForge.Windows;
using Xunit;

namespace SocketForge.Tests;

public sealed class WindowsSocketScannerTests
{
    [Fact]
    public async Task ScanSocketsAsync_WhenIpv6ListenerIsOpen_ReturnsListeningRow()
    {
        // Arrange
        if (!OperatingSystem.IsWindows() || !Socket.OSSupportsIPv6)
        {
            return;
        }

        using var listener = new TcpListener(IPAddress.IPv6Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var scanner = new WindowsSocketScanner(new StubProcessInspector());

        // Act
        var connections = await scanner.ScanSocketsAsync(CancellationToken.None);

        // Assert
        connections.Should().Contain(c =>
            c.Protocol == SocketTransportProtocol.Tcp &&
            c.Direction == SocketFlowDirection.Listening &&
            c.LocalEndpoint == new SocketEndpoint(IPAddress.IPv6Loopback, port));
    }

    [Theory]
    [InlineData(11u, 0, true)]
    [InlineData(11u, 4321, false)]
    [InlineData(5u, 0, false)]
    [InlineData(2u, 0, false)]
    public void IsOwnerlessTimeWait_WhenStateAndOwnerVary_FlagsOnlyTimeWaitWithoutOwner(uint state, int owningPid, bool expected)
    {
        // Arrange: Windows hands TIME_WAIT sockets to pid 0 once their process has released them
        var row = new NativeSocketRow(
            new SocketEndpoint(IPAddress.Parse("192.168.1.20"), 50000),
            new SocketEndpoint(IPAddress.Parse("192.168.1.10"), 443),
            state,
            owningPid);

        // Act
        var result = WindowsSocketScanner.IsOwnerlessTimeWait(row);

        // Assert
        result.Should().Be(expected);
    }

    private sealed class StubProcessInspector : IProcessInspector
    {
        public Task<ProcessMetadata> ResolveProcessAsync(int processId, CancellationToken cancellationToken = default) =>
            Task.FromResult(new ProcessMetadata(processId, "stub", @"C:\tools\stub.exe", string.Empty, string.Empty, "user"));
    }
}
