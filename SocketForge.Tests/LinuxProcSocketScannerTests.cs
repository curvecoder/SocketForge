using System.Globalization;
using System.Net;
using System.Net.Sockets;
using AwesomeAssertions;
using ProcessForge.Contracts;
using ProcessForge.Models;
using SocketForge.Linux;
using SocketForge.Models;
using Xunit;

namespace SocketForge.Tests;

public sealed class LinuxProcSocketScannerTests : IDisposable
{
    private const string Header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
    private const string LineTail = " 00000000:00000000 00:00000000 00000000  1000        0 {0} 1 0000000000000000 100 0 0 10 0\n";

    private readonly string _procRoot = Path.Combine(Path.GetTempPath(), "socketforge_linux_" + Guid.NewGuid().ToString("N"));

    public LinuxProcSocketScannerTests()
    {
        Directory.CreateDirectory(Path.Combine(_procRoot, "net"));
    }

    public void Dispose()
    {
        if (Directory.Exists(_procRoot))
        {
            Directory.Delete(_procRoot, recursive: true);
        }
    }

    [Fact]
    public async Task ScanSocketsAsync_WhenDualStackSocketSeesIpv4Peer_ReturnsIpv4Addresses()
    {
        // Arrange: ::ffff:192.168.1.20:50000 connected to ::ffff:192.168.1.10:443
        WriteTable("tcp6", Line("0000000000000000FFFF00001401A8C0:C350", "0000000000000000FFFF00000A01A8C0:01BB", "01", 4242));
        var scanner = new LinuxProcSocketScanner(new StubProcessInspector(), _procRoot);

        // Act
        var connections = await scanner.ScanSocketsAsync(CancellationToken.None);

        // Assert
        var connection = connections.Should().ContainSingle().Subject;
        connection.LocalEndpoint.Should().Be(new SocketEndpoint(IPAddress.Parse("192.168.1.20"), 50000));
        connection.RemoteEndpoint.Should().Be(new SocketEndpoint(IPAddress.Parse("192.168.1.10"), 443));
        connection.RemoteEndpoint.Address.AddressFamily.Should().Be(AddressFamily.InterNetwork);
    }

    [Fact]
    public async Task ScanSocketsAsync_WhenSocketIsNativeIpv6_KeepsIpv6Address()
    {
        // Arrange: fd00::1:443 listening on the IPv6 table
        WriteTable("tcp6", Line("000000FD000000000000000001000000:01BB", "00000000000000000000000000000000:0000", "0A", 4243));
        var scanner = new LinuxProcSocketScanner(new StubProcessInspector(), _procRoot);

        // Act
        var connections = await scanner.ScanSocketsAsync(CancellationToken.None);

        // Assert
        connections.Should().ContainSingle()
            .Which.LocalEndpoint.Should().Be(new SocketEndpoint(IPAddress.Parse("fd00::1"), 443));
    }

    [Fact]
    public async Task ScanSocketsAsync_WhenDualStackUdpSocketListensOnMappedAnyAddress_ReturnsIpv4AnyListener()
    {
        // Arrange: ::ffff:0.0.0.0:53 bound on the UDP IPv6 table
        WriteTable("udp6", Line("0000000000000000FFFF000000000000:0035", "00000000000000000000000000000000:0000", "07", 4244));
        var scanner = new LinuxProcSocketScanner(new StubProcessInspector(), _procRoot);

        // Act
        var connections = await scanner.ScanSocketsAsync(CancellationToken.None);

        // Assert
        var connection = connections.Should().ContainSingle().Subject;
        connection.LocalEndpoint.Should().Be(new SocketEndpoint(IPAddress.Any, 53));
        connection.Direction.Should().Be(SocketFlowDirection.Listening);
    }

    private static string Line(string local, string remote, string state, int inode) =>
        $"   0: {local} {remote} {state}" + string.Format(CultureInfo.InvariantCulture, LineTail, inode);

    private void WriteTable(string name, params string[] lines) =>
        File.WriteAllText(Path.Combine(_procRoot, "net", name), Header + string.Concat(lines));

    private sealed class StubProcessInspector : IProcessInspector
    {
        public Task<ProcessMetadata> ResolveProcessAsync(int processId, CancellationToken cancellationToken = default) =>
            Task.FromResult(new ProcessMetadata(processId, "stub", "/usr/bin/stub", "", "", "user"));
    }
}
