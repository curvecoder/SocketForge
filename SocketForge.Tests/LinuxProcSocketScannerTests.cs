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

    [Fact]
    public async Task ScanSocketsAsync_WhenTcpLocalPortMatchesBoundUdpPort_ResolvesTcpFlowAsOutbound()
    {
        // Arrange: UDP bound on 0.0.0.0:50000 and a TCP connection from 192.168.1.20:50000 to 192.168.1.10:443
        WriteTable("udp", Line("00000000:C350", "00000000:0000", "07", 5001));
        WriteTable("tcp", Line("1401A8C0:C350", "0A01A8C0:01BB", "01", 5002));
        var scanner = new LinuxProcSocketScanner(new StubProcessInspector(), _procRoot);

        // Act
        var connections = await scanner.ScanSocketsAsync(CancellationToken.None);

        // Assert
        connections.Single(c => c.Protocol == SocketTransportProtocol.Tcp)
            .Direction.Should().Be(SocketFlowDirection.Outbound);
    }

    [Fact]
    public async Task ScanSocketsAsync_WhenTcpPortIsOnlyHeldByClosedSocket_ResolvesTcpFlowAsOutbound()
    {
        // Arrange: a closed TCP socket (07) and a TCP connection on the same local port 50001 to 192.168.1.10:443
        WriteTable(
            "tcp",
            Line("1401A8C0:C351", "0A01A8C0:01BB", "07", 5003),
            Line("1401A8C0:C351", "0A01A8C0:01BB", "01", 5004));
        var scanner = new LinuxProcSocketScanner(new StubProcessInspector(), _procRoot);

        // Act
        var connections = await scanner.ScanSocketsAsync(CancellationToken.None);

        // Assert
        connections.Single(c => c.State == "Established")
            .Direction.Should().Be(SocketFlowDirection.Outbound);
    }

    [Fact]
    public async Task ScanSocketsAsync_WhenConnectedUdpLocalPortMatchesTcpListener_ResolvesUdpFlowAsOutbound()
    {
        // Arrange: TCP listening on port 50002 and a connected UDP socket from port 50002 to 192.168.1.1:53
        WriteTable("tcp", Line("00000000:C352", "00000000:0000", "0A", 5005));
        WriteTable("udp", Line("1401A8C0:C352", "0101A8C0:0035", "01", 5006));
        var scanner = new LinuxProcSocketScanner(new StubProcessInspector(), _procRoot);

        // Act
        var connections = await scanner.ScanSocketsAsync(CancellationToken.None);

        // Assert
        connections.Single(c => c.Protocol == SocketTransportProtocol.Udp)
            .Direction.Should().Be(SocketFlowDirection.Outbound);
    }

    [Fact]
    public async Task ScanSocketsAsync_WhenConnectedUdpLocalPortIsBoundUnconnected_ResolvesUdpFlowAsInbound()
    {
        // Arrange: UDP service bound on 0.0.0.0:5353 and a connected UDP socket on 5353 talking to 192.168.1.30:1900,
        // a pair that the port heuristics alone would classify as outbound
        WriteTable(
            "udp",
            Line("00000000:14E9", "00000000:0000", "07", 5007),
            Line("1401A8C0:14E9", "1E01A8C0:076C", "01", 5008));
        var scanner = new LinuxProcSocketScanner(new StubProcessInspector(), _procRoot);

        // Act
        var connections = await scanner.ScanSocketsAsync(CancellationToken.None);

        // Assert
        connections.Single(c => c.RemoteEndpoint.Port == 1900)
            .Direction.Should().Be(SocketFlowDirection.Inbound);
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
