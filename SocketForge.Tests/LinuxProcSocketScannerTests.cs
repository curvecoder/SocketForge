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

    [Theory]
    [InlineData("0100007F:ZZZZ", "00000000:0000")]
    [InlineData("ZZZZZZZZ:0050", "00000000:0000")]
    [InlineData("0000000000000000ZZZZ00000100007F:0050", "00000000000000000000000000000000:0000")]
    [InlineData("0100007F:0050", "0A01A8C0:FFFFFFFF")]
    [InlineData("0100007F:0050", "0A01A8C0:10000")]
    public async Task ScanSocketsAsync_WhenLineHasUnparseableEndpoint_SkipsOnlyThatLine(string local, string remote)
    {
        // Arrange
        // One unexpected line followed by a valid listener on 192.168.1.20:22.
        WriteTable("tcp", Line(local, remote, "01", 6001), Line("1401A8C0:0016", "00000000:0000", "0A", 6002));
        var scanner = new LinuxProcSocketScanner(new StubProcessInspector(), _procRoot);

        // Act
        var act = () => scanner.ScanSocketsAsync(CancellationToken.None);

        // Assert
        var connections = (await act.Should().NotThrowAsync()).Subject;
        connections.Should().ContainSingle()
            .Which.LocalEndpoint.Should().Be(new SocketEndpoint(IPAddress.Parse("192.168.1.20"), 22));
    }

    [Fact]
    public async Task ScanSocketsAsync_WhenListeningLineHasUnparseablePort_DoesNotCountItAsService()
    {
        // Arrange
        // A malformed listener line on port "ZZZZ", then a TCP flow from 192.168.1.20:50003 to 192.168.1.10:443.
        WriteTable(
            "tcp",
            Line("00000000:ZZZZ", "00000000:0000", "0A", 6003),
            Line("1401A8C0:C353", "0A01A8C0:01BB", "01", 6004));
        var scanner = new LinuxProcSocketScanner(new StubProcessInspector(), _procRoot);

        // Act
        var act = () => scanner.ScanSocketsAsync(CancellationToken.None);

        // Assert
        var connections = (await act.Should().NotThrowAsync()).Subject;
        connections.Should().ContainSingle()
            .Which.Direction.Should().Be(SocketFlowDirection.Outbound);
    }

    [Fact]
    public async Task ScanSocketsAsync_WhenTimeWaitSocketHasNoInode_SkipsIt()
    {
        // Arrange
        // The kernel detaches TIME_WAIT sockets from their file, so they carry inode 0 and no owning process.
        WriteTable(
            "tcp",
            Line("1401A8C0:C354", "0A01A8C0:01BB", "06", 0),
            Line("1401A8C0:C355", "0A01A8C0:01BB", "01", 7001));
        var scanner = new LinuxProcSocketScanner(new StubProcessInspector(), _procRoot);

        // Act
        var connections = await scanner.ScanSocketsAsync(CancellationToken.None);

        // Assert
        connections.Should().ContainSingle()
            .Which.State.Should().Be("Established");
    }

    [Theory]
    [InlineData("tcp", "06", 7002, 1)]
    [InlineData("tcp6", "06", 0, 0)]
    [InlineData("udp", "06", 0, 1)]
    [InlineData("tcp", "05", 0, 1)]
    public async Task ScanSocketsAsync_WhenSocketIsNotAnOwnerlessTcpTimeWait_KeepsIt(string table, string state, int inode, int expectedCount)
    {
        // Arrange
        // Only an IPv4 or IPv6 TCP socket in TIME_WAIT with inode 0 is dropped (expected count 0 for the tcp6 case).
        var address = table.EndsWith('6') ? "0000000000000000FFFF00001401A8C0:C356" : "1401A8C0:C356";
        var remote = table.EndsWith('6') ? "0000000000000000FFFF00000A01A8C0:01BB" : "0A01A8C0:01BB";
        WriteTable(table, Line(address, remote, state, inode));
        var scanner = new LinuxProcSocketScanner(new StubProcessInspector(), _procRoot);

        // Act
        var connections = await scanner.ScanSocketsAsync(CancellationToken.None);

        // Assert
        connections.Should().HaveCount(expectedCount);
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
