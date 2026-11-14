using System.Net;
using AwesomeAssertions;
using ProcessForge.Models;
using SocketForge.Models;
using Xunit;

namespace SocketForge.Tests;

public sealed class ActiveSocketConnectionTests
{
    [Fact]
    public void ComputeLogicalKey_WhenExecutablePathsAreEmpty_DistinguishesProcessesByName()
    {
        // Arrange: two protected processes whose paths cannot be read without elevation
        var first = Outbound(new ProcessMetadata(612, "lsass", string.Empty, string.Empty, string.Empty, "SYSTEM"));
        var second = Outbound(new ProcessMetadata(704, "svchost", string.Empty, string.Empty, string.Empty, "SYSTEM"));

        // Act
        var firstKey = first.ComputeLogicalKey();
        var secondKey = second.ComputeLogicalKey();

        // Assert
        firstKey.Should().NotBe(secondKey);
        firstKey.Should().Be("Tcp:Outbound:lsass:192.168.1.10:443");
        secondKey.Should().Be("Tcp:Outbound:svchost:192.168.1.10:443");
    }

    [Fact]
    public void ComputeLogicalKey_WhenPathsAreWhitespace_UsesProcessName()
    {
        // Arrange
        var connection = Outbound(new ProcessMetadata(612, "lsass", "  ", string.Empty, " ", "SYSTEM"));

        // Act
        var key = connection.ComputeLogicalKey();

        // Assert
        key.Should().Be("Tcp:Outbound:lsass:192.168.1.10:443");
    }

    [Fact]
    public void ComputeLogicalKey_WhenExecutablePathIsKnown_KeepsThePathAsOwner()
    {
        // Arrange
        var connection = Outbound(new ProcessMetadata(1234, "curl", @"C:\tools\curl.exe", string.Empty, string.Empty, "user"));

        // Act
        var key = connection.ComputeLogicalKey();

        // Assert
        key.Should().Be(@"Tcp:Outbound:C:\tools\curl.exe:192.168.1.10:443");
    }

    [Fact]
    public void ComputeLogicalKey_WhenTargetExecutableIsKnown_PrefersItOverThePath()
    {
        // Arrange
        var connection = Outbound(new ProcessMetadata(1234, "java", "/usr/bin/java", "java -jar /opt/app.jar", "/opt/app.jar", "user"));

        // Act
        var key = connection.ComputeLogicalKey();

        // Assert
        key.Should().Be("Tcp:Outbound:/opt/app.jar:192.168.1.10:443");
    }

    private static ActiveSocketConnection Outbound(ProcessMetadata process) => new(
        SocketTransportProtocol.Tcp,
        SocketFlowDirection.Outbound,
        new SocketEndpoint(IPAddress.Parse("192.168.1.20"), 50000),
        new SocketEndpoint(IPAddress.Parse("192.168.1.10"), 443),
        "Established",
        process);
}
