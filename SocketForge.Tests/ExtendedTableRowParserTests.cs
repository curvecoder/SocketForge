using System.Buffers.Binary;
using System.Net;
using AwesomeAssertions;
using SocketForge.Models;
using SocketForge.Windows;
using Xunit;

namespace SocketForge.Tests;

public sealed class ExtendedTableRowParserTests
{
    [Fact]
    public void ParseTcp6_WhenTableHoldsAnEstablishedRow_DecodesEndpointsStateAndPid()
    {
        // Arrange: MIB_TCP6ROW_OWNER_PID, fd00::10 port 50000 to fd00::20 port 443, Established (5), pid 4321
        var row = new byte[56];
        IPAddress.Parse("fd00::10").GetAddressBytes().CopyTo(row, 0);
        BinaryPrimitives.WriteUInt16BigEndian(row.AsSpan(20), 50000);
        IPAddress.Parse("fd00::20").GetAddressBytes().CopyTo(row, 24);
        BinaryPrimitives.WriteUInt16BigEndian(row.AsSpan(44), 443);
        BinaryPrimitives.WriteUInt32LittleEndian(row.AsSpan(48), 5);
        BinaryPrimitives.WriteInt32LittleEndian(row.AsSpan(52), 4321);

        // Act
        var rows = ExtendedTableRowParser.ParseTcp6(Table(row));

        // Assert
        rows.Should().ContainSingle().Which.Should().Be(new NativeSocketRow(
            new SocketEndpoint(IPAddress.Parse("fd00::10"), 50000),
            new SocketEndpoint(IPAddress.Parse("fd00::20"), 443),
            5,
            4321));
    }

    [Fact]
    public void ParseTcp6_WhenRowCarriesIpv4MappedAddresses_ReturnsIpv4Endpoints()
    {
        // Arrange
        var row = new byte[56];
        IPAddress.Parse("::ffff:192.168.1.20").GetAddressBytes().CopyTo(row, 0);
        BinaryPrimitives.WriteUInt16BigEndian(row.AsSpan(20), 50000);
        IPAddress.Parse("::ffff:192.168.1.10").GetAddressBytes().CopyTo(row, 24);
        BinaryPrimitives.WriteUInt16BigEndian(row.AsSpan(44), 443);
        BinaryPrimitives.WriteUInt32LittleEndian(row.AsSpan(48), 5);

        // Act
        var parsed = ExtendedTableRowParser.ParseTcp6(Table(row)).Should().ContainSingle().Subject;

        // Assert
        parsed.Local.Should().Be(new SocketEndpoint(IPAddress.Parse("192.168.1.20"), 50000));
        parsed.Remote.Should().Be(new SocketEndpoint(IPAddress.Parse("192.168.1.10"), 443));
    }

    [Fact]
    public void ParseUdp6_WhenTableHoldsABoundRow_DecodesLocalEndpointAndPid()
    {
        // Arrange: MIB_UDP6ROW_OWNER_PID, [::]:5353, pid 1200
        var row = new byte[28];
        BinaryPrimitives.WriteUInt16BigEndian(row.AsSpan(20), 5353);
        BinaryPrimitives.WriteInt32LittleEndian(row.AsSpan(24), 1200);

        // Act
        var rows = ExtendedTableRowParser.ParseUdp6(Table(row));

        // Assert
        rows.Should().ContainSingle().Which.Should().Be(new NativeSocketRow(
            new SocketEndpoint(IPAddress.IPv6Any, 5353),
            new SocketEndpoint(IPAddress.IPv6Any, 0),
            0,
            1200));
    }

    [Fact]
    public void ParseTcp4_WhenRowCountExceedsBuffer_ReturnsOnlyCompleteRows()
    {
        // Arrange: the header announces three rows but the buffer holds one
        var row = new byte[24];
        IPAddress.Parse("192.168.1.20").GetAddressBytes().CopyTo(row, 4);
        BinaryPrimitives.WriteUInt16BigEndian(row.AsSpan(8), 22);
        var table = Table(row);
        BinaryPrimitives.WriteInt32LittleEndian(table, 3);

        // Act
        var rows = ExtendedTableRowParser.ParseTcp4(table);

        // Assert
        rows.Should().ContainSingle().Which.Local.Should().Be(new SocketEndpoint(IPAddress.Parse("192.168.1.20"), 22));
    }

    [Fact]
    public void ParseTcp6_WhenAddressIsLinkLocal_KeepsScopeId()
    {
        // Arrange: fe80::1%12 port 22 listening
        var row = new byte[56];
        IPAddress.Parse("fe80::1").GetAddressBytes().CopyTo(row, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(row.AsSpan(16), 12);
        BinaryPrimitives.WriteUInt16BigEndian(row.AsSpan(20), 22);
        BinaryPrimitives.WriteUInt32LittleEndian(row.AsSpan(48), 2);

        // Act
        var parsed = ExtendedTableRowParser.ParseTcp6(Table(row)).Should().ContainSingle().Subject;

        // Assert
        parsed.Local.Address.ScopeId.Should().Be(12);
    }

    [Fact]
    public void ParseTcp6_WhenGlobalAddressCarriesScopeId_DropsScopeId()
    {
        // Arrange
        var row = new byte[56];
        IPAddress.Parse("fd00::10").GetAddressBytes().CopyTo(row, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(row.AsSpan(16), 7);
        BinaryPrimitives.WriteUInt16BigEndian(row.AsSpan(20), 443);

        // Act
        var parsed = ExtendedTableRowParser.ParseTcp6(Table(row)).Should().ContainSingle().Subject;

        // Assert
        parsed.Local.Address.Should().Be(IPAddress.Parse("fd00::10"));
    }

    [Fact]
    public void ParseUdp4_WhenTableHoldsABoundRow_DecodesLocalEndpointAndPid()
    {
        // Arrange: MIB_UDPROW_OWNER_PID, 192.168.1.20:53, pid 900
        var row = new byte[12];
        IPAddress.Parse("192.168.1.20").GetAddressBytes().CopyTo(row, 0);
        BinaryPrimitives.WriteUInt16BigEndian(row.AsSpan(4), 53);
        BinaryPrimitives.WriteInt32LittleEndian(row.AsSpan(8), 900);

        // Act
        var rows = ExtendedTableRowParser.ParseUdp4(Table(row));

        // Assert
        rows.Should().ContainSingle().Which.Should().Be(new NativeSocketRow(
            new SocketEndpoint(IPAddress.Parse("192.168.1.20"), 53),
            new SocketEndpoint(IPAddress.Any, 0),
            0,
            900));
    }

    [Theory]
    [InlineData(new byte[0])]
    [InlineData(new byte[] { 0, 0 })]
    [InlineData(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF })]
    public void ParseTcp4_WhenTableIsShortOrCountIsNotPositive_ReturnsNoRow(byte[] table)
    {
        // Act
        var rows = ExtendedTableRowParser.ParseTcp4(table);

        // Assert
        rows.Should().BeEmpty();
    }

    private static byte[] Table(byte[] row)
    {
        var table = new byte[sizeof(int) + row.Length];
        BinaryPrimitives.WriteInt32LittleEndian(table, 1);
        row.CopyTo(table, sizeof(int));
        return table;
    }
}
