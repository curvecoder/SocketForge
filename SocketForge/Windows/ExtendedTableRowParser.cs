using System.Buffers.Binary;
using System.Net;
using SocketForge.Models;

namespace SocketForge.Windows;

/// <summary>
/// One row of an IP Helper owner-PID table, decoded from its native layout.
/// </summary>
internal sealed record NativeSocketRow(SocketEndpoint Local, SocketEndpoint Remote, uint State, int OwningPid);

/// <summary>
/// Decodes the rows of the <c>TCP_TABLE_OWNER_PID_ALL</c> and <c>UDP_TABLE_OWNER_PID</c> tables for IPv4 and IPv6.
/// </summary>
/// <remarks>
/// Every table starts with a 32-bit row count followed by fixed-size rows. Ports are stored in network byte order in
/// the low 16 bits of a 32-bit field; addresses are stored in network byte order.
/// </remarks>
internal static class ExtendedTableRowParser
{
    private const int Tcp4RowSize = 24;
    private const int Tcp6RowSize = 56;
    private const int Udp4RowSize = 12;
    private const int Udp6RowSize = 28;

    private delegate NativeSocketRow RowDecoder(ReadOnlySpan<byte> row);

    internal static IReadOnlyList<NativeSocketRow> ParseTcp4(byte[] table) => ParseRows(table, Tcp4RowSize, DecodeTcp4);

    internal static IReadOnlyList<NativeSocketRow> ParseTcp6(byte[] table) => ParseRows(table, Tcp6RowSize, DecodeTcp6);

    internal static IReadOnlyList<NativeSocketRow> ParseUdp4(byte[] table) => ParseRows(table, Udp4RowSize, DecodeUdp4);

    internal static IReadOnlyList<NativeSocketRow> ParseUdp6(byte[] table) => ParseRows(table, Udp6RowSize, DecodeUdp6);

    private static List<NativeSocketRow> ParseRows(byte[] table, int rowSize, RowDecoder decode)
    {
        var rows = new List<NativeSocketRow>();
        if (table.Length < sizeof(int))
        {
            return rows;
        }

        var rowCount = Math.Min(BinaryPrimitives.ReadInt32LittleEndian(table), (table.Length - sizeof(int)) / rowSize);
        for (var i = 0; i < rowCount; i++)
        {
            rows.Add(decode(table.AsSpan(sizeof(int) + (i * rowSize), rowSize)));
        }

        return rows;
    }

    private static NativeSocketRow DecodeTcp4(ReadOnlySpan<byte> row) => new(
        Local: new SocketEndpoint(new IPAddress(row.Slice(4, 4)), ReadPort(row, 8)),
        Remote: new SocketEndpoint(new IPAddress(row.Slice(12, 4)), ReadPort(row, 16)),
        State: BinaryPrimitives.ReadUInt32LittleEndian(row),
        OwningPid: BinaryPrimitives.ReadInt32LittleEndian(row[20..]));

    private static NativeSocketRow DecodeUdp4(ReadOnlySpan<byte> row) => new(
        Local: new SocketEndpoint(new IPAddress(row[..4]), ReadPort(row, 4)),
        Remote: new SocketEndpoint(IPAddress.Any, 0),
        State: 0,
        OwningPid: BinaryPrimitives.ReadInt32LittleEndian(row[8..]));

    private static NativeSocketRow DecodeTcp6(ReadOnlySpan<byte> row) => new(
        Local: new SocketEndpoint(ReadIpv6Address(row, 0), ReadPort(row, 20)),
        Remote: new SocketEndpoint(ReadIpv6Address(row, 24), ReadPort(row, 44)),
        State: BinaryPrimitives.ReadUInt32LittleEndian(row[48..]),
        OwningPid: BinaryPrimitives.ReadInt32LittleEndian(row[52..]));

    private static NativeSocketRow DecodeUdp6(ReadOnlySpan<byte> row) => new(
        Local: new SocketEndpoint(ReadIpv6Address(row, 0), ReadPort(row, 20)),
        Remote: new SocketEndpoint(IPAddress.IPv6Any, 0),
        State: 0,
        OwningPid: BinaryPrimitives.ReadInt32LittleEndian(row[24..]));

    // The 16 address bytes are followed by the 32-bit scope id. It is kept for link-local addresses only, where it tells
    // interfaces apart; elsewhere it would make an address compare unequal to the same address seen on Linux.
    // A dual-mode socket reports IPv4 peers as ::ffff:a.b.c.d, mapped back so that one host keeps one address whichever
    // table lists the socket.
    private static IPAddress ReadIpv6Address(ReadOnlySpan<byte> row, int offset)
    {
        var address = new IPAddress(row.Slice(offset, 16));
        if (address.IsIPv4MappedToIPv6)
        {
            return address.MapToIPv4();
        }

        return address.IsIPv6LinkLocal
            ? new IPAddress(row.Slice(offset, 16), BinaryPrimitives.ReadUInt32LittleEndian(row[(offset + 16)..]))
            : address;
    }

    private static int ReadPort(ReadOnlySpan<byte> row, int offset) => BinaryPrimitives.ReadUInt16BigEndian(row.Slice(offset, 2));
}
