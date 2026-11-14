using System.Net;
using System.Runtime.InteropServices;
using ProcessForge.Contracts;
using SocketForge.Contracts;
using SocketForge.Models;
using SocketForge.Resolution;

namespace SocketForge.Windows;

/// <summary>
/// Windows socket scanner built on the native IP Helper API (iphlpapi.dll).
/// </summary>
public sealed class WindowsSocketScanner(IProcessInspector processInspector) : ISocketScanner
{
    private readonly IProcessInspector _processInspector = processInspector ?? throw new ArgumentNullException(nameof(processInspector));

    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const uint ListenState = 2;
    private const uint TimeWaitState = 11;
    private const int TcpTableOwnerPidAll = 5;
    private const int UdpTableOwnerPid = 1;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int pdwSize,
        bool bOrder,
        int ulAf,
        int tableClass,
        uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(
        IntPtr pUdpTable,
        ref int pdwSize,
        bool bOrder,
        int ulAf,
        int tableClass,
        uint reserved);

    /// <inheritdoc />
    public async Task<IReadOnlyList<ActiveSocketConnection>> ScanSocketsAsync(CancellationToken cancellationToken = default)
    {
        var records = new List<ActiveSocketConnection>();

        // IP Helper keeps one table per address family; the two reads are separate snapshots, so a socket opened between
        // them may be missing from this cycle and is picked up by the next one.
        var tcpRows = ReadTcpRows(AfInet).Concat(ReadTcpRows(AfInet6)).Where(row => !IsOwnerlessTimeWait(row)).ToList();
        var listeningPorts = new HashSet<int>();
        foreach (var row in tcpRows)
        {
            if (row.State == ListenState || row.Remote.Port == 0)
            {
                listeningPorts.Add(row.Local.Port);
            }
        }

        foreach (var row in tcpRows)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var process = await _processInspector.ResolveProcessAsync(row.OwningPid, cancellationToken).ConfigureAwait(false);

            records.Add(new ActiveSocketConnection(
                Protocol: SocketTransportProtocol.Tcp,
                Direction: DetermineDirection(row.Local, row.Remote, row.State, listeningPorts),
                LocalEndpoint: row.Local,
                RemoteEndpoint: row.Remote,
                State: MapTcpState(row.State),
                Process: process));
        }

        foreach (var row in ReadUdpRows(AfInet).Concat(ReadUdpRows(AfInet6)))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var process = await _processInspector.ResolveProcessAsync(row.OwningPid, cancellationToken).ConfigureAwait(false);

            records.Add(new ActiveSocketConnection(
                Protocol: SocketTransportProtocol.Udp,
                Direction: SocketFlowDirection.Listening,
                LocalEndpoint: row.Local,
                RemoteEndpoint: row.Remote,
                State: "UDP",
                Process: process));
        }

        return records;
    }

    internal static SocketFlowDirection DetermineDirection(
        SocketEndpoint local,
        SocketEndpoint remote,
        uint state,
        IReadOnlySet<int>? listeningPorts)
    {
        return SocketFlowDirectionResolver.Resolve(local, remote, isListeningState: state == ListenState, listeningPorts);
    }

    internal static SocketFlowDirection DetermineDirection(SocketEndpoint local, SocketEndpoint remote, uint state) =>
        DetermineDirection(local, remote, state, listeningPorts: null);

    // Once a process closes a connection, Windows keeps the TIME_WAIT row for a few minutes under pid 0. It no longer
    // belongs to any process and would show up as a second flow of the same destination owned by "System Idle".
    internal static bool IsOwnerlessTimeWait(NativeSocketRow row) => row.State == TimeWaitState && row.OwningPid == 0;

    internal static string MapTcpState(uint state)
    {
        return state switch
        {
            1 => "Closed",
            2 => "Listen",
            3 => "SynSent",
            4 => "SynReceived",
            5 => "Established",
            6 => "FinWait1",
            7 => "FinWait2",
            8 => "CloseWait",
            9 => "Closing",
            10 => "LastAck",
            11 => "TimeWait",
            12 => "DeleteTCB",
            _ => $"Unknown({state})"
        };
    }

    private static IReadOnlyList<NativeSocketRow> ReadTcpRows(int addressFamily)
    {
        var table = ExtendedTableReader.Read(
            (IntPtr buffer, ref int size) => GetExtendedTcpTable(buffer, ref size, true, addressFamily, TcpTableOwnerPidAll, 0),
            nameof(GetExtendedTcpTable));
        return addressFamily == AfInet6 ? ExtendedTableRowParser.ParseTcp6(table) : ExtendedTableRowParser.ParseTcp4(table);
    }

    private static IReadOnlyList<NativeSocketRow> ReadUdpRows(int addressFamily)
    {
        var table = ExtendedTableReader.Read(
            (IntPtr buffer, ref int size) => GetExtendedUdpTable(buffer, ref size, true, addressFamily, UdpTableOwnerPid, 0),
            nameof(GetExtendedUdpTable));
        return addressFamily == AfInet6 ? ExtendedTableRowParser.ParseUdp6(table) : ExtendedTableRowParser.ParseUdp4(table);
    }
}
