using System.Globalization;
using System.Net;
using ProcessForge.Contracts;
using ProcessForge.Models;
using SocketForge.Contracts;
using SocketForge.Models;
using SocketForge.Resolution;

namespace SocketForge.Linux;

/// <summary>
/// Linux socket scanner that parses /proc/net.
/// </summary>
/// <remarks>
/// The scanner keeps, between scans, which process holds each socket inode. A kept owner is used only after its
/// descriptor was read again and still points to that socket, so keep one instance for as long as you scan.
/// </remarks>
public sealed class LinuxProcSocketScanner : ISocketScanner
{
    private readonly IProcessInspector _processInspector;
    private readonly string _procRoot;
    private readonly SocketOwnerTable _ownerTable;

    // TCP_LISTEN. A TCP socket in TCP_CLOSE (07) is not accepting connections and must not mark its port as a service.
    private const string TcpListenState = "0A";

    private const string TcpTimeWaitState = "06";

    private const string NoInode = "0";

    // The kernel reports an unconnected UDP socket, the only kind that receives from any peer, in state 07.
    private const string UdpUnconnectedState = "07";

    /// <summary>
    /// Creates a scanner that reads the given /proc tree.
    /// </summary>
    /// <param name="processInspector">The inspector that resolves the process owning each socket.</param>
    /// <param name="procRoot">The root of the /proc tree; <c>/proc</c> when empty.</param>
    /// <exception cref="ArgumentNullException"><paramref name="processInspector"/> is <see langword="null"/>.</exception>
    public LinuxProcSocketScanner(IProcessInspector processInspector, string procRoot = "/proc")
        : this(processInspector, procRoot, descriptorReader: null)
    {
    }

    internal LinuxProcSocketScanner(IProcessInspector processInspector, string procRoot, IProcDescriptorReader? descriptorReader)
    {
        _processInspector = processInspector ?? throw new ArgumentNullException(nameof(processInspector));
        _procRoot = string.IsNullOrWhiteSpace(procRoot) ? "/proc" : procRoot;
        _ownerTable = new SocketOwnerTable(descriptorReader ?? new ProcFsDescriptorReader(_procRoot));
    }

    internal IProcessInspector ProcessInspector => _processInspector;

    /// <inheritdoc />
    public async Task<IReadOnlyList<ActiveSocketConnection>> ScanSocketsAsync(CancellationToken cancellationToken = default)
    {
        var tcpLines = await ReadTableAsync("tcp", cancellationToken).ConfigureAwait(false);
        var tcp6Lines = await ReadTableAsync("tcp6", cancellationToken).ConfigureAwait(false);
        var udpLines = await ReadTableAsync("udp", cancellationToken).ConfigureAwait(false);
        var udp6Lines = await ReadTableAsync("udp6", cancellationToken).ConfigureAwait(false);

        // Each protocol has its own port space: a UDP socket bound on a port says nothing about a TCP flow using it.
        var tcpListeningPorts = CollectListeningPorts(TcpListenState, tcpLines, tcp6Lines);
        var udpListeningPorts = CollectListeningPorts(UdpUnconnectedState, udpLines, udp6Lines);

        var rows = new List<ProcNetRow>();
        CollectRows(tcpLines, SocketTransportProtocol.Tcp, tcpListeningPorts, rows, cancellationToken);
        CollectRows(tcp6Lines, SocketTransportProtocol.Tcp, tcpListeningPorts, rows, cancellationToken);
        CollectRows(udpLines, SocketTransportProtocol.Udp, udpListeningPorts, rows, cancellationToken);
        CollectRows(udp6Lines, SocketTransportProtocol.Udp, udpListeningPorts, rows, cancellationToken);

        // The tables are read before the owners are searched, so that every inode looked for existed when it was listed.
        var inodes = rows.Select(row => row.Inode).Where(inode => !string.Equals(inode, NoInode, StringComparison.Ordinal)).ToHashSet(StringComparer.Ordinal);
        var owners = _ownerTable.ResolveOwners(inodes, cancellationToken);

        var processResolver = new ScanProcessResolver(_processInspector);
        var records = new List<ActiveSocketConnection>(rows.Count);
        foreach (var row in rows)
        {
            var processId = owners.GetValueOrDefault(row.Inode);
            var process = await processResolver.ResolveAsync(processId, cancellationToken).ConfigureAwait(false);
            records.Add(row.ToConnection(process));
        }

        return records;
    }

    private async Task<string[]> ReadTableAsync(string name, CancellationToken cancellationToken)
    {
        var path = Path.Combine(_procRoot, "net", name);
        return File.Exists(path)
            ? await File.ReadAllLinesAsync(path, cancellationToken).ConfigureAwait(false)
            : [];
    }

    private static HashSet<int> CollectListeningPorts(string listenState, params string[][] lineSets)
    {
        var listeningPorts = new HashSet<int>();
        foreach (var lines in lineSets)
        {
            for (var i = 1; i < lines.Length; i++)
            {
                var line = lines[i].Trim();
                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 4)
                {
                    continue;
                }

                var stateHex = parts[3];
                if (string.Equals(stateHex, listenState, StringComparison.OrdinalIgnoreCase))
                {
                    if (TryParseEndpoint(parts[1], out var localEp) && localEp.Port > 0)
                    {
                        listeningPorts.Add(localEp.Port);
                    }
                }
            }
        }

        return listeningPorts;
    }

    private static void CollectRows(
        string[] lines,
        SocketTransportProtocol protocol,
        IReadOnlySet<int> listeningPorts,
        List<ProcNetRow> rows,
        CancellationToken cancellationToken)
    {
        for (var i = 1; i < lines.Length; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var line = lines[i].Trim();
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 10)
            {
                continue;
            }

            if (!TryParseEndpoint(parts[1], out var localEp) || !TryParseEndpoint(parts[2], out var remoteEp))
            {
                continue;
            }

            var stateHex = parts[3];
            var inode = parts[9];
            if (protocol == SocketTransportProtocol.Tcp && IsOwnerlessTimeWait(stateHex, inode))
            {
                continue;
            }

            var isListening = string.Equals(stateHex, TcpListenState, StringComparison.OrdinalIgnoreCase) ||
                              remoteEp.Port == 0 ||
                              remoteEp.Address.Equals(IPAddress.Any) ||
                              remoteEp.Address.Equals(IPAddress.IPv6Any);

            var direction = SocketFlowDirectionResolver.Resolve(localEp, remoteEp, isListening, listeningPorts);
            rows.Add(new ProcNetRow(protocol, direction, localEp, remoteEp, MapLinuxState(stateHex), inode));
        }
    }

    // The /proc/net format is kernel output, not a stable contract: a line with an undecodable port or address is skipped
    // and the scan goes on with the next one. An endpoint without a colon, or an address that is neither 8 nor 32 hex
    // digits, keeps its historical reading as 0.0.0.0 so that existing consumers see the same rows as before.
    private static bool TryParseEndpoint(string hexEndpoint, out SocketEndpoint endpoint)
    {
        endpoint = new SocketEndpoint(IPAddress.Any, 0);
        var tokens = hexEndpoint.Split(':');
        if (tokens.Length != 2)
        {
            return true;
        }

        if (!int.TryParse(tokens[1], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var port) || port is < 0 or > 65535)
        {
            return false;
        }

        if (!TryParseHexAddress(tokens[0], out var address))
        {
            return false;
        }

        endpoint = new SocketEndpoint(address, port);
        return true;
    }

    private static bool TryParseHexAddress(string ipHex, out IPAddress address)
    {
        address = IPAddress.Any;
        if (ipHex.Length == 8)
        {
            if (!uint.TryParse(ipHex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var ipInt))
            {
                return false;
            }

            address = new IPAddress(ipInt);
            return true;
        }

        if (ipHex.Length != 32)
        {
            return true;
        }

        var bytes = new byte[16];
        for (var i = 0; i < 4; i++)
        {
            if (!uint.TryParse(ipHex.AsSpan(i * 8, 8), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var chunk))
            {
                return false;
            }

            BitConverter.GetBytes(chunk).CopyTo(bytes, i * 4);
        }

        // A dual-stack socket reports its IPv4 peers as ::ffff:a.b.c.d; mapping them back keeps one address per host
        // whether the peer was reached through the IPv4 or the IPv6 table.
        var parsed = new IPAddress(bytes);
        address = parsed.IsIPv4MappedToIPv6 ? parsed.MapToIPv4() : parsed;
        return true;
    }

    // The kernel detaches a TIME_WAIT socket from its file once the process closed it, so it carries inode 0 and no
    // owning process; reporting it would add a second flow of the same destination with an unknown owner. Other states
    // that can also carry inode 0, such as an orphaned FIN_WAIT2, are still reported.
    private static bool IsOwnerlessTimeWait(string stateHex, string inode) =>
        string.Equals(stateHex, TcpTimeWaitState, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(inode, NoInode, StringComparison.Ordinal);

    private static string MapLinuxState(string stateHex)
    {
        return stateHex switch
        {
            "0A" => "Listen",
            "01" => "Established",
            "02" => "SynSent",
            "03" => "SynRecv",
            "04" => "FinWait1",
            "05" => "FinWait2",
            "06" => "TimeWait",
            "07" => "Close",
            "08" => "CloseWait",
            "09" => "LastAck",
            _ => $"State({stateHex})"
        };
    }

    private readonly record struct ProcNetRow(
        SocketTransportProtocol Protocol,
        SocketFlowDirection Direction,
        SocketEndpoint LocalEndpoint,
        SocketEndpoint RemoteEndpoint,
        string State,
        string Inode)
    {
        public ActiveSocketConnection ToConnection(ProcessMetadata process) =>
            new(Protocol, Direction, LocalEndpoint, RemoteEndpoint, State, process);
    }
}
