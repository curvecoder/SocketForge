using System.Globalization;
using System.Net;
using ProcessForge.Contracts;
using SocketForge.Contracts;
using SocketForge.Models;
using SocketForge.Resolution;

namespace SocketForge.Linux;

/// <summary>
/// Linux socket scanner that parses /proc/net.
/// </summary>
public sealed class LinuxProcSocketScanner(IProcessInspector processInspector, string procRoot = "/proc") : ISocketScanner
{
    private readonly IProcessInspector _processInspector = processInspector ?? throw new ArgumentNullException(nameof(processInspector));
    private readonly string _procRoot = string.IsNullOrWhiteSpace(procRoot) ? "/proc" : procRoot;

    // TCP_LISTEN. A TCP socket in TCP_CLOSE (07) is not accepting connections and must not mark its port as a service.
    private const string TcpListenState = "0A";

    // The kernel reports an unconnected UDP socket, the only kind that receives from any peer, in state 07.
    private const string UdpUnconnectedState = "07";

    /// <inheritdoc />
    public async Task<IReadOnlyList<ActiveSocketConnection>> ScanSocketsAsync(CancellationToken cancellationToken = default)
    {
        var records = new List<ActiveSocketConnection>();
        var inodeToPid = BuildInodeToPidMap();

        var tcpPath = Path.Combine(_procRoot, "net", "tcp");
        var tcpLines = File.Exists(tcpPath)
            ? await File.ReadAllLinesAsync(tcpPath, cancellationToken).ConfigureAwait(false)
            : [];

        var tcp6Path = Path.Combine(_procRoot, "net", "tcp6");
        var tcp6Lines = File.Exists(tcp6Path)
            ? await File.ReadAllLinesAsync(tcp6Path, cancellationToken).ConfigureAwait(false)
            : [];

        var udpPath = Path.Combine(_procRoot, "net", "udp");
        var udpLines = File.Exists(udpPath)
            ? await File.ReadAllLinesAsync(udpPath, cancellationToken).ConfigureAwait(false)
            : [];

        var udp6Path = Path.Combine(_procRoot, "net", "udp6");
        var udp6Lines = File.Exists(udp6Path)
            ? await File.ReadAllLinesAsync(udp6Path, cancellationToken).ConfigureAwait(false)
            : [];

        // Each protocol has its own port space: a UDP socket bound on a port says nothing about a TCP flow using it.
        var tcpListeningPorts = CollectListeningPorts(TcpListenState, tcpLines, tcp6Lines);
        var udpListeningPorts = CollectListeningPorts(UdpUnconnectedState, udpLines, udp6Lines);

        if (tcpLines.Length > 0)
        {
            await ParseProcNetLinesAsync(tcpLines, SocketTransportProtocol.Tcp, inodeToPid, tcpListeningPorts, records, cancellationToken).ConfigureAwait(false);
        }

        if (tcp6Lines.Length > 0)
        {
            await ParseProcNetLinesAsync(tcp6Lines, SocketTransportProtocol.Tcp, inodeToPid, tcpListeningPorts, records, cancellationToken).ConfigureAwait(false);
        }

        if (udpLines.Length > 0)
        {
            await ParseProcNetLinesAsync(udpLines, SocketTransportProtocol.Udp, inodeToPid, udpListeningPorts, records, cancellationToken).ConfigureAwait(false);
        }

        if (udp6Lines.Length > 0)
        {
            await ParseProcNetLinesAsync(udp6Lines, SocketTransportProtocol.Udp, inodeToPid, udpListeningPorts, records, cancellationToken).ConfigureAwait(false);
        }

        return records;
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

    private async Task ParseProcNetLinesAsync(
        string[] lines,
        SocketTransportProtocol protocol,
        Dictionary<string, int> inodeToPid,
        IReadOnlySet<int> listeningPorts,
        List<ActiveSocketConnection> records,
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

            _ = inodeToPid.TryGetValue(inode, out var pid);
            var process = await _processInspector.ResolveProcessAsync(pid, cancellationToken).ConfigureAwait(false);

            var isListening = string.Equals(stateHex, TcpListenState, StringComparison.OrdinalIgnoreCase) ||
                              remoteEp.Port == 0 ||
                              remoteEp.Address.Equals(IPAddress.Any) ||
                              remoteEp.Address.Equals(IPAddress.IPv6Any);

            var direction = SocketFlowDirectionResolver.Resolve(localEp, remoteEp, isListening, listeningPorts);

            records.Add(new ActiveSocketConnection(
                Protocol: protocol,
                Direction: direction,
                LocalEndpoint: localEp,
                RemoteEndpoint: remoteEp,
                State: MapLinuxState(stateHex),
                Process: process));
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

    private Dictionary<string, int> BuildInodeToPidMap()
    {
        var map = new Dictionary<string, int>(StringComparer.Ordinal);
        if (!Directory.Exists(_procRoot))
        {
            return map;
        }

        try
        {
            var procDirs = Directory.GetDirectories(_procRoot);
            foreach (var dir in procDirs)
            {
                var dirName = Path.GetFileName(dir);
                if (!int.TryParse(dirName, NumberStyles.Integer, CultureInfo.InvariantCulture, out var pid))
                {
                    continue;
                }

                var fdDir = Path.Combine(dir, "fd");
                if (!Directory.Exists(fdDir))
                {
                    continue;
                }

                try
                {
                    var links = Directory.GetFiles(fdDir);
                    foreach (var link in links)
                    {
                        var linkTarget = new FileInfo(link).LinkTarget ?? File.ResolveLinkTarget(link, returnFinalTarget: false)?.FullName;
                        if (linkTarget is not null && linkTarget.Contains("socket:[", StringComparison.Ordinal))
                        {
                            var startIdx = linkTarget.IndexOf("socket:[", StringComparison.Ordinal) + "socket:[".Length;
                            var endIdx = linkTarget.IndexOf(']', startIdx);
                            if (endIdx > startIdx)
                            {
                                var inode = linkTarget[startIdx..endIdx];
                                map[inode] = pid;
                            }
                        }
                    }
                }
                catch (IOException)
                {
                    // The process exited while its fd directory was listed. Its sockets not mapped yet keep pid 0; the
                    // other processes are still mapped.
                }
                catch (UnauthorizedAccessException)
                {
                    // Without root, the fd directories of other users' processes cannot be read. Their sockets are
                    // still reported, with pid 0.
                }
            }
        }
        catch (IOException)
        {
            // /proc cannot be listed: the map stays empty and every socket is reported with pid 0.
        }

        return map;
    }
}
