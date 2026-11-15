namespace SocketForge.Linux;

/// <summary>
/// Finds the process that holds each socket inode listed in /proc/net, keeping what it read between scans.
/// </summary>
/// <remarks>
/// <para>
/// Linux offers no index from a socket inode to its process: the only source is the <c>fd</c> directory of every
/// process. Reading all of them on each scan costs most of the scan, so the table keeps the descriptors it read and, on
/// the next scan, reads only what may have changed:
/// </para>
/// <list type="bullet">
/// <item>a kept owner is used only after its descriptor link was read again and still points to the same socket, so a
/// closed descriptor, a reused descriptor number or a reused pid never keeps a socket on the wrong process;</item>
/// <item>the descriptors of processes that appeared since the last scan are read, and processes that exited are
/// forgotten;</item>
/// <item>a socket still unattributed after that is searched in the other processes, the ones known to hold sockets
/// first, until every such socket is found;</item>
/// <item>a socket that no readable process held when every process was read is reported with pid 0; it is searched
/// again when a new process holds it, and in every process once every <see cref="UnownedRetryPeriod"/> scans, for the
/// holders that became readable or received it from another process.</item>
/// </list>
/// <para>
/// When several processes hold the same socket, the one with the highest pid keeps it, as with the former full walk in
/// /proc order.
/// </para>
/// <para>
/// The /proc reads are synchronous and run under a lock: two scans of the same scanner run one after the other.
/// </para>
/// </remarks>
internal sealed class SocketOwnerTable(IProcDescriptorReader descriptorReader)
{
    internal const int UnownedRetryPeriod = 16;

    private readonly object _gate = new();
    private readonly Dictionary<int, IReadOnlyList<ProcSocketDescriptor>> _descriptorsByProcess = [];
    private readonly Dictionary<string, SocketOwner> _ownerByInode = new(StringComparer.Ordinal);
    private readonly HashSet<string> _unownedInodes = new(StringComparer.Ordinal);
    private int _scansSinceCompleteSearch;

    public IReadOnlyDictionary<string, int> ResolveOwners(IReadOnlySet<string> inodes, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(inodes);

        lock (_gate)
        {
            if (++_scansSinceCompleteSearch >= UnownedRetryPeriod)
            {
                _unownedInodes.Clear();
            }

            var readThisScan = RefreshProcessList(cancellationToken);
            var owners = new Dictionary<string, int>(StringComparer.Ordinal);
            var missing = new HashSet<string>(StringComparer.Ordinal);
            var staleProcesses = new HashSet<int>();
            foreach (var inode in inodes)
            {
                if (TryConfirmOwner(inode, staleProcesses, out var processId))
                {
                    owners[inode] = processId;
                }
                else if (!_unownedInodes.Contains(inode))
                {
                    missing.Add(inode);
                }
            }

            if (missing.Count > 0)
            {
                SearchMissing(missing, owners, readThisScan, staleProcesses, cancellationToken);
            }

            // Only inodes still listed are worth remembering; the others belonged to sockets that are gone.
            _unownedInodes.IntersectWith(inodes);
            return owners;
        }
    }

    private HashSet<int> RefreshProcessList(CancellationToken cancellationToken)
    {
        var current = descriptorReader.ListProcessIds().ToHashSet();
        if (current.Count == 0)
        {
            // /proc could not be listed, since the scanning process itself is always listed. The known processes are
            // kept: their owners are still confirmed one by one, and a failed listing must not make them vanish.
            return [];
        }

        foreach (var processId in _descriptorsByProcess.Keys.Where(processId => !current.Contains(processId)).ToList())
        {
            Forget(processId);
        }

        var readThisScan = new HashSet<int>();
        foreach (var processId in current.Where(processId => !_descriptorsByProcess.ContainsKey(processId)).Order())
        {
            cancellationToken.ThrowIfCancellationRequested();
            Read(processId);
            readThisScan.Add(processId);
        }

        return readThisScan;
    }

    private bool TryConfirmOwner(string inode, HashSet<int> staleProcesses, out int processId)
    {
        processId = 0;
        if (!_ownerByInode.TryGetValue(inode, out var owner))
        {
            return false;
        }

        if (string.Equals(descriptorReader.ReadSocketInode(owner.Location), inode, StringComparison.Ordinal))
        {
            processId = owner.ProcessId;
            return true;
        }

        _ownerByInode.Remove(inode);
        staleProcesses.Add(owner.ProcessId);
        return false;
    }

    private void SearchMissing(
        HashSet<string> missing,
        Dictionary<string, int> owners,
        HashSet<int> readThisScan,
        HashSet<int> staleProcesses,
        CancellationToken cancellationToken)
    {
        // A process whose descriptor changed, or that already held sockets, is the likeliest holder of a new socket.
        var candidates = _descriptorsByProcess
            .Where(pair => !readThisScan.Contains(pair.Key))
            .OrderByDescending(pair => staleProcesses.Contains(pair.Key))
            .ThenByDescending(pair => pair.Value.Count > 0)
            .ThenBy(pair => pair.Key)
            .Select(pair => pair.Key)
            .ToList();

        foreach (var processId in candidates)
        {
            if (missing.Count == 0)
            {
                return;
            }

            cancellationToken.ThrowIfCancellationRequested();
            foreach (var descriptor in Read(processId))
            {
                if (missing.Remove(descriptor.Inode))
                {
                    owners[descriptor.Inode] = _ownerByInode[descriptor.Inode].ProcessId;
                }
            }
        }

        // Every process was read in this scan and none holds these sockets: the holders are unreadable, or the sockets
        // closed after /proc/net was read.
        _unownedInodes.UnionWith(missing);
        _scansSinceCompleteSearch = 0;
    }

    private IReadOnlyList<ProcSocketDescriptor> Read(int processId)
    {
        Forget(processId);
        var descriptors = descriptorReader.ReadSocketDescriptors(processId);
        _descriptorsByProcess[processId] = descriptors;
        foreach (var descriptor in descriptors)
        {
            _unownedInodes.Remove(descriptor.Inode);
            if (_ownerByInode.TryGetValue(descriptor.Inode, out var owner) && owner.ProcessId > processId)
            {
                continue;
            }

            _ownerByInode[descriptor.Inode] = new SocketOwner(processId, descriptor.Location);
        }

        return descriptors;
    }

    private void Forget(int processId)
    {
        if (!_descriptorsByProcess.Remove(processId, out var descriptors))
        {
            return;
        }

        foreach (var descriptor in descriptors)
        {
            if (_ownerByInode.TryGetValue(descriptor.Inode, out var owner) && owner.ProcessId == processId)
            {
                _ownerByInode.Remove(descriptor.Inode);
            }
        }
    }

    private readonly record struct SocketOwner(int ProcessId, string Location);
}
