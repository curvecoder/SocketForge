using System.Globalization;
using SocketForge.Linux;

namespace SocketForge.Tests;

/// <summary>
/// An in-memory /proc: each process maps descriptor numbers to socket inodes.
/// </summary>
internal sealed class FakeProcDescriptors : IProcDescriptorReader
{
    private readonly SortedDictionary<int, Dictionary<string, string>> _processes = [];
    private readonly List<int> _readProcessIds = [];

    public IReadOnlyList<int> ReadProcessIds => _readProcessIds;

    public bool FailListing { get; set; }

    public FakeProcDescriptors Hold(int processId, string descriptor, string inode)
    {
        if (!_processes.TryGetValue(processId, out var descriptors))
        {
            descriptors = [];
            _processes[processId] = descriptors;
        }

        descriptors[descriptor] = inode;
        return this;
    }

    public FakeProcDescriptors Close(int processId, string descriptor)
    {
        _processes[processId].Remove(descriptor);
        return this;
    }

    public FakeProcDescriptors Exit(int processId)
    {
        _processes.Remove(processId);
        return this;
    }

    public void ForgetReads() => _readProcessIds.Clear();

    public IReadOnlyList<int> ListProcessIds() => FailListing ? [] : [.. _processes.Keys];

    public IReadOnlyList<ProcSocketDescriptor> ReadSocketDescriptors(int processId)
    {
        _readProcessIds.Add(processId);
        return _processes.TryGetValue(processId, out var descriptors)
            ? [.. descriptors.Select(pair => new ProcSocketDescriptor(Location(processId, pair.Key), pair.Value))]
            : [];
    }

    public string? ReadSocketInode(string location)
    {
        var separator = location.IndexOf('/', StringComparison.Ordinal);
        var processId = int.Parse(location[..separator], CultureInfo.InvariantCulture);
        return _processes.TryGetValue(processId, out var descriptors) && descriptors.TryGetValue(location[(separator + 1)..], out var inode)
            ? inode
            : null;
    }

    private static string Location(int processId, string descriptor) =>
        string.Create(CultureInfo.InvariantCulture, $"{processId}/{descriptor}");
}
