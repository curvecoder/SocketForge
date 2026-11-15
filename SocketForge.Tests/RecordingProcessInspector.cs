using System.Collections.Concurrent;
using ProcessForge.Contracts;
using ProcessForge.Models;

namespace SocketForge.Tests;

internal sealed class RecordingProcessInspector : IProcessInspector
{
    private readonly ConcurrentQueue<int> _requestedProcessIds = new();

    public IReadOnlyList<int> RequestedProcessIds => [.. _requestedProcessIds];

    public Task<ProcessMetadata> ResolveProcessAsync(int processId, CancellationToken cancellationToken = default)
    {
        _requestedProcessIds.Enqueue(processId);
        return Task.FromResult(new ProcessMetadata(processId, "stub", "stub", string.Empty, string.Empty, "user"));
    }
}
