using ProcessForge.Contracts;
using ProcessForge.Models;

namespace SocketForge.Resolution;

// A process usually owns many sockets: resolving it once per row repeated the same native and /proc reads for each of
// them. One instance lives for a single scan only, so a PID reused by another process is resolved again on the next scan.
internal sealed class ScanProcessResolver(IProcessInspector processInspector)
{
    private readonly Dictionary<int, ProcessMetadata> _resolvedProcesses = [];

    public async Task<ProcessMetadata> ResolveAsync(int processId, CancellationToken cancellationToken)
    {
        if (_resolvedProcesses.TryGetValue(processId, out var known))
        {
            return known;
        }

        var process = await processInspector.ResolveProcessAsync(processId, cancellationToken).ConfigureAwait(false);
        _resolvedProcesses[processId] = process;
        return process;
    }
}
