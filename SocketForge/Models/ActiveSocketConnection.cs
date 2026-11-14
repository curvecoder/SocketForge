using ProcessForge.Models;

namespace SocketForge.Models;

/// <summary>
/// Immutable view of an active network socket and its owning process.
/// </summary>
/// <param name="Protocol">Transport protocol.</param>
/// <param name="Direction">Resolved flow direction.</param>
/// <param name="LocalEndpoint">Local endpoint.</param>
/// <param name="RemoteEndpoint">Remote endpoint.</param>
/// <param name="State">Socket state as text (for example Established or Listen).</param>
/// <param name="Process">Metadata of the owning process, resolved through ProcessForge.</param>
public sealed record ActiveSocketConnection(
    SocketTransportProtocol Protocol,
    SocketFlowDirection Direction,
    SocketEndpoint LocalEndpoint,
    SocketEndpoint RemoteEndpoint,
    string State,
    ProcessMetadata Process)
{
    /// <summary>
    /// Computes the canonical key used to deduplicate this socket.
    /// </summary>
    /// <remarks>
    /// The owner part of the key is the target executable, else the executable path, else the process name.
    /// </remarks>
    /// <returns>A key that stays the same across client ephemeral ports of one logical flow.</returns>
    public string ComputeLogicalKey()
    {
        var owner = ResolveOwner();

        return Direction switch
        {
            SocketFlowDirection.Outbound => $"{Protocol}:{Direction}:{owner}:{RemoteEndpoint.Address}:{RemoteEndpoint.Port}",
            SocketFlowDirection.Inbound => $"{Protocol}:{Direction}:{owner}:{LocalEndpoint.Port}:{RemoteEndpoint.Address}",
            SocketFlowDirection.Listening => $"{Protocol}:{Direction}:{owner}:{LocalEndpoint.Port}",
            _ => $"{Protocol}:{Direction}:{owner}:{LocalEndpoint}:{RemoteEndpoint}"
        };
    }

    // The path is empty for a protected process read without elevation or a process that already exited; falling back
    // to the name keeps such processes apart instead of merging every one of them into a single flow.
    private string ResolveOwner()
    {
        if (!string.IsNullOrWhiteSpace(Process.TargetExecutable))
        {
            return Process.TargetExecutable;
        }

        return string.IsNullOrWhiteSpace(Process.ExecutablePath) ? Process.ProcessName : Process.ExecutablePath;
    }
}
