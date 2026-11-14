using SocketForge.Models;

namespace SocketForge.Contracts;

/// <summary>
/// Enumerates the network connections and sockets of the host system, without depending on Npcap.
/// </summary>
public interface ISocketScanner
{
    /// <summary>
    /// Scans all active TCP connections and UDP sockets.
    /// </summary>
    /// <param name="cancellationToken">Cooperative cancellation token.</param>
    /// <returns>The observed network connections.</returns>
    /// <exception cref="System.ComponentModel.Win32Exception">On Windows, the IP Helper API failed to return a socket table.</exception>
    /// <exception cref="InvalidOperationException">On Windows, the socket table kept growing faster than it could be read.</exception>
    /// <exception cref="OperationCanceledException">The scan was cancelled through <paramref name="cancellationToken"/>.</exception>
    Task<IReadOnlyList<ActiveSocketConnection>> ScanSocketsAsync(CancellationToken cancellationToken = default);
}
