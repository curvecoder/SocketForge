using ProcessForge.Contracts;
using ProcessForge.Inspectors;
using SocketForge.Contracts;
using SocketForge.Linux;
using SocketForge.Windows;

namespace SocketForge.Factories;

/// <summary>
/// Creates the socket scanner that matches the host operating system.
/// </summary>
public static class SocketScannerFactory
{
    /// <summary>
    /// Creates the socket scanner for the operating system the process runs on, with a process inspector that keeps
    /// each resolved process for the lifetime of the scanner.
    /// </summary>
    /// <remarks>
    /// The inspector is a <see cref="CachingProcessInspector"/> around a <see cref="CrossPlatformProcessInspector"/>:
    /// across scans, a process already seen is not read again unless its start time changed. Keep the returned scanner for
    /// as long as you scan, so that the cache lives with it.
    /// </remarks>
    /// <returns>The scanner for the current operating system.</returns>
    /// <exception cref="PlatformNotSupportedException">The operating system is neither Windows nor Linux.</exception>
    public static ISocketScanner Create() => Create(new CachingProcessInspector(new CrossPlatformProcessInspector()));

    /// <summary>
    /// Creates the socket scanner for the operating system the process runs on.
    /// </summary>
    /// <param name="processInspector">
    /// The inspector that resolves the process owning each socket. It is used as given, without an added cache.
    /// </param>
    /// <returns>The scanner for the current operating system.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="processInspector"/> is <see langword="null"/>.</exception>
    /// <exception cref="PlatformNotSupportedException">The operating system is neither Windows nor Linux.</exception>
    public static ISocketScanner Create(IProcessInspector processInspector)
    {
        ArgumentNullException.ThrowIfNull(processInspector);

        if (OperatingSystem.IsWindows())
        {
            return new WindowsSocketScanner(processInspector);
        }

        if (OperatingSystem.IsLinux())
        {
            return new LinuxProcSocketScanner(processInspector);
        }

        throw new PlatformNotSupportedException($"The {Environment.OSVersion.Platform} operating system is not supported.");
    }
}
