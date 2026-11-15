using System.Globalization;

namespace SocketForge.Linux;

/// <summary>
/// Reads socket descriptors from the <c>/proc/&lt;pid&gt;/fd</c> symbolic links, whose targets read <c>socket:[inode]</c>.
/// </summary>
internal sealed class ProcFsDescriptorReader(string procRoot) : IProcDescriptorReader
{
    private const string SocketLinkPrefix = "socket:[";

    public IReadOnlyList<int> ListProcessIds()
    {
        if (!Directory.Exists(procRoot))
        {
            return [];
        }

        var processIds = new List<int>();
        try
        {
            foreach (var directory in Directory.EnumerateDirectories(procRoot))
            {
                if (int.TryParse(Path.GetFileName(directory), NumberStyles.Integer, CultureInfo.InvariantCulture, out var processId))
                {
                    processIds.Add(processId);
                }
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // /proc cannot be listed in full. A partial list would make live processes look exited, so none is
            // returned and the caller keeps the processes it already knows.
            return [];
        }

        return processIds;
    }

    public IReadOnlyList<ProcSocketDescriptor> ReadSocketDescriptors(int processId)
    {
        var fdDirectory = Path.Combine(procRoot, processId.ToString(CultureInfo.InvariantCulture), "fd");
        var descriptors = new List<ProcSocketDescriptor>();
        if (!Directory.Exists(fdDirectory))
        {
            return descriptors;
        }

        try
        {
            foreach (var link in Directory.GetFiles(fdDirectory))
            {
                if (ReadSocketInode(link) is { } inode)
                {
                    descriptors.Add(new ProcSocketDescriptor(link, inode));
                }
            }
        }
        catch (IOException)
        {
            // The process exited before its fd directory was listed: it holds no socket any more.
        }
        catch (UnauthorizedAccessException)
        {
            // Without root, the fd directories of other users' processes cannot be read. Their sockets are still
            // reported, with pid 0.
        }

        return descriptors;
    }

    public string? ReadSocketInode(string location)
    {
        try
        {
            return TryReadInode(location, out var inode) ? inode : null;
        }
        catch (IOException)
        {
            // The descriptor was closed after the fd directory was listed, or its process exited: it no longer points
            // to a socket. While a directory is read, the other descriptors are still read.
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            // The process became unreadable, for example after a setuid exec: the descriptor cannot confirm an owner.
            return null;
        }
    }

    private static bool TryReadInode(string link, out string inode)
    {
        inode = string.Empty;
        var linkTarget = new FileInfo(link).LinkTarget;
        if (linkTarget is null || !linkTarget.StartsWith(SocketLinkPrefix, StringComparison.Ordinal))
        {
            return false;
        }

        var endIndex = linkTarget.IndexOf(']', SocketLinkPrefix.Length);
        if (endIndex <= SocketLinkPrefix.Length)
        {
            return false;
        }

        inode = linkTarget[SocketLinkPrefix.Length..endIndex];
        return true;
    }
}
