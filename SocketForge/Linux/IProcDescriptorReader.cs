namespace SocketForge.Linux;

/// <summary>
/// Reads the socket descriptors that processes hold, from the <c>fd</c> directories of a /proc tree.
/// </summary>
internal interface IProcDescriptorReader
{
    /// <summary>
    /// Lists the processes present in the /proc tree.
    /// </summary>
    /// <returns>The process identifiers, or an empty list when the tree cannot be listed.</returns>
    IReadOnlyList<int> ListProcessIds();

    /// <summary>
    /// Reads the socket descriptors a process holds.
    /// </summary>
    /// <param name="processId">The process whose descriptors are read.</param>
    /// <returns>
    /// The socket descriptors, or the ones read before the process exited; an empty list when its descriptors cannot be
    /// read.
    /// </returns>
    IReadOnlyList<ProcSocketDescriptor> ReadSocketDescriptors(int processId);

    /// <summary>
    /// Reads the socket inode a descriptor points to now.
    /// </summary>
    /// <param name="location">The <see cref="ProcSocketDescriptor.Location"/> of a descriptor read earlier.</param>
    /// <returns>
    /// The inode, or <see langword="null"/> when the descriptor was closed, no longer points to a socket, or its process
    /// exited.
    /// </returns>
    string? ReadSocketInode(string location);
}

/// <summary>
/// A descriptor that points to a socket.
/// </summary>
/// <param name="Location">Where the descriptor can be read again, for <see cref="IProcDescriptorReader.ReadSocketInode"/>.</param>
/// <param name="Inode">The socket inode, as /proc/net prints it.</param>
internal readonly record struct ProcSocketDescriptor(string Location, string Inode);
