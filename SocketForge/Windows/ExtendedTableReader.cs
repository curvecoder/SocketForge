using System.ComponentModel;
using System.Runtime.InteropServices;

namespace SocketForge.Windows;

/// <summary>
/// Signature shared by <c>GetExtendedTcpTable</c> and <c>GetExtendedUdpTable</c> once the address family and table class are fixed.
/// </summary>
internal delegate uint ExtendedTableQuery(IntPtr buffer, ref int size);

/// <summary>
/// Copies an IP Helper extended table into managed memory.
/// </summary>
internal static class ExtendedTableReader
{
    private const uint NoError = 0;
    private const uint ErrorInsufficientBuffer = 122;

    // Sockets open and close between the size call and the read call; each retry uses the size the API just
    // reported, so a few attempts are enough unless the table grows without pause.
    private const int MaxAttempts = 8;

    internal static byte[] Read(ExtendedTableQuery query, string apiName)
    {
        ArgumentNullException.ThrowIfNull(query);

        var size = 0;
        var result = query(IntPtr.Zero, ref size);
        if (result == NoError)
        {
            return [];
        }

        var attempts = 0;
        while (result == ErrorInsufficientBuffer)
        {
            attempts++;
            if (attempts > MaxAttempts)
            {
                throw new InvalidOperationException($"{apiName} still reported an insufficient buffer after {MaxAttempts} attempts.");
            }

            if (TryReadIntoBuffer(query, ref size, out result) is { } table)
            {
                return table;
            }
        }

        throw new Win32Exception((int)result, $"{apiName} failed with error {result}.");
    }

    private static byte[]? TryReadIntoBuffer(ExtendedTableQuery query, ref int size, out uint result)
    {
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            result = query(buffer, ref size);
            if (result != NoError)
            {
                return null;
            }

            var table = new byte[size];
            Marshal.Copy(buffer, table, 0, size);
            return table;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }
}
