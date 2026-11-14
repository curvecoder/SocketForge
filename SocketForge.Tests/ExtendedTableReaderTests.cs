using System.ComponentModel;
using System.Runtime.InteropServices;
using AwesomeAssertions;
using SocketForge.Windows;
using Xunit;

namespace SocketForge.Tests;

public sealed class ExtendedTableReaderTests
{
    private const uint NoError = 0;
    private const uint ErrorInsufficientBuffer = 122;
    private const uint ErrorInvalidParameter = 87;

    [Fact]
    public void Read_WhenTableGrowsBetweenSizeAndReadCalls_RetriesWithTheNewSize()
    {
        // Arrange: the table holds one row at the size call and two rows when the first read happens
        var calls = 0;
        uint Query(IntPtr buffer, ref int size)
        {
            calls++;
            var required = calls == 1 ? 8 : 12;
            if (buffer == IntPtr.Zero || size < required)
            {
                size = required;
                return ErrorInsufficientBuffer;
            }

            Marshal.WriteInt32(buffer, 0, 2);
            Marshal.WriteInt32(buffer, 4, 0x11);
            Marshal.WriteInt32(buffer, 8, 0x22);
            return NoError;
        }

        // Act
        var table = ExtendedTableReader.Read(Query, "GetExtendedTcpTable");

        // Assert
        table.Should().Equal(2, 0, 0, 0, 0x11, 0, 0, 0, 0x22, 0, 0, 0);
        calls.Should().Be(3);
    }

    [Fact]
    public void Read_WhenReadCallReturnsAnotherError_ThrowsWin32Exception()
    {
        // Arrange
        uint Query(IntPtr buffer, ref int size)
        {
            if (buffer == IntPtr.Zero)
            {
                size = 8;
                return ErrorInsufficientBuffer;
            }

            return ErrorInvalidParameter;
        }

        // Act
        var act = () => ExtendedTableReader.Read(Query, "GetExtendedUdpTable");

        // Assert
        act.Should().Throw<Win32Exception>()
            .Where(ex => ex.NativeErrorCode == (int)ErrorInvalidParameter && ex.Message.Contains("GetExtendedUdpTable", StringComparison.Ordinal));
    }

    [Fact]
    public void Read_WhenSizeCallReturnsAnotherError_ThrowsWin32Exception()
    {
        // Arrange
        static uint Query(IntPtr buffer, ref int size) => ErrorInvalidParameter;

        // Act
        var act = () => ExtendedTableReader.Read(Query, "GetExtendedTcpTable");

        // Assert
        act.Should().Throw<Win32Exception>()
            .Where(ex => ex.NativeErrorCode == (int)ErrorInvalidParameter);
    }

    [Fact]
    public void Read_WhenLastAttemptReturnsAnotherError_ThrowsWin32Exception()
    {
        // Arrange: the table grows on every read until the last allowed attempt, which fails for another reason
        var reads = 0;
        uint Query(IntPtr buffer, ref int size)
        {
            if (buffer != IntPtr.Zero && ++reads == 8)
            {
                return ErrorInvalidParameter;
            }

            size += 8;
            return ErrorInsufficientBuffer;
        }

        // Act
        var act = () => ExtendedTableReader.Read(Query, "GetExtendedTcpTable");

        // Assert
        act.Should().Throw<Win32Exception>()
            .Where(ex => ex.NativeErrorCode == (int)ErrorInvalidParameter);
    }

    [Fact]
    public void Read_WhenTableKeepsGrowing_ThrowsInvalidOperationException()
    {
        // Arrange
        uint Query(IntPtr buffer, ref int size)
        {
            size += 8;
            return ErrorInsufficientBuffer;
        }

        // Act
        var act = () => ExtendedTableReader.Read(Query, "GetExtendedTcpTable");

        // Assert
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*GetExtendedTcpTable*");
    }

    [Fact]
    public void Read_WhenSizeCallSucceedsWithoutBuffer_ReturnsEmptyTable()
    {
        // Arrange
        static uint Query(IntPtr buffer, ref int size) => NoError;

        // Act
        var table = ExtendedTableReader.Read(Query, "GetExtendedTcpTable");

        // Assert
        table.Should().BeEmpty();
    }
}
