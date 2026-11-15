using AwesomeAssertions;
using ProcessForge.Contracts;
using ProcessForge.Inspectors;
using SocketForge.Contracts;
using SocketForge.Factories;
using SocketForge.Linux;
using SocketForge.Windows;
using Xunit;

namespace SocketForge.Tests;

public sealed class SocketScannerFactoryTests
{
    [Fact]
    public void Create_WhenNoInspectorIsGiven_UsesCachingProcessInspector()
    {
        // Act
        var scanner = SocketScannerFactory.Create();

        // Assert
        ProcessInspectorOf(scanner).Should().BeOfType<CachingProcessInspector>();
    }

    [Fact]
    public void Create_WhenInspectorIsGiven_UsesItWithoutWrapping()
    {
        // Arrange
        var inspector = new RecordingProcessInspector();

        // Act
        var scanner = SocketScannerFactory.Create(inspector);

        // Assert
        ProcessInspectorOf(scanner).Should().BeSameAs(inspector);
    }

    private static IProcessInspector ProcessInspectorOf(ISocketScanner scanner) => scanner switch
    {
        WindowsSocketScanner windows => windows.ProcessInspector,
        LinuxProcSocketScanner linux => linux.ProcessInspector,
        _ => throw new InvalidOperationException($"Unexpected scanner type {scanner.GetType().Name}."),
    };
}
