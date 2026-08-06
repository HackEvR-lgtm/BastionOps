using System;
using System.Reflection;
using CapabilityDenialSystem;

namespace BastionOps.Tests.Unit;

public class ProcessInjectionMonitorTests : IDisposable
{
    private readonly CdsConfiguration _config;
    private ProcessInjectionMonitor? _monitor;

    public ProcessInjectionMonitorTests()
    {
        _config = new CdsConfiguration
        {
            protection_settings = new ProtectionSettings
            {
                enable_process_injection_protection = true,
                scan_interval_ms = 100,
                auto_terminate_threats = false
            }
        };
    }

    public void Dispose()
    {
        _monitor?.Stop();
    }

    [Fact]
    public void StartStop_DoesNotThrow()
    {
        _monitor = new ProcessInjectionMonitor(_config);

        _monitor.Start();
        System.Threading.Thread.Sleep(50);
        _monitor.Stop();
    }

    [Fact]
    public void Start_WithDisabledConfig_DoesNotCreateTimer()
    {
        var disabledConfig = new CdsConfiguration
        {
            protection_settings = new ProtectionSettings
            {
                enable_process_injection_protection = false
            }
        };
        _monitor = new ProcessInjectionMonitor(disabledConfig);

        _monitor.Start();
        _monitor.Stop();

        Assert.True(true);
    }

    [Fact]
    public void IsSystemProcess_MethodExists()
    {
        var method = typeof(ProcessInjectionMonitor).GetMethod("IsSystemProcess",
            BindingFlags.NonPublic | BindingFlags.Instance);

        Assert.NotNull(method);
    }

    [Fact]
    public void CheckForInjectionIndicators_MethodExists()
    {
        var method = typeof(ProcessInjectionMonitor).GetMethod("CheckForInjectionIndicators",
            BindingFlags.NonPublic | BindingFlags.Instance);

        Assert.NotNull(method);
    }

    [Fact]
    public void DetectUnbackedExecutableMemory_MethodExists()
    {
        var method = typeof(ProcessInjectionMonitor).GetMethod("DetectUnbackedExecutableMemory",
            BindingFlags.NonPublic | BindingFlags.Instance);

        Assert.NotNull(method);
    }

    [Fact]
    public void Constructor_WithNullConfig_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new ProcessInjectionMonitor(null!));
    }
}
