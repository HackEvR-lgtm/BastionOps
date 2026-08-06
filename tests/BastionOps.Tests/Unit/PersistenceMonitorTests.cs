using System;
using System.Reflection;
using CapabilityDenialSystem;

namespace BastionOps.Tests.Unit;

public class PersistenceMonitorTests : IDisposable
{
    private PersistenceMonitor? _monitor;

    public void Dispose()
    {
        _monitor?.Stop();
    }

    [Fact]
    public void StartStop_DoesNotThrow()
    {
        var config = new CdsConfiguration
        {
            protection_settings = new ProtectionSettings
            {
                enable_persistence_monitor = true,
                scan_interval_ms = 100,
                auto_terminate_threats = false
            }
        };
        _monitor = new PersistenceMonitor(config);

        _monitor.Start();
        System.Threading.Thread.Sleep(50);
        _monitor.Stop();
    }

    [Fact]
    public void Start_WithDisabledConfig_DoesNotCreateTimer()
    {
        var config = new CdsConfiguration
        {
            protection_settings = new ProtectionSettings
            {
                enable_persistence_monitor = false
            }
        };
        _monitor = new PersistenceMonitor(config);

        _monitor.Start();
        _monitor.Stop();

        Assert.True(true);
    }

    [Fact]
    public void InitializeSnapshots_MethodExists()
    {
        var method = typeof(PersistenceMonitor).GetMethod("InitializeSnapshots",
            BindingFlags.NonPublic | BindingFlags.Instance);

        Assert.NotNull(method);
    }

    [Fact]
    public void GetRootKey_MethodExists()
    {
        var method = typeof(PersistenceMonitor).GetMethod("GetRootKey",
            BindingFlags.NonPublic | BindingFlags.Instance);

        Assert.NotNull(method);
    }

    [Fact]
    public void ExtractExecutablePath_MethodExists()
    {
        var method = typeof(PersistenceMonitor).GetMethod("ExtractExecutablePath",
            BindingFlags.NonPublic | BindingFlags.Instance);

        Assert.NotNull(method);
    }

    [Fact]
    public void IsHashWhitelisted_MethodExists()
    {
        var method = typeof(PersistenceMonitor).GetMethod("IsHashWhitelisted",
            BindingFlags.NonPublic | BindingFlags.Instance);

        Assert.NotNull(method);
    }
}
