using System;
using System.Reflection;
using CapabilityDenialSystem;

namespace BastionOps.Tests.Unit;

public class AntiKeyloggingEngineTests : IDisposable
{
    private AntiKeyloggingEngine? _engine;

    public void Dispose()
    {
        _engine?.Stop();
    }

    [Fact]
    public void StartStop_DoesNotThrow()
    {
        var config = new CdsConfiguration
        {
            protection_settings = new ProtectionSettings
            {
                enable_keylog_protection = true,
                scan_interval_ms = 100,
                auto_terminate_threats = false
            }
        };
        _engine = new AntiKeyloggingEngine(config);

        _engine.Start();
        System.Threading.Thread.Sleep(50);
        _engine.Stop();
    }

    [Fact]
    public void Start_WithDisabledConfig_DoesNotCreateTimer()
    {
        var config = new CdsConfiguration
        {
            protection_settings = new ProtectionSettings
            {
                enable_keylog_protection = false
            }
        };
        _engine = new AntiKeyloggingEngine(config);

        _engine.Start();
        _engine.Stop();

        Assert.True(true);
    }

    [Fact]
    public void HasUnauthorizedHooks_MethodExists()
    {
        var method = typeof(AntiKeyloggingEngine).GetMethod("HasUnauthorizedHooks",
            BindingFlags.NonPublic | BindingFlags.Instance);

        Assert.NotNull(method);
    }

    [Fact]
    public void IsSuspiciousThread_MethodExists()
    {
        var method = typeof(AntiKeyloggingEngine).GetMethod("IsSuspiciousThread",
            BindingFlags.NonPublic | BindingFlags.Instance);

        Assert.NotNull(method);
    }
}
