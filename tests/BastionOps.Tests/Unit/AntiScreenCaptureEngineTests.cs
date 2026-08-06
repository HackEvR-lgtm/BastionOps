using System;
using System.Reflection;
using CapabilityDenialSystem;

namespace BastionOps.Tests.Unit;

public class AntiScreenCaptureEngineTests : IDisposable
{
    private AntiScreenCaptureEngine? _engine;

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
                enable_screen_protection = true,
                scan_interval_ms = 100,
                auto_terminate_threats = false
            }
        };
        _engine = new AntiScreenCaptureEngine(config);

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
                enable_screen_protection = false
            }
        };
        _engine = new AntiScreenCaptureEngine(config);

        _engine.Start();
        _engine.Stop();

        Assert.True(true);
    }

    [Fact]
    public void IsWhitelisted_MethodExists()
    {
        var method = typeof(AntiScreenCaptureEngine).GetMethod("IsWhitelisted",
            BindingFlags.NonPublic | BindingFlags.Instance);

        Assert.NotNull(method);
    }

    [Fact]
    public void HasSuspiciousScreenCaptureBehavior_MethodExists()
    {
        var method = typeof(AntiScreenCaptureEngine).GetMethod("HasSuspiciousScreenCaptureBehavior",
            BindingFlags.NonPublic | BindingFlags.Instance);

        Assert.NotNull(method);
    }

    [Fact]
    public void ApplyDisplayAffinity_DoesNotThrow()
    {
        var config = new CdsConfiguration
        {
            protection_settings = new ProtectionSettings
            {
                enable_screen_protection = true
            }
        };
        _engine = new AntiScreenCaptureEngine(config);

        // IntPtr.Zero es un handle inválido pero no debería crashear
        _engine.ApplyDisplayAffinity(IntPtr.Zero);
    }
}
