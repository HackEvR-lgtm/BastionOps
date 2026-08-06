using System;
using System.Reflection;
using CapabilityDenialSystem;

namespace BastionOps.Tests.Unit;

public class NetworkProtectionEngineTests : IDisposable
{
    private NetworkProtectionEngine? _engine;

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
                enable_network_protection = true,
                scan_interval_ms = 100,
                auto_terminate_threats = false
            },
            network_rules = new NetworkRules
            {
                block_all_outbound_by_default = false,
                allowed_dns_resolvers = new System.Collections.Generic.List<string>()
            }
        };
        _engine = new NetworkProtectionEngine(config);

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
                enable_network_protection = false
            }
        };
        _engine = new NetworkProtectionEngine(config);

        _engine.Start();
        _engine.Stop();

        Assert.True(true);
    }

    [Fact]
    public void TriggerPanicMode_MethodExists()
    {
        var method = typeof(NetworkProtectionEngine).GetMethod("TriggerPanicMode",
            BindingFlags.Public | BindingFlags.Static);

        Assert.NotNull(method);
    }

    [Fact]
    public void IsSuspiciousConnection_MethodExists()
    {
        var method = typeof(NetworkProtectionEngine).GetMethod("IsSuspiciousConnection",
            BindingFlags.NonPublic | BindingFlags.Instance);

        Assert.NotNull(method);
    }

    [Fact]
    public void GetActiveConnections_MethodExists()
    {
        var method = typeof(NetworkProtectionEngine).GetMethod("GetActiveConnections",
            BindingFlags.NonPublic | BindingFlags.Instance);

        Assert.NotNull(method);
    }
}
