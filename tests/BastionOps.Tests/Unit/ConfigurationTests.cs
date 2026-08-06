using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using CapabilityDenialSystem;

namespace BastionOps.Tests.Unit;

public class ConfigurationTests : IDisposable
{
    private readonly string _configPath;

    public ConfigurationTests()
    {
        _configPath = Path.Combine(Path.GetTempPath(), $"cds_config_{Guid.NewGuid()}.json");
    }

    public void Dispose()
    {
        try { File.Delete(_configPath); } catch { }
    }

    [Fact]
    public void Deserialize_ValidConfig_ReturnsObject()
    {
        var config = CreateValidConfig();
        string json = JsonSerializer.Serialize(config);
        File.WriteAllText(_configPath, json);

        string content = File.ReadAllText(_configPath);
        var result = JsonSerializer.Deserialize<CdsConfiguration>(content);

        Assert.NotNull(result);
        Assert.Equal("1.0.0", result.system_version);
        Assert.Equal("MAXIMUM_ISOLATION", result.security_level);
        Assert.NotNull(result.logging);
        Assert.True(result.logging.enabled);
        Assert.NotNull(result.whitelisted_processes);
        Assert.Single(result.whitelisted_processes);
        Assert.NotNull(result.network_rules);
        Assert.True(result.network_rules.block_all_outbound_by_default);
        Assert.NotNull(result.protection_settings);
        Assert.True(result.protection_settings.auto_terminate_threats);
    }

    [Fact]
    public void Deserialize_MissingOptionalSections_HandlesGracefully()
    {
        var minimalConfig = new
        {
            system_version = "1.0.0",
            security_level = "TEST"
        };
        string json = JsonSerializer.Serialize(minimalConfig);
        File.WriteAllText(_configPath, json);

        var result = JsonSerializer.Deserialize<CdsConfiguration>(File.ReadAllText(_configPath));

        Assert.NotNull(result);
        Assert.Null(result.logging);
        Assert.Null(result.whitelisted_processes);
    }

    [Fact]
    public void WhitelistEntry_Validation_Works()
    {
        var entry = new WhitelistEntry
        {
            name = "test.exe",
            path = @"C:\Windows\test.exe",
            sha256 = "aabbccdd11223344556677889900aabbccdd11223344556677889900aabbccdd",
            allow_screen_capture = true,
            allow_keyboard_hooks = false,
            allow_network_outbound = true
        };

        Assert.Equal("test.exe", entry.name);
        Assert.True(entry.allow_screen_capture);
        Assert.False(entry.allow_keyboard_hooks);
        Assert.True(entry.allow_network_outbound);
    }

    [Fact]
    public void NetworkRules_DnsResolvers_NotNull()
    {
        var rules = new NetworkRules
        {
            block_all_outbound_by_default = true,
            allowed_dns_resolvers = new List<string> { "1.1.1.1", "8.8.8.8" }
        };

        Assert.NotNull(rules.allowed_dns_resolvers);
        Assert.Equal(2, rules.allowed_dns_resolvers.Count);
    }

    [Fact]
    public void ProtectionSettings_DefaultValues_AreCorrect()
    {
        var settings = new ProtectionSettings
        {
            enable_screen_protection = true,
            enable_keylog_protection = true,
            enable_process_injection_protection = true,
            enable_network_protection = true,
            enable_persistence_monitor = true,
            scan_interval_ms = 1000,
            auto_terminate_threats = true
        };

        Assert.True(settings.enable_screen_protection);
        Assert.Equal(1000, settings.scan_interval_ms);
    }

    [Fact]
    public void CdsConfiguration_Serialization_RoundTrip()
    {
        var original = CreateValidConfig();
        string json = JsonSerializer.Serialize(original);
        var deserialized = JsonSerializer.Deserialize<CdsConfiguration>(json);

        Assert.NotNull(deserialized);
        Assert.Equal(original.system_version, deserialized.system_version);
        Assert.Equal(original.security_level, deserialized.security_level);
    }

    [Fact]
    public void WhitelistEntry_HashComparison_IsCaseInsensitive()
    {
        var entry = new WhitelistEntry
        {
            sha256 = "AABBCCDD11223344556677889900AABBCCDD11223344556677889900AABBCCDD"
        };

        bool matches = entry.sha256.Equals("aabbccdd11223344556677889900aabbccdd11223344556677889900aabbccdd", StringComparison.OrdinalIgnoreCase);

        Assert.True(matches);
    }

    private static CdsConfiguration CreateValidConfig()
    {
        return new CdsConfiguration
        {
            system_version = "1.0.0",
            security_level = "MAXIMUM_ISOLATION",
            logging = new LoggingConfig
            {
                enabled = true,
                log_path = @"C:\ProgramData\CDS\logs\audit.log"
            },
            whitelisted_processes = new List<WhitelistEntry>
            {
                new WhitelistEntry
                {
                    name = "explorer.exe",
                    path = @"C:\Windows\explorer.exe",
                    sha256 = "0000000000000000000000000000000000000000000000000000000000000000",
                    allow_screen_capture = true,
                    allow_keyboard_hooks = true,
                    allow_network_outbound = false
                }
            },
            network_rules = new NetworkRules
            {
                block_all_outbound_by_default = true,
                allowed_dns_resolvers = new List<string> { "1.1.1.1", "8.8.8.8" }
            },
            registry_monitor_paths = new List<string>
            {
                @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            },
            protection_settings = new ProtectionSettings
            {
                enable_screen_protection = true,
                enable_keylog_protection = true,
                enable_process_injection_protection = true,
                enable_network_protection = true,
                enable_persistence_monitor = true,
                scan_interval_ms = 1000,
                auto_terminate_threats = true
            }
        };
    }
}
