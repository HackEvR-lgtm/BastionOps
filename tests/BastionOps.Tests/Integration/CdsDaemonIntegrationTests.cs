using System;
using System.IO;
using System.Text.Json;
using System.Threading;
using CapabilityDenialSystem;

namespace BastionOps.Tests.Integration;

public class CdsDaemonIntegrationTests : IDisposable
{
    private readonly string _testDir;
    private readonly string _configPath;
    private readonly string _logPath;

    public CdsDaemonIntegrationTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), $"cds_test_{Guid.NewGuid()}");
        Directory.CreateDirectory(_testDir);

        _configPath = Path.Combine(_testDir, "whitelist.json");
        _logPath = Path.Combine(_testDir, "audit.log");

        var config = new CdsConfiguration
        {
            system_version = "1.0.0-test",
            security_level = "TEST",
            logging = new LoggingConfig { enabled = true, log_path = _logPath },
            whitelisted_processes = new System.Collections.Generic.List<WhitelistEntry>(),
            network_rules = new NetworkRules
            {
                block_all_outbound_by_default = false,
                allowed_dns_resolvers = new System.Collections.Generic.List<string>()
            },
            protection_settings = new ProtectionSettings
            {
                enable_screen_protection = false,
                enable_keylog_protection = false,
                enable_process_injection_protection = false,
                enable_network_protection = false,
                enable_persistence_monitor = false,
                scan_interval_ms = 5000,
                auto_terminate_threats = false
            }
        };

        File.WriteAllText(_configPath, JsonSerializer.Serialize(config));
    }

    public void Dispose()
    {
        try { Directory.Delete(_testDir, true); } catch { }
    }

    [Fact]
    public void Daemon_StartStop_LifecycleWorks()
    {
        string originalDir = Environment.CurrentDirectory;
        try
        {
            Environment.CurrentDirectory = _testDir;
            var daemon = new CdsDaemon();

            daemon.Start();
            Thread.Sleep(200);
            daemon.Stop();
        }
        finally
        {
            Environment.CurrentDirectory = originalDir;
        }
    }

    [Fact]
    public void Daemon_MultipleStartCalls_HandledGracefully()
    {
        string originalDir = Environment.CurrentDirectory;
        try
        {
            Environment.CurrentDirectory = _testDir;
            var daemon = new CdsDaemon();

            daemon.Start();
            daemon.Start(); // Segunda llamada debería ser ignorada
            Thread.Sleep(100);
            daemon.Stop();
        }
        finally
        {
            Environment.CurrentDirectory = originalDir;
        }
    }

    [Fact]
    public void Daemon_StopWithoutStart_DoesNotThrow()
    {
        string originalDir = Environment.CurrentDirectory;
        try
        {
            Environment.CurrentDirectory = _testDir;
            var daemon = new CdsDaemon();

            daemon.Stop();
        }
        finally
        {
            Environment.CurrentDirectory = originalDir;
        }
    }
}
