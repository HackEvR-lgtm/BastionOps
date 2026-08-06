using System;
using System.IO;
using System.Linq;
using System.Threading;
using CapabilityDenialSystem;

namespace BastionOps.Tests.Unit;

public class LoggerTests : IDisposable
{
    private readonly string _logPath;

    public LoggerTests()
    {
        _logPath = Path.Combine(Path.GetTempPath(), $"cds_logger_test_{Guid.NewGuid()}.log");
    }

    public void Dispose()
    {
        try { File.Delete(_logPath); } catch { }
    }

    [Fact]
    public void Initialize_CreatesDirectory()
    {
        string dir = Path.Combine(Path.GetTempPath(), $"cds_test_dir_{Guid.NewGuid()}");
        string logFile = Path.Combine(dir, "test.log");

        try
        {
            CdsLogger.Initialize(logFile);

            Assert.True(Directory.Exists(dir));
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { }
        }
    }

    [Fact]
    public void Log_WritesToFile()
    {
        CdsLogger.Initialize(_logPath);
        string message = $"Test message {Guid.NewGuid()}";

        CdsLogger.Info(message, "TestSource");

        Assert.True(File.Exists(_logPath));
        string content = File.ReadAllText(_logPath);
        Assert.Contains(message, content);
        Assert.Contains("[INFO]", content);
        Assert.Contains("[TestSource]", content);
    }

    [Fact]
    public void Log_ThreadSafe_MultipleConcurrentWrites()
    {
        CdsLogger.Initialize(_logPath);
        int threadCount = 10;
        int messagesPerThread = 20;
        var threads = new System.Collections.Generic.List<Thread>();

        for (int i = 0; i < threadCount; i++)
        {
            int threadId = i;
            var t = new Thread(() =>
            {
                for (int j = 0; j < messagesPerThread; j++)
                {
                    CdsLogger.Info($"Thread {threadId} Message {j}", "ConcurrencyTest");
                }
            });
            threads.Add(t);
            t.Start();
        }

        foreach (var t in threads) t.Join();

        string[] lines = File.ReadAllLines(_logPath);
        Assert.Equal(threadCount * messagesPerThread, lines.Length);
    }

    [Fact]
    public void Log_DifferentLevels_ContainCorrectTags()
    {
        CdsLogger.Initialize(_logPath);

        CdsLogger.Info("info msg", "Test");
        CdsLogger.Warning("warn msg", "Test");
        CdsLogger.Error("error msg", "Test");
        CdsLogger.Audit("audit msg", "Test");
        CdsLogger.Threat("threat msg", "Test");

        string content = File.ReadAllText(_logPath);
        Assert.Contains("[INFO]", content);
        Assert.Contains("[WARNING]", content);
        Assert.Contains("[ERROR]", content);
        Assert.Contains("[AUDIT]", content);
        Assert.Contains("[THREAT]", content);
    }

    [Fact]
    public void Log_IncludesTimestamp()
    {
        CdsLogger.Initialize(_logPath);

        CdsLogger.Info("timestamp test", "Test");

        string content = File.ReadAllText(_logPath);
        Assert.Contains(DateTime.Now.ToString("yyyy-MM-dd"), content);
    }

    [Fact]
    public void Log_WithEmptyMessage_Works()
    {
        CdsLogger.Initialize(_logPath);

        CdsLogger.Info("", "Test");

        string[] lines = File.ReadAllLines(_logPath);
        Assert.Single(lines);
    }

    [Fact]
    public void Log_WithSpecialCharacters_PreservesContent()
    {
        CdsLogger.Initialize(_logPath);
        string special = "Special: \"quotes\" <tags> & ampersands \n newlines";

        CdsLogger.Info(special, "Test");

        string content = File.ReadAllText(_logPath);
        Assert.Contains(special, content);
    }
}
