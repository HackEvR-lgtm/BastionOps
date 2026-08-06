using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using CapabilityDenialSystem;

namespace BastionOps.Tests.Helpers;

public static class TestLogger
{
    public static List<string> LogEntries { get; } = new();

    public static void CaptureLogs(Action action)
    {
        LogEntries.Clear();
        string tempLog = Path.Combine(Path.GetTempPath(), $"cds_test_{Guid.NewGuid()}.log");
        
        try
        {
            CdsLogger.Initialize(tempLog);
            action();
            if (File.Exists(tempLog))
            {
                LogEntries.AddRange(File.ReadAllLines(tempLog));
            }
        }
        finally
        {
            try { File.Delete(tempLog); } catch { }
        }
    }
}
