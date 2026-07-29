using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using ThreadingTimer = System.Threading.Timer;
using Microsoft.Win32;

namespace CapabilityDenialSystem
{
    #region Win32 API Declarations

    public static class Win32Api
    {
        // User32.dll - Screen Capture & Input APIs
        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr GetDC(IntPtr hWnd);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr GetWindowDC(IntPtr hWnd);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern int ReleaseDC(IntPtr hWnd, IntPtr hDC);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr GetDesktopWindow();

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool PrintWindow(IntPtr hwnd, IntPtr hDC, uint nFlags);

        [DllImport("gdi32.dll", SetLastError = true)]
        public static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight,
            IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);

        [DllImport("gdi32.dll", SetLastError = true)]
        public static extern bool StretchBlt(IntPtr hdcDest, int nXOriginDest, int nYOriginDest,
            int nWidthDest, int nHeightDest, IntPtr hdcSrc, int nXOriginSrc, int nYOriginSrc,
            int nWidthSrc, int nHeightSrc, uint dwRop);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool SetWindowDisplayAffinity(IntPtr hWnd, uint dwAffinity);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr SetWindowsHookExW(int idHook, HookProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll", SetLastError = true)]
        public static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

        // Kernel32.dll - Process & Memory APIs
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress,
            out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint GetLastError();

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        public static extern uint GetModuleFileName(IntPtr hModule, [MarshalAs(UnmanagedType.LPWStr)] StringBuilder lpFilename, uint nSize);

        // Advapi32.dll - Security & Registry APIs
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint GetSecurityInfo(IntPtr handle, SE_OBJECT_TYPE ObjectType,
            uint SecurityInfo, IntPtr psidOwner, IntPtr psidGroup,
            out IntPtr pDACL, IntPtr pSACL, out IntPtr ppSecurityDescriptor);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint SetSecurityInfo(IntPtr handle, SE_OBJECT_TYPE ObjectType,
            uint SecurityInfo, IntPtr psidOwner, IntPtr psidGroup,
            IntPtr pDACL, IntPtr pSACL);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
            string StringSecurityDescriptor, uint StringSDRevision,
            out IntPtr SecurityDescriptor, out uint SecurityDescriptorSize);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool InitializeSecurityDescriptor(
            IntPtr pSecurityDescriptor, uint dwRevision);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool SetSecurityDescriptorDacl(
            IntPtr pSecurityDescriptor, bool bDaclPresent, IntPtr pDacl, bool bDaclDefaulted);

        // Constants
        public const uint WDA_EXCLUDEFROMCAPTURE = 0x11;
        public const uint WDA_MONITOR = 0x12;
        
        public const int WH_KEYBOARD = 2;
        public const int WH_KEYBOARD_LL = 13;
        public const int WH_GETMESSAGE = 3;
        
        public const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
        public const uint PROCESS_VM_WRITE = 0x0020;
        public const uint PROCESS_VM_OPERATION = 0x0008;
        public const uint PROCESS_VM_READ = 0x0010;
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;
        
        public const uint PAGE_EXECUTE_READWRITE = 0x40;
        public const uint PAGE_READWRITE = 0x04;
        public const uint PAGE_EXECUTE = 0x10;
        
        public const uint DACL_SECURITY_INFORMATION = 0x00000004;
        public const uint OWNER_SECURITY_INFORMATION = 0x00000001;
        
        public const int ERROR_SUCCESS = 0;
        
        public const int SRCCOPY = 0x00CC0020;

        // Delegates
        public delegate IntPtr HookProc(int nCode, IntPtr wParam, IntPtr lParam);

        // Enums
        public enum SE_OBJECT_TYPE : uint
        {
            SE_KERNEL_OBJECT = 7,
            SE_WINDOW_OBJECT = 8,
            SE_SERVICE = 5,
            SE_PRINTER = 3,
            SE_FILE_OBJECT = 1,
            SE_REGISTRY_KEY = 4,
            SE_LMSHARE = 4,
            SE_DS = 11
        }

        // Structures
        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KBDLLHOOKSTRUCT
        {
            public uint vkCode;
            public uint scanCode;
            public uint flags;
            public uint time;
            public IntPtr dwExtraInfo;
        }
    }

    #endregion

    #region Configuration Classes

    public class WhitelistEntry
    {
        public string name { get; set; }
        public string path { get; set; }
        public string sha256 { get; set; }
        public bool allow_screen_capture { get; set; }
        public bool allow_keyboard_hooks { get; set; }
        public bool allow_network_outbound { get; set; }
    }

    public class NetworkRules
    {
        public bool block_all_outbound_by_default { get; set; }
        public List<string> allowed_dns_resolvers { get; set; }
    }

    public class LoggingConfig
    {
        public bool enabled { get; set; }
        public string log_path { get; set; }
    }

    public class ProtectionSettings
    {
        public bool enable_screen_protection { get; set; }
        public bool enable_keylog_protection { get; set; }
        public bool enable_process_injection_protection { get; set; }
        public bool enable_network_protection { get; set; }
        public bool enable_persistence_monitor { get; set; }
        public int scan_interval_ms { get; set; }
        public bool auto_terminate_threats { get; set; }
    }

    public class CdsConfiguration
    {
        public string system_version { get; set; }
        public string security_level { get; set; }
        public LoggingConfig logging { get; set; }
        public List<WhitelistEntry> whitelisted_processes { get; set; }
        public NetworkRules network_rules { get; set; }
        public List<string> registry_monitor_paths { get; set; }
        public ProtectionSettings protection_settings { get; set; }
    }

    #endregion

    #region Logger

    public static class CdsLogger
    {
        private static string _logPath = "C:\\ProgramData\\CDS\\logs\\audit.log";
        private static readonly object _lockObj = new object();

        public static void Initialize(string logPath)
        {
            _logPath = logPath;
            try
            {
                string dir = Path.GetDirectoryName(_logPath);
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                {
                    Directory.CreateDirectory(dir);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Failed to create log directory: {ex.Message}");
            }
        }

        public static void Log(string level, string message, string source = "CDS")
        {
            string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
            string logEntry = $"[{timestamp}] [{level}] [{source}] {message}";
            
            lock (_lockObj)
            {
                try
                {
                    File.AppendAllText(_logPath, logEntry + Environment.NewLine);
                    Console.WriteLine(logEntry);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[{timestamp}] [ERROR] [Logger] Failed to write log: {ex.Message}");
                }
            }
        }

        public static void Info(string message, string source = "CDS") => Log("INFO", message, source);
        public static void Warning(string message, string source = "CDS") => Log("WARNING", message, source);
        public static void Error(string message, string source = "CDS") => Log("ERROR", message, source);
        public static void Audit(string message, string source = "AUDIT") => Log("AUDIT", message, source);
        public static void Threat(string message, string source = "THREAT") => Log("THREAT", message, source);
    }

    #endregion

    #region Hash Utility

    public static class HashUtility
    {
        public static string ComputeSha256(string filePath)
        {
            try
            {
                using (SHA256 sha256 = SHA256.Create())
                using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    byte[] hashBytes = sha256.ComputeHash(fs);
                    return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
                }
            }
            catch (Exception ex)
            {
                CdsLogger.Error($"Failed to compute hash for {filePath}: {ex.Message}", "HashUtility");
                return string.Empty;
            }
        }

        public static bool VerifyFileHash(string filePath, string expectedHash)
        {
            if (string.IsNullOrEmpty(filePath) || string.IsNullOrEmpty(expectedHash))
                return false;

            string actualHash = ComputeSha256(filePath);
            return actualHash.Equals(expectedHash, StringComparison.OrdinalIgnoreCase);
        }
    }

    #endregion

    #region Module 1: Anti-Screen-Capture Engine

    public class AntiScreenCaptureEngine
    {
        private CdsConfiguration _config;
        private HashSet<uint> _monitoredProcesses = new HashSet<uint>();
        private ThreadingTimer _monitorTimer;

        public AntiScreenCaptureEngine(CdsConfiguration config)
        {
            _config = config;
        }

        public void Start()
        {
            if (!_config.protection_settings.enable_screen_protection)
            {
                CdsLogger.Info("Screen capture protection is disabled in configuration", "AntiScreenCapture");
                return;
            }

            CdsLogger.Info("Starting Anti-Screen-Capture Engine", "AntiScreenCapture");
            
            int interval = _config.protection_settings.scan_interval_ms;
            _monitorTimer = new ThreadingTimer(MonitorScreenCaptureAttempts, null, interval, interval);
        }

        public void Stop()
        {
            _monitorTimer?.Dispose();
            CdsLogger.Info("Anti-Screen-Capture Engine stopped", "AntiScreenCapture");
        }

        private void MonitorScreenCaptureAttempts(object state)
        {
            try
            {
                Process[] processes = Process.GetProcesses();
                
                foreach (Process proc in processes)
                {
                    try
                    {
                        uint processId = (uint)proc.Id;
                        
                        if (IsWhitelisted(proc))
                            continue;

                        IntPtr desktopHandle = Win32Api.GetDesktopWindow();
                        IntPtr dc = Win32Api.GetDC(desktopHandle);
                        
                        if (dc != IntPtr.Zero)
                        {
                            Win32Api.ReleaseDC(desktopHandle, dc);
                            
                            if (HasSuspiciousScreenCaptureBehavior(proc))
                            {
                                CdsLogger.Threat($"Process {proc.ProcessName} (PID: {processId}) detected attempting screen capture", "AntiScreenCapture");
                                
                                if (_config.protection_settings.auto_terminate_threats)
                                {
                                    TerminateProcess(proc, "Unauthorized screen capture attempt");
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        CdsLogger.Warning($"Error monitoring process {proc.ProcessName}: {ex.Message}", "AntiScreenCapture");
                    }
                    finally
                    {
                        try { proc.Dispose(); } catch { }
                    }
                }
            }
            catch (Exception ex)
            {
                CdsLogger.Error($"Screen capture monitor error: {ex.Message}", "AntiScreenCapture");
            }
        }

        private bool IsWhitelisted(Process proc)
        {
            try
            {
                string procPath = proc.MainModule?.FileName;
                if (string.IsNullOrEmpty(procPath))
                    return false;

                string procHash = HashUtility.ComputeSha256(procPath);
                
                foreach (var entry in _config.whitelisted_processes)
                {
                    if (entry.sha256.Equals(procHash, StringComparison.OrdinalIgnoreCase))
                    {
                        return entry.allow_screen_capture;
                    }
                }
            }
            catch { }
            
            return false;
        }

        private bool HasSuspiciousScreenCaptureBehavior(Process proc)
        {
            try
            {
                var modules = proc.Modules;
                foreach (ProcessModule module in modules)
                {
                    string moduleName = module.ModuleName.ToLower();
                    if (moduleName.Contains("screen") || moduleName.Contains("capture") || 
                        moduleName.Contains("screenshot") || moduleName.Contains("record"))
                    {
                        return true;
                    }
                }

                string[] suspiciousNames = { "snipping", "grabber", "spy", "keylog", "rat", "remote" };
                foreach (string name in suspiciousNames)
                {
                    if (proc.ProcessName.ToLower().Contains(name))
                        return true;
                }
            }
            catch { }
            
            return false;
        }

        private void TerminateProcess(Process proc, string reason)
        {
            try
            {
                CdsLogger.Audit($"Terminating process {proc.ProcessName} (PID: {proc.Id}): {reason}", "AntiScreenCapture");
                proc.Kill();
                proc.WaitForExit(5000);
            }
            catch (Exception ex)
            {
                CdsLogger.Error($"Failed to terminate process {proc.ProcessName}: {ex.Message}", "AntiScreenCapture");
            }
        }

        public void ApplyDisplayAffinity(IntPtr hWnd)
        {
            try
            {
                Win32Api.SetWindowDisplayAffinity(hWnd, Win32Api.WDA_EXCLUDEFROMCAPTURE);
                CdsLogger.Info($"Applied display affinity to window handle {hWnd}", "AntiScreenCapture");
            }
            catch (Exception ex)
            {
                CdsLogger.Error($"Failed to apply display affinity: {ex.Message}", "AntiScreenCapture");
            }
        }
    }

    #endregion

    #region Module 2: Anti-Keylogging Engine

    public class AntiKeyloggingEngine
    {
        private CdsConfiguration _config;
        private List<IntPtr> _authorizedHooks = new List<IntPtr>();
        private ThreadingTimer _hookMonitorTimer;
        private IntPtr _ownHook = IntPtr.Zero;

        public AntiKeyloggingEngine(CdsConfiguration config)
        {
            _config = config;
        }

        public void Start()
        {
            if (!_config.protection_settings.enable_keylog_protection)
            {
                CdsLogger.Info("Keylogging protection is disabled in configuration", "AntiKeylog");
                return;
            }

            CdsLogger.Info("Starting Anti-Keylogging Engine", "AntiKeylog");
            
            int interval = _config.protection_settings.scan_interval_ms;
            _hookMonitorTimer = new ThreadingTimer(MonitorKeyboardHooks, null, interval, interval);
        }

        public void Stop()
        {
            if (_ownHook != IntPtr.Zero)
            {
                Win32Api.UnhookWindowsHookEx(_ownHook);
                _ownHook = IntPtr.Zero;
            }
            _hookMonitorTimer?.Dispose();
            CdsLogger.Info("Anti-Keylogging Engine stopped", "AntiKeylog");
        }

        private void MonitorKeyboardHooks(object state)
        {
            try
            {
                Process[] processes = Process.GetProcesses();
                
                foreach (Process proc in processes)
                {
                    try
                    {
                        if (IsWhitelisted(proc))
                            continue;

                        if (HasUnauthorizedHooks(proc))
                        {
                            CdsLogger.Threat($"Process {proc.ProcessName} (PID: {proc.Id}) has unauthorized keyboard hooks", "AntiKeylog");
                            
                            if (_config.protection_settings.auto_terminate_threats)
                            {
                                TerminateProcess(proc, "Unauthorized keyboard hook detected");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        CdsLogger.Warning($"Error checking process {proc.ProcessName}: {ex.Message}", "AntiKeylog");
                    }
                    finally
                    {
                        try { proc.Dispose(); } catch { }
                    }
                }
            }
            catch (Exception ex)
            {
                CdsLogger.Error($"Hook monitor error: {ex.Message}", "AntiKeylog");
            }
        }

        private bool IsWhitelisted(Process proc)
        {
            try
            {
                string procPath = proc.MainModule?.FileName;
                if (string.IsNullOrEmpty(procPath))
                    return false;

                string procHash = HashUtility.ComputeSha256(procPath);
                
                foreach (var entry in _config.whitelisted_processes)
                {
                    if (entry.sha256.Equals(procHash, StringComparison.OrdinalIgnoreCase))
                    {
                        return entry.allow_keyboard_hooks;
                    }
                }
            }
            catch { }
            
            return false;
        }

        private bool HasUnauthorizedHooks(Process proc)
        {
            try
            {
                string procName = proc.ProcessName.ToLower();
                
                string[] knownKeyloggers = { "keylog", "spy", "logger", "capture", "input", "hook" };
                foreach (string name in knownKeyloggers)
                {
                    if (procName.Contains(name))
                        return true;
                }

                var threads = proc.Threads;
                foreach (System.Diagnostics.ProcessThread thread in threads)
                {
                    if (thread.ThreadState == System.Diagnostics.ThreadState.Wait &&
                        thread.WaitReason == System.Diagnostics.ThreadWaitReason.Executive)
                    {
                        if (IsSuspiciousThread(proc, thread))
                            return true;
                    }
                }
            }
            catch { }
            
            return false;
        }

        private bool IsSuspiciousThread(Process proc, System.Diagnostics.ProcessThread thread)
        {
            try
            {
                string[] suspiciousModules = { "user32", "gdi32", "rawinput" };
                
                foreach (ProcessModule module in proc.Modules)
                {
                    string modName = module.ModuleName.ToLower();
                    if (suspiciousModules.Any(s => modName.Contains(s)))
                    {
                        if (proc.ProcessName.ToLower().Contains("spy") ||
                            proc.ProcessName.ToLower().Contains("keylog") ||
                            proc.ProcessName.ToLower().Contains("rat"))
                        {
                            return true;
                        }
                    }
                }
            }
            catch { }
            
            return false;
        }

        private void TerminateProcess(Process proc, string reason)
        {
            try
            {
                CdsLogger.Audit($"Terminating process {proc.ProcessName} (PID: {proc.Id}): {reason}", "AntiKeylog");
                proc.Kill();
                proc.WaitForExit(5000);
            }
            catch (Exception ex)
            {
                CdsLogger.Error($"Failed to terminate process {proc.ProcessName}: {ex.Message}", "AntiKeylog");
            }
        }
    }

    #endregion

    #region Module 3: Process Injection Monitor

    public class ProcessInjectionMonitor
    {
        private CdsConfiguration _config;
        private ThreadingTimer _injectionMonitorTimer;
        private Dictionary<int, ProcessSnapshot> _processSnapshots = new Dictionary<int, ProcessSnapshot>();

        public ProcessInjectionMonitor(CdsConfiguration config)
        {
            _config = config;
        }

        public void Start()
        {
            if (!_config.protection_settings.enable_process_injection_protection)
            {
                CdsLogger.Info("Process injection protection is disabled in configuration", "ProcessInjection");
                return;
            }

            CdsLogger.Info("Starting Process Injection Monitor", "ProcessInjection");
            
            int interval = _config.protection_settings.scan_interval_ms;
            _injectionMonitorTimer = new ThreadingTimer(MonitorProcessInjection, null, interval, interval);
        }

        public void Stop()
        {
            _injectionMonitorTimer?.Dispose();
            CdsLogger.Info("Process Injection Monitor stopped", "ProcessInjection");
        }

        private void MonitorProcessInjection(object state)
        {
            try
            {
                Process[] processes = Process.GetProcesses();
                var currentPids = new HashSet<int>();

                foreach (Process proc in processes)
                {
                    try
                    {
                        int pid = proc.Id;
                        currentPids.Add(pid);

                        if (IsSystemProcess(proc))
                            continue;

                        if (CheckForInjectionIndicators(proc))
                        {
                            CdsLogger.Threat($"Process {proc.ProcessName} (PID: {pid}) shows injection indicators", "ProcessInjection");
                            
                            if (_config.protection_settings.auto_terminate_threats)
                            {
                                TerminateProcess(proc, "Process injection detected");
                            }
                        }

                        UpdateSnapshot(proc);
                    }
                    catch (Exception ex)
                    {
                        CdsLogger.Warning($"Error monitoring process: {ex.Message}", "ProcessInjection");
                    }
                    finally
                    {
                        try { proc.Dispose(); } catch { }
                    }
                }

                RemoveStaleSnapshots(currentPids);
            }
            catch (Exception ex)
            {
                CdsLogger.Error($"Injection monitor error: {ex.Message}", "ProcessInjection");
            }
        }

        private bool IsSystemProcess(Process proc)
        {
            string[] systemProcesses = { "system", "idle", "smss", "csrss", "wininit", "services", "lsass", "lsm" };
            return systemProcesses.Any(s => proc.ProcessName.ToLower().Equals(s));
        }

        private bool CheckForInjectionIndicators(Process proc)
        {
            try
            {
                // First check using advanced unbacked executable memory detection
                if (DetectUnbackedExecutableMemory(proc))
                {
                    return true;
                }

                IntPtr hProcess = Win32Api.OpenProcess(
                    Win32Api.PROCESS_VM_READ | Win32Api.PROCESS_QUERY_INFORMATION,
                    false, (uint)proc.Id);

                if (hProcess == IntPtr.Zero)
                    return false;

                try
                {
                    IntPtr baseAddr = IntPtr.Zero;
                    Win32Api.MEMORY_BASIC_INFORMATION mbi;

                    while (Win32Api.VirtualQueryEx(hProcess, baseAddr, out mbi, (uint)Marshal.SizeOf<Win32Api.MEMORY_BASIC_INFORMATION>()))
                    {
                        if (mbi.Protect == Win32Api.PAGE_EXECUTE_READWRITE && mbi.RegionSize.ToInt64() > 0)
                        {
                            if (mbi.Type == 0x00020000) 
                            {
                                CdsLogger.Warning($"RWX memory region found in {proc.ProcessName} at {mbi.BaseAddress}", "ProcessInjection");
                                return true;
                            }
                        }

                        baseAddr = IntPtr.Add(mbi.BaseAddress, mbi.RegionSize.ToInt32());
                        
                        if (baseAddr.ToInt64() <= 0)
                            break;
                    }
                }
                finally
                {
                    Win32Api.CloseHandle(hProcess);
                }

                if (HasSuspiciousHandles(proc))
                    return true;
            }
            catch { }
            
            return false;
        }

        /// <summary>
        /// Advanced heuristic: Detects unbacked executable memory regions (shellcode injection indicator)
        /// </summary>
        private bool DetectUnbackedExecutableMemory(Process proc)
        {
            try
            {
                IntPtr hProcess = Win32Api.OpenProcess(
                    Win32Api.PROCESS_QUERY_INFORMATION | Win32Api.PROCESS_VM_READ, 
                    false, 
                    (uint)proc.Id);

                if (hProcess == IntPtr.Zero) return false;

                try
                {
                    IntPtr baseAddress = IntPtr.Zero;
                    Win32Api.MEMORY_BASIC_INFORMATION mbi = new Win32Api.MEMORY_BASIC_INFORMATION();
                    int suspiciousRegionCount = 0;

                    while (Win32Api.VirtualQueryEx(hProcess, baseAddress, out mbi, (uint)Marshal.SizeOf<Win32Api.MEMORY_BASIC_INFORMATION>()))
                    {
                        // Check for MEM_PRIVATE (not backed by a file/image on disk) AND executable permissions
                        bool isPrivate = (mbi.Type == 0x20000); // MEM_PRIVATE
                        bool isExecutable = (mbi.Protect & (0x10 | 0x20 | 0x40 | 0x80)) != 0; // PAGE_EXECUTE, EXECUTE_READ, EXECUTE_READWRITE, EXECUTE_WRITECOPY

                        if (isPrivate && isExecutable && mbi.RegionSize.ToInt64() >= 4096) // Ignore tiny allocations
                        {
                            // Heuristic filter: Allow known JIT compilers to have some private executable memory
                            string[] jitProcesses = { "dotnet", "java", "node", "chrome", "msedge", "firefox" };
                            if (!jitProcesses.Contains(proc.ProcessName.ToLower()))
                            {
                                suspiciousRegionCount++;
                                CdsLogger.Audit($"UNBACKED_EXEC_MEMORY_DETECTED - PID {proc.Id} ({proc.ProcessName}): Suspicious private executable memory at 0x{mbi.BaseAddress:X}, Size: {mbi.RegionSize}", "ProcessInjectionMonitor");
                            }
                        }

                        baseAddress = IntPtr.Add(mbi.BaseAddress, (int)mbi.RegionSize);
                    }

                    // Threshold: More than 1 suspicious unbacked executable region in a non-JIT process is a critical threat
                    return suspiciousRegionCount > 1;
                }
                finally
                {
                    Win32Api.CloseHandle(hProcess);
                }
            }
            catch
            {
                return false;
            }
        }
        private bool HasSuspiciousHandles(Process proc)
        {
            try
            {
                string procName = proc.ProcessName.ToLower();
                string[] suspiciousPatterns = { "inject", "hollow", "shellcode", "payload", "dropper" };
                
                foreach (string pattern in suspiciousPatterns)
                {
                    if (procName.Contains(pattern))
                        return true;
                }

                var handles = GetProcessHandles(proc);
                foreach (var handle in handles)
                {
                    if (handle.Contains("memory") || handle.Contains("section"))
                        return true;
                }
            }
            catch { }
            
            return false;
        }

        private List<string> GetProcessHandles(Process proc)
        {
            var handles = new List<string>();
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "handle.exe",
                    Arguments = $"-p {proc.Id} -accepteula",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (var p = Process.Start(psi))
                {
                    string output = p.StandardOutput.ReadToEnd();
                    p.WaitForExit();
                    
                    string[] lines = output.Split('\n');
                    foreach (string line in lines)
                    {
                        if (!string.IsNullOrWhiteSpace(line))
                            handles.Add(line.ToLower());
                    }
                }
            }
            catch { }
            
            return handles;
        }

        private void UpdateSnapshot(Process proc)
        {
            int pid = proc.Id;
            try
            {
                var snapshot = new ProcessSnapshot
                {
                    Pid = pid,
                    Name = proc.ProcessName,
                    HandleCount = proc.HandleCount,
                    ThreadCount = proc.Threads.Count,
                    Timestamp = DateTime.Now
                };

                if (_processSnapshots.ContainsKey(pid))
                {
                    var prev = _processSnapshots[pid];
                    if (snapshot.HandleCount > prev.HandleCount * 2 ||
                        snapshot.ThreadCount > prev.ThreadCount * 2)
                    {
                        CdsLogger.Warning($"Rapid resource growth in {proc.ProcessName}: Handles {prev.HandleCount}->{snapshot.HandleCount}, Threads {prev.ThreadCount}->{snapshot.ThreadCount}", "ProcessInjection");
                    }
                }

                _processSnapshots[pid] = snapshot;
            }
            catch { }
        }

        private void RemoveStaleSnapshots(HashSet<int> currentPids)
        {
            var staleKeys = _processSnapshots.Keys.Where(k => !currentPids.Contains(k)).ToList();
            foreach (int key in staleKeys)
            {
                _processSnapshots.Remove(key);
            }
        }

        private void TerminateProcess(Process proc, string reason)
        {
            try
            {
                CdsLogger.Audit($"Terminating process {proc.ProcessName} (PID: {proc.Id}): {reason}", "ProcessInjection");
                proc.Kill();
                proc.WaitForExit(5000);
            }
            catch (Exception ex)
            {
                CdsLogger.Error($"Failed to terminate process {proc.ProcessName}: {ex.Message}", "ProcessInjection");
            }
        }

        private class ProcessSnapshot
        {
            public int Pid { get; set; }
            public string Name { get; set; }
            public int HandleCount { get; set; }
            public int ThreadCount { get; set; }
            public DateTime Timestamp { get; set; }
        }
    }

    #endregion

    #region Module 4: Network Protection Engine

    public class NetworkProtectionEngine
    {
        private CdsConfiguration _config;
        private ThreadingTimer _networkMonitorTimer;

        public NetworkProtectionEngine(CdsConfiguration config)
        {
            _config = config;
        }

        public void Start()
        {
            if (!_config.protection_settings.enable_network_protection)
            {
                CdsLogger.Info("Network protection is disabled in configuration", "NetworkProtection");
                return;
            }

            CdsLogger.Info("Starting Network Protection Engine", "NetworkProtection");
            
            ApplyFirewallRules();
            
            int interval = _config.protection_settings.scan_interval_ms * 5;
            _networkMonitorTimer = new ThreadingTimer(MonitorNetworkActivity, null, interval, interval);
        }

        public void Stop()
        {
            _networkMonitorTimer?.Dispose();
            CdsLogger.Info("Network Protection Engine stopped", "NetworkProtection");
        }

        /// <summary>
        /// EMERGENCY: Instantly isolates the machine from all network traffic.
        /// </summary>
        public static void TriggerPanicMode()
        {
            try
            {
                CdsLogger.Audit("CRITICAL_PANIC_MODE_ACTIVATED - EMERGENCY: Initiating total network isolation. Blocking all inbound/outbound traffic.", "NetworkProtectionEngine");

                string panicScript = @"
                    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block -Enabled True;
                    Get-NetFirewallRule | Where-Object { $_.DisplayName -notmatch '^CDS_' } | Disable-NetFirewallRule;
                ";

                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-ExecutionPolicy Bypass -NoProfile -Command \"{panicScript}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (var proc = Process.Start(psi))
                {
                    proc?.WaitForExit(10000);
                }
                
                CdsLogger.Audit("PANIC_MODE_SUCCESS - Network isolation successfully enforced.", "NetworkProtectionEngine");
            }
            catch (Exception ex)
            {
                CdsLogger.Error($"Failed to execute panic mode: {ex.Message}", "NetworkProtectionEngine");
            }
        }

        public void ApplyFirewallRules()
        {
            try
            {
                if (!_config.network_rules.block_all_outbound_by_default)
                {
                    CdsLogger.Info("Outbound blocking is disabled in configuration", "NetworkProtection");
                    return;
                }

                CdsLogger.Info("Applying default outbound block policy", "NetworkProtection");

                string ruleName = "CDS_Default_Block_Outbound";
                string psCommand = $@"
                    $existingRule = Get-NetFirewallRule -Name '{ruleName}' -ErrorAction SilentlyContinue
                    if ($null -eq $existingRule) {{
                        New-NetFirewallRule -Name '{ruleName}' -DisplayName 'CDS Default Block Outbound' -Direction Outbound -Action Block -Enabled True -Profile Any
                    }}
                ";

                ExecutePowerShell(psCommand);

                foreach (string dnsResolver in _config.network_rules.allowed_dns_resolvers)
                {
                    AllowDnsResolver(dnsResolver);
                }

                AllowWhitelistedProcesses();
            }
            catch (Exception ex)
            {
                CdsLogger.Error($"Failed to apply firewall rules: {ex.Message}", "NetworkProtection");
            }
        }

        private void AllowDnsResolver(string resolver)
        {
            try
            {
                string ruleName = $"CDS_Allow_DNS_{resolver.Replace(".", "_")}";
                string psCommand = $@"
                    $existingRule = Get-NetFirewallRule -Name '{ruleName}' -ErrorAction SilentlyContinue
                    if ($null -eq $existingRule) {{
                        New-NetFirewallRule -Name '{ruleName}' -DisplayName 'CDS Allow DNS {resolver}' -Direction Outbound -Action Allow -Protocol UDP -RemotePort 53 -RemoteAddress '{resolver}' -Enabled True -Profile Any
                    }}
                ";

                ExecutePowerShell(psCommand);
                CdsLogger.Info($"Created firewall rule to allow DNS resolver {resolver}", "NetworkProtection");
            }
            catch (Exception ex)
            {
                CdsLogger.Error($"Failed to create DNS allow rule for {resolver}: {ex.Message}", "NetworkProtection");
            }
        }

        private void AllowWhitelistedProcesses()
        {
            foreach (var entry in _config.whitelisted_processes)
            {
                if (entry.allow_network_outbound && !string.IsNullOrEmpty(entry.path))
                {
                    try
                    {
                        string ruleName = $"CDS_Allow_{entry.name.Replace(".", "_")}";
                        string normalizedPath = entry.path.Replace("\\", "\\\\");
                        
                        string psCommand = $@"
                            $existingRule = Get-NetFirewallRule -Name '{ruleName}' -ErrorAction SilentlyContinue
                            if ($null -eq $existingRule) {{
                                New-NetFirewallRule -Name '{ruleName}' -DisplayName 'CDS Allow {entry.name}' -Direction Outbound -Action Allow -Program '{normalizedPath}' -Enabled True -Profile Any
                            }}
                        ";

                        ExecutePowerShell(psCommand);
                        CdsLogger.Info($"Created firewall rule to allow {entry.name}", "NetworkProtection");
                    }
                    catch (Exception ex)
                    {
                        CdsLogger.Error($"Failed to create allow rule for {entry.name}: {ex.Message}", "NetworkProtection");
                    }
                }
            }
        }

        private void MonitorNetworkActivity(object state)
        {
            try
            {
                var activeConnections = GetActiveConnections();
                
                foreach (var conn in activeConnections)
                {
                    if (IsSuspiciousConnection(conn))
                    {
                        CdsLogger.Threat($"Suspicious network connection detected: {conn}", "NetworkProtection");
                    }
                }
            }
            catch (Exception ex)
            {
                CdsLogger.Error($"Network monitor error: {ex.Message}", "NetworkProtection");
            }
        }

        private List<string> GetActiveConnections()
        {
            var connections = new List<string>();
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "netstat.exe",
                    Arguments = "-ano",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (var p = Process.Start(psi))
                {
                    string output = p.StandardOutput.ReadToEnd();
                    p.WaitForExit();
                    
                    string[] lines = output.Split('\n');
                    foreach (string line in lines)
                    {
                        if (line.Contains("ESTABLISHED") || line.Contains("SYN_SENT"))
                        {
                            connections.Add(line.Trim());
                        }
                    }
                }
            }
            catch { }
            
            return connections;
        }

        private bool IsSuspiciousConnection(string connection)
        {
            string lowerConn = connection.ToLower();
            
            string[] suspiciousPorts = { ":4444", ":5555", ":6666", ":31337", ":12345", ":54321" };
            foreach (string port in suspiciousPorts)
            {
                if (lowerConn.Contains(port))
                    return true;
            }

            if (lowerConn.Contains("tor") || lowerConn.Contains("onion"))
                return true;

            return false;
        }

        private void ExecutePowerShell(string command)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-ExecutionPolicy Bypass -Command \"{command}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (var p = Process.Start(psi))
                {
                    string output = p.StandardOutput.ReadToEnd();
                    string error = p.StandardError.ReadToEnd();
                    p.WaitForExit();
                    
                    if (!string.IsNullOrEmpty(error))
                    {
                        CdsLogger.Warning($"PowerShell warning: {error}", "NetworkProtection");
                    }
                }
            }
            catch (Exception ex)
            {
                CdsLogger.Error($"PowerShell execution failed: {ex.Message}", "NetworkProtection");
            }
        }
    }

    #endregion

    #region Module 5: Persistence Monitor

    public class PersistenceMonitor
    {
        private CdsConfiguration _config;
        private ThreadingTimer _persistenceMonitorTimer;
        private Dictionary<string, string> _registrySnapshot = new Dictionary<string, string>();
        private HashSet<string> _taskSnapshot = new HashSet<string>();

        public PersistenceMonitor(CdsConfiguration config)
        {
            _config = config;
        }

        public void Start()
        {
            if (!_config.protection_settings.enable_persistence_monitor)
            {
                CdsLogger.Info("Persistence monitoring is disabled in configuration", "PersistenceMonitor");
                return;
            }

            CdsLogger.Info("Starting Persistence Monitor", "PersistenceMonitor");
            
            InitializeSnapshots();
            
            int interval = _config.protection_settings.scan_interval_ms * 2;
            _persistenceMonitorTimer = new ThreadingTimer(MonitorPersistence, null, interval, interval);
        }

        public void Stop()
        {
            _persistenceMonitorTimer?.Dispose();
            CdsLogger.Info("Persistence Monitor stopped", "PersistenceMonitor");
        }

        private void InitializeSnapshots()
        {
            try
            {
                _registrySnapshot.Clear();
                _taskSnapshot.Clear();

                string[] runKeys = {
                    @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                    @"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    @"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
                };

                foreach (string keyPath in runKeys)
                {
                    try
                    {
                        var values = Microsoft.Win32.Registry.GetValue(keyPath, null, null);
                        if (values != null)
                        {
                            _registrySnapshot[keyPath] = values.ToString();
                        }
                    }
                    catch (Exception ex)
                    {
                        CdsLogger.Warning($"Failed to read registry key {keyPath}: {ex.Message}", "PersistenceMonitor");
                    }
                }

                CaptureScheduledTasks();
            }
            catch (Exception ex)
            {
                CdsLogger.Error($"Failed to initialize persistence snapshots: {ex.Message}", "PersistenceMonitor");
            }
        }

        private void CaptureScheduledTasks()
        {
            try
            {
                string psCommand = @"
                    Get-ScheduledTask | Where-Object { $_.State -eq 'Ready' -or $_.State -eq 'Running' } | 
                    ForEach-Object { $_.TaskPath + $_.TaskName }
                ";

                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-ExecutionPolicy Bypass -Command \"{psCommand}\"",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (var p = Process.Start(psi))
                {
                    string output = p.StandardOutput.ReadToEnd();
                    p.WaitForExit();
                    
                    string[] tasks = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    foreach (string task in tasks)
                    {
                        if (!string.IsNullOrWhiteSpace(task))
                        {
                            _taskSnapshot.Add(task.Trim());
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                CdsLogger.Warning($"Failed to capture scheduled tasks: {ex.Message}", "PersistenceMonitor");
            }
        }

        private void MonitorPersistence(object state)
        {
            try
            {
                MonitorRegistryChanges();
                MonitorScheduledTaskChanges();
            }
            catch (Exception ex)
            {
                CdsLogger.Error($"Persistence monitor error: {ex.Message}", "PersistenceMonitor");
            }
        }

        private void MonitorRegistryChanges()
        {
            string[] runKeys = {
                @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                @"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            };

            foreach (string keyPath in runKeys)
            {
                try
                {
                    var currentValue = Microsoft.Win32.Registry.GetValue(keyPath, null, null);
                    string currentValueStr = currentValue?.ToString() ?? string.Empty;

                    if (_registrySnapshot.ContainsKey(keyPath))
                    {
                        string prevValue = _registrySnapshot[keyPath];
                        if (currentValueStr != prevValue)
                        {
                            CdsLogger.Threat($"Registry change detected in {keyPath}", "PersistenceMonitor");
                            AnalyzeAndRemediateRegistryChange(keyPath, currentValueStr);
                            _registrySnapshot[keyPath] = currentValueStr;
                        }
                    }
                    else
                    {
                        _registrySnapshot[keyPath] = currentValueStr;
                    }
                }
                catch (Exception ex)
                {
                    CdsLogger.Warning($"Failed to monitor registry key {keyPath}: {ex.Message}", "PersistenceMonitor");
                }
            }
        }

        private void AnalyzeAndRemediateRegistryChange(string keyPath, string currentValue)
        {
            try
            {
                string[] entries = currentValue.Split(new[] { '\0' }, StringSplitOptions.RemoveEmptyEntries);
                
                foreach (string entry in entries)
                {
                    if (string.IsNullOrWhiteSpace(entry))
                        continue;

                    string executablePath = ExtractExecutablePath(entry);
                    if (!string.IsNullOrEmpty(executablePath) && File.Exists(executablePath))
                    {
                        string fileHash = HashUtility.ComputeSha256(executablePath);
                        
                        if (!IsHashWhitelisted(fileHash))
                        {
                            CdsLogger.Threat($"Non-whitelisted executable in registry: {executablePath} (Hash: {fileHash})", "PersistenceMonitor");
                            
                            if (_config.protection_settings.auto_terminate_threats)
                            {
                                RemoveRegistryEntry(keyPath, entry);
                                CdsLogger.Audit($"Removed malicious registry entry: {entry}", "PersistenceMonitor");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                CdsLogger.Error($"Failed to analyze registry change: {ex.Message}", "PersistenceMonitor");
            }
        }

        private string ExtractExecutablePath(string registryValue)
        {
            try
            {
                registryValue = registryValue.Trim();
                
                if (registryValue.StartsWith("\""))
                {
                    int endQuote = registryValue.IndexOf('"', 1);
                    if (endQuote > 0)
                    {
                        return registryValue.Substring(1, endQuote - 1);
                    }
                }
                
                string[] parts = registryValue.Split(' ');
                if (parts.Length > 0)
                {
                    string path = parts[0].Trim('"');
                    if (File.Exists(path))
                        return path;
                    
                    if (path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                        return path;
                }
            }
            catch { }
            
            return string.Empty;
        }

        private void RemoveRegistryEntry(string keyPath, string valueName)
        {
            try
            {
                string[] parts = keyPath.Split('\\');
                string hive = parts[0];
                string subKey = string.Join("\\", parts.Skip(1));

                RegistryKey rootKey = GetRootKey(hive);
                if (rootKey != null)
                {
                    using (RegistryKey key = rootKey.OpenSubKey(subKey, true))
                    {
                        if (key != null)
                        {
                            string[] valueNames = key.GetValueNames();
                            foreach (string name in valueNames)
                            {
                                string value = key.GetValue(name)?.ToString();
                                if (value != null && value.Contains(valueName))
                                {
                                    key.DeleteValue(name, false);
                                    CdsLogger.Info($"Deleted registry value: {name}", "PersistenceMonitor");
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                CdsLogger.Error($"Failed to remove registry entry: {ex.Message}", "PersistenceMonitor");
            }
        }

        private RegistryKey GetRootKey(string hive)
        {
            switch (hive.ToUpper())
            {
                case "HKEY_LOCAL_MACHINE":
                case "HKLM":
                    return Registry.LocalMachine;
                case "HKEY_CURRENT_USER":
                case "HKCU":
                    return Registry.CurrentUser;
                case "HKEY_CLASSES_ROOT":
                case "HKCR":
                    return Registry.ClassesRoot;
                default:
                    return null;
            }
        }

        private void MonitorScheduledTaskChanges()
        {
            try
            {
                var currentTasks = new HashSet<string>();
                
                string psCommand = @"
                    Get-ScheduledTask | Where-Object { $_.State -eq 'Ready' -or $_.State -eq 'Running' } | 
                    ForEach-Object { $_.TaskPath + $_.TaskName }
                ";

                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-ExecutionPolicy Bypass -Command \"{psCommand}\"",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (var p = Process.Start(psi))
                {
                    string output = p.StandardOutput.ReadToEnd();
                    p.WaitForExit();
                    
                    string[] tasks = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    foreach (string task in tasks)
                    {
                        if (!string.IsNullOrWhiteSpace(task))
                        {
                            currentTasks.Add(task.Trim());
                        }
                    }
                }

                var newTasks = currentTasks.Except(_taskSnapshot).ToList();
                foreach (string newTask in newTasks)
                {
                    CdsLogger.Threat($"New scheduled task detected: {newTask}", "PersistenceMonitor");
                    AnalyzeAndRemediateTask(newTask);
                }

                _taskSnapshot = currentTasks;
            }
            catch (Exception ex)
            {
                CdsLogger.Error($"Failed to monitor scheduled tasks: {ex.Message}", "PersistenceMonitor");
            }
        }

        private void AnalyzeAndRemediateTask(string taskName)
        {
            try
            {
                string psCommand = $@"
                    $task = Get-ScheduledTask -TaskPath '{taskName.Replace("'", "''")}' -ErrorAction SilentlyContinue
                    if ($task) {{
                        $action = $task.Actions | Select-Object -First 1
                        if ($action) {{
                            $action.Execute
                        }}
                    }}
                ";

                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-ExecutionPolicy Bypass -Command \"{psCommand}\"",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (var p = Process.Start(psi))
                {
                    string executablePath = p.StandardOutput.ReadToEnd().Trim();
                    p.WaitForExit();
                    
                    if (!string.IsNullOrEmpty(executablePath) && File.Exists(executablePath))
                    {
                        string fileHash = HashUtility.ComputeSha256(executablePath);
                        
                        if (!IsHashWhitelisted(fileHash))
                        {
                            CdsLogger.Threat($"Non-whitelisted executable in scheduled task: {executablePath}", "PersistenceMonitor");
                            
                            if (_config.protection_settings.auto_terminate_threats)
                            {
                                RemoveScheduledTask(taskName);
                                CdsLogger.Audit($"Removed malicious scheduled task: {taskName}", "PersistenceMonitor");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                CdsLogger.Error($"Failed to analyze scheduled task: {ex.Message}", "PersistenceMonitor");
            }
        }

        private void RemoveScheduledTask(string taskName)
        {
            try
            {
                string safeTaskName = taskName.Replace("'", "''");
                string psCommand = $@"
                    $task = Get-ScheduledTask -TaskPath '{safeTaskName}' -ErrorAction SilentlyContinue
                    if ($task) {{
                        Unregister-ScheduledTask -TaskPath '{safeTaskName}' -Confirm:$false
                    }}
                ";

                ExecutePowerShell(psCommand);
            }
            catch (Exception ex)
            {
                CdsLogger.Error($"Failed to remove scheduled task {taskName}: {ex.Message}", "PersistenceMonitor");
            }
        }

        private bool IsHashWhitelisted(string hash)
        {
            if (string.IsNullOrEmpty(hash))
                return false;

            foreach (var entry in _config.whitelisted_processes)
            {
                if (entry.sha256.Equals(hash, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        private void ExecutePowerShell(string command)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-ExecutionPolicy Bypass -Command \"{command}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (var p = Process.Start(psi))
                {
                    p.StandardOutput.ReadToEnd();
                    p.StandardError.ReadToEnd();
                    p.WaitForExit();
                }
            }
            catch (Exception ex)
            {
                CdsLogger.Error($"PowerShell execution failed: {ex.Message}", "PersistenceMonitor");
            }
        }
    }

    #endregion

    #region Main CDS Daemon

    public class CdsDaemon
    {
        private CdsConfiguration _config;
        private AntiScreenCaptureEngine _screenEngine;
        private AntiKeyloggingEngine _keylogEngine;
        private ProcessInjectionMonitor _injectionMonitor;
        private NetworkProtectionEngine _networkEngine;
        private PersistenceMonitor _persistenceMonitor;
        private bool _running = false;

        public CdsDaemon()
        {
            LoadConfiguration();
            InitializeEngines();
        }

        private void LoadConfiguration()
        {
            string configPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "whitelist.json");
            
            if (!File.Exists(configPath))
            {
                configPath = "whitelist.json";
            }

            if (!File.Exists(configPath))
            {
                CdsLogger.Error("Configuration file whitelist.json not found", "CDS");
                throw new FileNotFoundException("whitelist.json not found");
            }

            try
            {
                string jsonContent = File.ReadAllText(configPath);
                _config = System.Text.Json.JsonSerializer.Deserialize<CdsConfiguration>(jsonContent);
                
                if (_config.logging.enabled)
                {
                    CdsLogger.Initialize(_config.logging.log_path);
                }
                
                CdsLogger.Info($"CDS Configuration loaded successfully. Version: {_config.system_version}", "CDS");
                CdsLogger.Info($"Security Level: {_config.security_level}", "CDS");
            }
            catch (Exception ex)
            {
                CdsLogger.Error($"Failed to load configuration: {ex.Message}", "CDS");
                throw;
            }
        }

        private void InitializeEngines()
        {
            _screenEngine = new AntiScreenCaptureEngine(_config);
            _keylogEngine = new AntiKeyloggingEngine(_config);
            _injectionMonitor = new ProcessInjectionMonitor(_config);
            _networkEngine = new NetworkProtectionEngine(_config);
            _persistenceMonitor = new PersistenceMonitor(_config);
        }

        public void Start()
        {
            if (_running)
            {
                CdsLogger.Warning("CDS is already running", "CDS");
                return;
            }

            CdsLogger.Info("=========================================", "CDS");
            CdsLogger.Info("Capability Denial System Starting...", "CDS");
            CdsLogger.Info($"Version: {_config.system_version}", "CDS");
            CdsLogger.Info($"Security Level: {_config.security_level}", "CDS");
            CdsLogger.Info("=========================================", "CDS");

            _running = true;

            try
            {
                // Register PID with Kernel Driver (Phase 2: IOCTL Communication)
                int currentPid = System.Diagnostics.Process.GetCurrentProcess().Id;
                bool kernelRegistered = KernelDriverCommunicator.RegisterCdsPid(currentPid);
                
                if (kernelRegistered)
                {
                    CdsLogger.Info($"Kernel-mode protection ACTIVE. PID {currentPid} registered.", "CDS");
                }
                else
                {
                    CdsLogger.Warning("Kernel driver not found. Running in User-Mode only.", "CDS");
                }

                _screenEngine.Start();
                _keylogEngine.Start();
                _injectionMonitor.Start();
                _networkEngine.Start();
                _persistenceMonitor.Start();

                CdsLogger.Info("All protection engines started successfully", "CDS");
                CdsLogger.Info("CDS is now actively protecting the system", "CDS");
            }
            catch (Exception ex)
            {
                CdsLogger.Error($"Failed to start CDS engines: {ex.Message}", "CDS");
                Stop();
                throw;
            }
        }

        public void Stop()
        {
            CdsLogger.Info("Stopping CDS...", "CDS");

            _running = false;

            _screenEngine?.Stop();
            _keylogEngine?.Stop();
            _injectionMonitor?.Stop();
            _networkEngine?.Stop();
            _persistenceMonitor?.Stop();

            CdsLogger.Info("CDS stopped gracefully", "CDS");
            CdsLogger.Info("=========================================", "CDS");
        }

        public void RunInteractive()
        {
            Start();
            
            CdsLogger.Info("Press any key to stop CDS...", "CDS");
            Console.ReadKey(true);
            
            Stop();
        }

        public void RunAsService()
        {
            Start();
            
            while (_running)
            {
                Thread.Sleep(1000);
            }
        }
    }

    #endregion

    #region Security Enforcer - Process Mitigations & Anti-Debugging

    public static class SecurityEnforcer
    {
        [DllImport("kernel32.dll")]
        private static extern bool IsDebuggerPresent();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetProcessMitigationPolicy(int mitigationPolicy, ref PROCESS_MITIGATION_DYNAMIC_CODE_POLICY policy, int size);

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_MITIGATION_DYNAMIC_CODE_POLICY 
        {
            public uint Flags;
        }

        public static void EnforceSecurity()
        {
            try
            {
                // 1. Anti-Debug: Native API Check
                if (IsDebuggerPresent()) 
                {
                    CdsLogger.Audit("CRITICAL: Native debugger detected (IsDebuggerPresent). Terminating immediately.", "SecurityEnforcer");
                    Environment.Exit(1);
                }

                bool isRemoteDebugged = false;
                CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref isRemoteDebugged);
                if (isRemoteDebugged)
                {
                    CdsLogger.Audit("CRITICAL: Remote debugger attached. Terminating immediately.", "SecurityEnforcer");
                    Environment.Exit(1);
                }

                // 2. Anti-Analysis: Suspicious Process Detection
                string[] badProcesses = { "x64dbg", "ollydbg", "cheatengine", "cheatengine-x86_64", "procmon", "procmon64", "wireshark", "fiddler", "processhacker" };
                var runningProcesses = Process.GetProcesses();
                foreach (var p in runningProcesses) 
                {
                    try 
                    {
                        if (badProcesses.Contains(p.ProcessName.ToLower())) 
                        {
                            CdsLogger.Audit($"CRITICAL: Analysis tool detected ({p.ProcessName}). Triggering Network Panic and Terminating.", "SecurityEnforcer");
                            NetworkProtectionEngine.TriggerPanicMode();
                            Environment.Exit(1);
                        }
                    }
                    catch { /* Ignore access denied on system processes */ }
                }

                // 3. Process Hardening: Block Dynamic Code Generation (Mitigates some shellcode injection)
                // Flag 1 = ProhibitDynamicCode
                var policy = new PROCESS_MITIGATION_DYNAMIC_CODE_POLICY { Flags = 1 }; 
                SetProcessMitigationPolicy(2, ref policy, Marshal.SizeOf(policy)); // 2 = ProcessDynamicCodePolicy

                CdsLogger.Audit("Process mitigations and anti-debug checks applied successfully.", "SecurityEnforcer");
            }
            catch (Exception ex)
            {
                CdsLogger.Audit($"Warning: Security enforcement partially failed: {ex.Message}", "SecurityEnforcer");
            }
        }
    }

    #endregion

    #region Configuration Protection (DPAPI)

    public static class ConfigurationProtector
    {
        private static readonly string ConfigPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "CDS", "whitelist.json");

        public static void ProtectConfiguration()
        {
            try
            {
                if (File.Exists(ConfigPath))
                {
                    byte[] plaintext = File.ReadAllBytes(ConfigPath);
                    // Encrypt using LocalMachine scope (only this PC can decrypt it)
                    byte[] encrypted = System.Security.Cryptography.ProtectedData.Protect(
                        plaintext, 
                        null, 
                        System.Security.Cryptography.DataProtectionScope.LocalMachine);
                    
                    File.WriteAllBytes(ConfigPath + ".enc", encrypted);
                    File.Delete(ConfigPath); // Remove plaintext version
                    CdsLogger.Audit("Configuration encrypted and secured via DPAPI.", "ConfigurationProtector");
                }
            }
            catch (Exception ex)
            {
                CdsLogger.Audit($"Warning: Configuration protection failed: {ex.Message}", "ConfigurationProtector");
            }
        }

        public static string LoadProtectedConfiguration()
        {
            try
            {
                string encPath = ConfigPath + ".enc";
                if (File.Exists(encPath))
                {
                    byte[] encrypted = File.ReadAllBytes(encPath);
                    byte[] plaintext = System.Security.Cryptography.ProtectedData.Unprotect(
                        encrypted, 
                        null, 
                        System.Security.Cryptography.DataProtectionScope.LocalMachine);
                    return Encoding.UTF8.GetString(plaintext);
                }
                else if (File.Exists(ConfigPath))
                {
                    // Fallback for first run before encryption
                    return File.ReadAllText(ConfigPath);
                }
            }
            catch (Exception ex)
            {
                CdsLogger.Audit($"CRITICAL: Failed to load protected config: {ex.Message}", "ConfigurationProtector");
            }
            return null;
        }
    }

    #endregion

    #region File Integrity Monitoring (FIM)

    public static class FileIntegrityMonitor
    {
        private static FileSystemWatcher _watcher;

        public static void StartMonitoring()
        {
            try
            {
                string cdsDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "CDS");
                if (!Directory.Exists(cdsDir)) Directory.CreateDirectory(cdsDir);

                _watcher = new FileSystemWatcher(cdsDir)
                {
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                    IncludeSubdirectories = true,
                    EnableRaisingEvents = true
                };

                _watcher.Changed += OnFileSystemChanged;
                _watcher.Created += OnFileSystemChanged;
                _watcher.Deleted += OnFileSystemChanged;
                _watcher.Renamed += OnFileSystemChanged;

                CdsLogger.Audit("File Integrity Monitoring started on CDS directory.", "FileIntegrityMonitor");
            }
            catch (Exception ex)
            {
                CdsLogger.Audit($"Warning: FIM failed to start: {ex.Message}", "FileIntegrityMonitor");
            }
        }

        private static void OnFileSystemChanged(object sender, FileSystemEventArgs e)
        {
            // Ignore our own log files to prevent loops
            if (e.FullPath.ToLower().Contains("audit.log") || e.FullPath.ToLower().Contains("setup.log")) return;

            CdsLogger.Audit($"CRITICAL: Unauthorized file system change detected in CDS directory! File: {e.Name}, ChangeType: {e.ChangeType}", "FileIntegrityMonitor");
            
            // Trigger immediate isolation
            try 
            {
                NetworkProtectionEngine.TriggerPanicMode();
            } 
            catch { }
            
            Environment.Exit(1);
        }
    }

    #endregion

    #region Advanced ETW/WMI Injection Monitoring

    public static class AdvancedInjectionMonitor
    {
        private static ManagementEventWatcher _moduleLoadWatcher;

        public static void StartMonitoring()
        {
            try
            {
                // Listen to Kernel ETW Module Load events via WMI
                var query = new WqlEventQuery("SELECT * FROM Win32_ModuleLoadTrace");
                _moduleLoadWatcher = new ManagementEventWatcher(query);
                _moduleLoadWatcher.EventArrived += OnModuleLoaded;
                _moduleLoadWatcher.Start();

                CdsLogger.Audit("AdvancedInjectionMonitor", "Kernel-level Module Load monitoring (ETW/WMI) started.");
            }
            catch (Exception ex)
            {
                CdsLogger.Audit("AdvancedInjectionMonitor", $"Warning: ETW Module monitoring failed to start: {ex.Message}");
            }
        }

        private static void OnModuleLoaded(object sender, EventArrivedEventArgs e)
        {
            try
            {
                // Extract event data
                string processName = e.NewEvent["ProcessName"]?.ToString()?.ToLower() ?? "";
                string fileName = e.NewEvent["FileName"]?.ToString()?.ToLower() ?? "";

                if (string.IsNullOrEmpty(processName) || string.IsNullOrEmpty(fileName)) return;

                // Define critical system processes we want to protect from injection
                string[] criticalProcesses = { "svchost.exe", "lsass.exe", "explorer.exe", "winlogon.exe", "services.exe" };
                
                if (criticalProcesses.Contains(processName))
                {
                    // Define trusted system directories
                    bool isTrustedPath = fileName.StartsWith(@"c:\windows\system32") || 
                                         fileName.StartsWith(@"c:\windows\syswow64") ||
                                         fileName.StartsWith(@"c:\windows\winsxs");

                    // Define highly suspicious directories (common malware drop zones)
                    bool isSuspiciousPath = fileName.Contains(@"\appdata\") || 
                                            fileName.Contains(@"\temp\") || 
                                            fileName.Contains(@"\downloads\");

                    if (!isTrustedPath && isSuspiciousPath)
                    {
                        CdsLogger.Audit("AdvancedInjectionMonitor", $"CRITICAL: Suspicious module load detected! Process: {processName}, Module: {fileName}");
                        
                        // High confidence threat: Trigger Panic Mode immediately
                        try 
                        {
                            NetworkProtectionEngine.TriggerPanicMode();
                        } 
                        catch { }
                        
                        Environment.Exit(1);
                    }
                    else if (!isTrustedPath)
                    {
                        // Medium confidence: Log it for forensic analysis
                        CdsLogger.Audit("AdvancedInjectionMonitor", $"WARNING: Untrusted module loaded in critical process. Process: {processName}, Module: {fileName}");
                    }
                }
            }
            catch 
            { 
                // Silently ignore parsing errors to prevent crashing the monitor
            }
        }
    }

    #endregion

    #region Program Entry Point

    class Program
    {
        static void Main(string[] args)
        {
            // Enforce security before doing anything else
            SecurityEnforcer.EnforceSecurity();
            
            // Initialize Configuration Protection and FIM
            ConfigurationProtector.ProtectConfiguration();
            FileIntegrityMonitor.StartMonitoring();
            
            // Start Advanced ETW/WMI Injection Monitoring
            AdvancedInjectionMonitor.StartMonitoring();

            Console.OutputEncoding = Encoding.UTF8;
            
            Console.WriteLine("==============================================");
            Console.WriteLine("   CAPABILITY DENIAL SYSTEM (CDS) v2.1");
            Console.WriteLine("   Advanced Host-Based Protection");
            Console.WriteLine("==============================================");
            Console.WriteLine();

            try
            {
                // Check for tray mode argument
                if (args.Contains("--tray") || args.Contains("-t"))
                {
                    // Run with System Tray Dashboard in interactive mode
                    Application.EnableVisualStyles();
                    Application.SetCompatibleTextRenderingDefault(false);
                    
                    using (var trayApp = new CdsTrayApp())
                    {
                        // Start the daemon in a background thread
                        Thread daemonThread = new Thread(() =>
                        {
                            CdsDaemon daemon = new CdsDaemon();
                            daemon.RunAsService();
                        });
                        daemonThread.IsBackground = true;
                        daemonThread.Start();
                        
                        Application.Run(trayApp);
                    }
                    return;
                }

                CdsDaemon daemon = new CdsDaemon();

                if (args.Contains("--service") || args.Contains("-s"))
                {
                    Console.WriteLine("Running as background service...");
                    daemon.RunAsService();
                }
                else
                {
                    daemon.RunInteractive();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[FATAL ERROR] {ex.Message}");
                Console.WriteLine(ex.StackTrace);
                Environment.Exit(1);
            }

            Console.WriteLine();
            Console.WriteLine("CDS shutdown complete.");
        }
    }

    #endregion
}
