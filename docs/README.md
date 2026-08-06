# BastionOps v2.0 — Host-Based Defense Platform for APTs, RATs & Data Exfiltration Prevention

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/HackEvR-lgtm/BastionOps)
[![Tests](https://img.shields.io/badge/tests-50%2B-blue)](https://github.com/HackEvR-lgtm/BastionOps/tree/main/tests)
[![.NET](https://img.shields.io/badge/.NET-8.0-blueviolet)](https://dotnet.microsoft.com/)
[![License](https://img.shields.io/badge/license-Defensive%20Use%20Only-orange)](LICENSE)

---

## What is BastionOps?

**BastionOps** is an advanced host-based defense system built on the **Assume Breach** paradigm. Rather than attempting to prevent initial compromise, it **neutralizes attacker capabilities** post-infiltration — rendering them blind, deaf, and mute.

### Real-Time Protection Against:

| Threat | MITRE ATT&CK | Defense Mechanism |
|--------|-------------|-------------------|
| **Screen Capture / Recording** | T1113 | `WDA_EXCLUDEFROMCAPTURE` + GDI/DirectX API monitoring |
| **Keylogging / Input Capture** | T1056.001 | Unauthorized hook scanning (WH_KEYBOARD, WH_KEYBOARD_LL) |
| **Process Injection** | T1055 | RWX region detection via `VirtualQueryEx` + handle monitoring |
| **Data Exfiltration** | T1071, T1041 | Zero-trust egress firewall + hash-based allowlisting |
| **Persistence Mechanisms** | T1547.001, T1053.005 | Continuous Registry Run keys & Scheduled Tasks audit |
| **C2 Communication** | T1071 | Suspicious port blocking (4444, 5555, 31337, etc.) |

---

## Quick Start — 1 Minute

### Option A: Fully Automatic Installation (Recommended)

Download the repo and run **one file**:

```batch
Start-BastionOps-Auto.bat
```

**This handles everything automatically:**
- Verifies admin privileges (auto-elevates if needed)
- Verifies / installs .NET 8.0 SDK
- Builds the project in Release mode
- Installs the Windows Service
- Starts protection
- Verifies everything is running

### Option B: Interactive Mode (Manual Control)

```batch
Start-BastionOps.bat
```

### Option C: PowerShell (Advanced)

```powershell
# Run as Administrator
.\scripts\Setup-CDS.ps1 -Install
```

---

## System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| **Operating System** | Windows 10 v1809 | Windows 11 / Server 2022 |
| **.NET SDK** | 8.0 | 8.0+ |
| **Privileges** | Administrator | Administrator |
| **RAM** | 4 GB | 8 GB |
| **Disk Space** | 500 MB | 1 GB |

---

## Project Architecture

```
BastionOps/
├── Start-BastionOps-Auto.bat      # Fully automatic initializer
├── Start-BastionOps.bat           # Interactive menu
├── src/
│   ├── usermode/
│   │   ├── Program.cs                     # Main engine (5 protection engines)
│   │   ├── CdsTrayApp.cs                  # System tray application
│   │   ├── KernelDriverCommunicator.cs    # Kernel-mode driver communication
│   │   └── CapabilityDenialSystem.csproj  # .NET 8.0 project
│   ├── kernelmode/
│   │   ├── CdsProtectDriver.c             # Kernel-mode driver (WDK)
│   │   ├── CdsProtectDriver.inf           # Driver installation file
│   │   └── CdsProtectDriver.vcxproj       # Visual Studio project
│   └── installer/
│       ├── CdsInstaller.cs                # Custom installer
│       └── CdsInstaller.csproj            # Installer project
├── tests/
│   └── BastionOps.Tests/
│       ├── Unit/                          # Unit tests
│       ├── Integration/                   # Integration tests
│       ├── Helpers/                       # Test utilities
│       └── BastionOps.Tests.csproj        # xUnit project
├── scripts/
│   ├── Setup-CDS.ps1                      # PowerShell setup script
│   └── Build-All.ps1                      # Full build script
├── config/
│   └── whitelist.json                     # Allowed processes configuration
└── docs/
    └── README.md                          # This file
```

---

## Manual Build

```bash
# 1. Clone the repository
git clone https://github.com/HackEvR-lgtm/BastionOps.git
cd BastionOps

# 2. Build User-Mode
dotnet build src/usermode/CapabilityDenialSystem.csproj -c Release

# 3. Publish standalone
dotnet publish src/usermode/CapabilityDenialSystem.csproj -c Release   --self-contained true -r win-x64 -o build/usermode

# 4. Build tests
dotnet build tests/BastionOps.Tests/BastionOps.Tests.csproj

# 5. Run tests (on Windows)
dotnet test tests/BastionOps.Tests/BastionOps.Tests.csproj --verbosity normal

# 6. Build kernel driver (requires Visual Studio + WDK)
msbuild src/kernelmode/CdsProtectDriver.vcxproj /p:Configuration=Release /p:Platform=x64
```

---

## Test Suite

BastionOps includes **50+ test cases**:

| Category | File | Cases |
|----------|------|-------|
| **Hash Utility** | `HashUtilityTests.cs` | 6 tests |
| **String Obfuscation** | `StringObfuscatorTests.cs` | 8 tests |
| **Configuration** | `ConfigurationTests.cs` | 7 tests |
| **Logger** | `LoggerTests.cs` | 8 tests |
| **Security Enforcer** | `SecurityEnforcerTests.cs` | 2 tests |
| **Anti-Screen-Capture** | `AntiScreenCaptureEngineTests.cs` | 5 tests |
| **Anti-Keylogging** | `AntiKeyloggingEngineTests.cs` | 4 tests |
| **Process Injection** | `ProcessInjectionMonitorTests.cs` | 6 tests |
| **Network Protection** | `NetworkProtectionEngineTests.cs` | 5 tests |
| **Persistence Monitor** | `PersistenceMonitorTests.cs` | 6 tests |
| **Daemon Integration** | `CdsDaemonIntegrationTests.cs` | 3 tests |
| **Config Protector** | `ConfigurationProtectorTests.cs` | 2 tests |

---

## Bug Fixes Applied (v2.0)

| Bug | Severity | Fix |
|-----|----------|-----|
| 64-bit overflow in `VirtualQueryEx` | Critical | `IntPtr.Add` -> `new IntPtr(ToInt64())` |
| `kernelRegistered` always `true` | Critical | Real try/catch around `RegisterCdsPid()` |
| NullReferenceException in config | High | Null-coalescing (`??=`) for missing sections |
| HICON memory leak in tray icon | High | `DestroyIcon()` in `finally` block |
| Broken UI layout | Medium | Proper nested `Panel` with `Controls.Add()` |
| `CreateStatLabel` returned Label | Medium | Now returns `Panel` as intended |
| `UpdateDashboardStats` broken | Medium | Recursive search in nested Panels |
| Typo `Get-CDSSStatus` in PowerShell | Low | Fixed to `Get-CDSStatus` |
| Missing `ProtectedData` package | Low | Added `System.Security.Cryptography.ProtectedData` |
| Truncated `Program.cs` closure | Critical | Added catch block + class closures |
| Missing `EnableWindowsTargeting` | Medium | Added for cross-platform build |
| `Process.Start` without null check | Medium | Added `if (p == null)` verification |
| `Registry.GetValue` with `null` valueName | Medium | Uses `GetValueNames()` + loop |
| `RemoveRegistryEntry` incorrect logic | Medium | Exact name + content comparison |
| Unreachable code post-`Exit(1)` | Low | Removed dead code |

---

## Windows Service Usage

```powershell
# Check status
sc query BastionOps

# Start
sc start BastionOps

# Stop
sc stop BastionOps

# Uninstall
sc delete BastionOps
rmdir /S /Q "C:\Program Files\BastionOps"
```

---

## Panic Mode

```batch
# From interactive menu (option 10)
Start-BastionOps.bat

# Or manually via netsh:
netsh advfirewall firewall add rule name=BastionOps_Panic_Block dir=out action=block profile=any
netsh advfirewall firewall add rule name=BastionOps_Panic_DNS dir=out action=allow protocol=udp remoteport=53 profile=any

# To deactivate:
netsh advfirewall firewall delete rule name=BastionOps_Panic_Block
netsh advfirewall firewall delete rule name=BastionOps_Panic_DNS
```

---

## Logs

| Type | Location |
|------|----------|
| Audit Log | `C:\ProgramData\BastionOps\logs\audit.log` |
| Initialization Log | `logs\auto_init_YYYYMMDD_HHMMSS.log` |
| Setup Log | `C:\ProgramData\BastionOps\logs\setup.log` |

```powershell
# View logs in real-time
Get-Content C:\ProgramData\BastionOps\logs\audit.log -Tail 50 -Wait

# Search for detected threats
Select-String -Path C:\ProgramData\BastionOps\logs\audit.log -Pattern "THREAT"
```

---

## Troubleshooting

### Build Fails
```bash
dotnet --version
rm -rf src/usermode/obj src/usermode/bin
dotnet build src/usermode/CapabilityDenialSystem.csproj -c Release
```

### Service Won't Start
```powershell
sc query BastionOps
Get-EventLog -LogName Application -Source ".NET Runtime" -Newest 20
Get-Content config\whitelist.json | ConvertFrom-Json
```

### Legitimate Software Blocked
1. Get SHA256: `Get-FileHash C:\Path\app.exe`
2. Add to `config\whitelist.json`
3. Restart: `sc stop BastionOps && sc start BastionOps`

---

## Known Limitations

- Does not protect against kernel-mode rootkits (requires compiled WDK driver)
- .NET runtime dependency (potential attack vector)
- Heuristic screen capture detection (not absolute)
- May affect legitimate software not listed in whitelist

---

## License

This software is provided **solely for defensive security purposes**. Use responsibly and only on systems you own or have explicit authorization to protect.

---

## Credits

- **Original Development:** HackEvR-lgtm
- **Audit & Fixes:** qwen.ai (bot) + manual review
- **Test Suite:** xUnit + Moq
- **Kernel Driver:** Windows Driver Kit (WDK)

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| **2.0** | 2026-08 | 15+ bugs fixed, test suite, auto script, verified build |
| 1.0 | 2024 | Initial release with 5 protection engines |

---

**Repository:** https://github.com/HackEvR-lgtm/BastionOps
