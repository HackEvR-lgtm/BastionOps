# Capability Denial System (CDS)

## Advanced Host-Based Protection Against APTs and RATs

### Overview

The Capability Denial System (CDS) is a sophisticated host-based protection software designed to neutralize Advanced Persistent Threats (APTs) and Remote Access Trojans (RATs) using an "Assume Breach" security paradigm. Rather than attempting to prevent initial infection, CDS renders threat capabilities inoperative by denying:

- Screen Recording/Capture
- Keylogging/Input Capture
- Network Exfiltration
- Process Injection
- Persistence Mechanisms

---

## Architecture

CDS consists of five core protection engines:

| Module | Function | MITRE ATT&CK Techniques |
|--------|----------|------------------------|
| **Anti-Screen-Capture Engine** | Blinds GDI/DirectX capture APIs | T1113 (Screen Capture) |
| **Anti-Keylogging Engine** | Detects and removes unauthorized hooks | T1056.001 (Input Capture) |
| **Process Injection Monitor** | Detects RWX memory and cross-process injection | T1055 (Process Injection) |
| **Network Protection Engine** | Zero-trust egress firewall with hash-based allowlisting | T1071, T1041 (Exfiltration) |
| **Persistence Monitor** | Audits Registry Run keys and Scheduled Tasks | T1547.001, T1053.005 |

---

## Requirements

### Operating System
- Windows 10/11 (version 1809 or later recommended)
- Windows Server 2016/2019/2022

### Runtime
- .NET 8.0 SDK (for building) or .NET 8.0 Runtime (for execution)
- Alternative: .NET Framework 4.8

### Privileges
- Administrator privileges required for installation and firewall configuration
- Standard user can run in limited interactive mode

---

## Building from Source

### Prerequisites
```bash
# Install .NET 8.0 SDK from https://dotnet.microsoft.com/download
```

### Build Commands
```bash
# Navigate to source directory
cd /workspace

# Create project file
cat > CapabilityDenialSystem.csproj << 'EOF'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0-windows</TargetFramework>
    <PlatformTarget>x64</PlatformTarget>
    <UseWindowsForms>false</UseWindowsForms>
    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>
    <GenerateAssemblyInfo>true</GenerateAssemblyInfo>
    <AssemblyName>CapabilityDenialSystem</AssemblyName>
    <RootNamespace>CapabilityDenialSystem</RootNamespace>
  </PropertyGroup>
  <ItemGroup>
    <Reference Include="System.Management" />
    <Reference Include="Microsoft.Win32.Registry" />
  </ItemGroup>
</Project>
EOF

# Build Release version for .NET 8.0
dotnet build -c Release

# Or create standalone executable
dotnet publish -c Release -r win-x64 --self-contained -o ./publish

# For .NET Framework 4.8 (requires Visual Studio Build Tools)
msbuild /p:Configuration=Release /p:TargetFrameworkVersion=v4.8
```

---

## Installation

### Automated Installation (Recommended)

Run PowerShell as Administrator:

```powershell
# Execute setup script
.\Setup-CDS.ps1 -Install

# This will:
# 1. Create installation directory at C:\ProgramData\CDS
# 2. Copy binaries and configuration
# 3. Configure Windows Defender Firewall rules
# 4. Register CDS as a Windows Service
```

### Manual Installation

1. Copy `CapabilityDenialSystem.exe` to desired location
2. Copy `whitelist.json` to same directory
3. Configure firewall rules manually (see Setup-CDS.ps1 for reference)
4. Optionally register as service:
   ```powershell
   sc.exe create CDSDaemon binPath= "C:\Path\To\CapabilityDenialSystem.exe --service" start= auto DisplayName= "Capability Denial System"
   ```

---

## Configuration

### whitelist.json Structure

```json
{
  "system_version": "1.0.0",
  "security_level": "MAXIMUM_ISOLATION",
  "logging": {
    "enabled": true,
    "log_path": "C:\\ProgramData\\CDS\\logs\\audit.log"
  },
  "whitelisted_processes": [
    {
      "name": "explorer.exe",
      "path": "C:\\Windows\\explorer.exe",
      "sha256": "<actual_sha256_hash>",
      "allow_screen_capture": true,
      "allow_keyboard_hooks": true,
      "allow_network_outbound": false
    }
  ],
  "network_rules": {
    "block_all_outbound_by_default": true,
    "allowed_dns_resolvers": ["1.1.1.1", "8.8.8.8"]
  },
  "protection_settings": {
    "enable_screen_protection": true,
    "enable_keylog_protection": true,
    "enable_process_injection_protection": true,
    "enable_network_protection": true,
    "enable_persistence_monitor": true,
    "scan_interval_ms": 1000,
    "auto_terminate_threats": true
  }
}
```

### Updating Whitelist Hashes

```powershell
# Automatically update hashes for system executables
.\Setup-CDS.ps1 -UpdateWhitelist
```

---

## Usage

### Interactive Mode
```bash
# Run directly (press any key to stop)
.\CapabilityDenialSystem.exe
```

### Service Mode
```bash
# Run as background service
.\CapabilityDenialSystem.exe --service

# Or via Windows Service Controller
Start-Service CDSDaemon
Stop-Service CDSDaemon
Get-Service CDSDaemon
```

### Check Status
```powershell
.\Setup-CDS.ps1
```

---

## Log Files

| Log Type | Location |
|----------|----------|
| Audit Log | `C:\ProgramData\CDS\logs\audit.log` |
| Setup Log | `C:\ProgramData\CDS\logs\setup.log` |

### Viewing Logs
```powershell
# Real-time log monitoring
Get-Content "C:\ProgramData\CDS\logs\audit.log" -Tail 50 -Wait

# Search for threats
Select-String -Path "C:\ProgramData\CDS\logs\audit.log" -Pattern "THREAT"
```

---

## Protection Engine Details

### 1. Anti-Screen-Capture Engine
- Monitors all processes for screen capture API usage
- Applies `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` to CDS windows
- Detects suspicious module names (screen, capture, screenshot, record)
- Terminates processes with known spyware naming patterns

### 2. Anti-Keylogging Engine
- Scans for unauthorized keyboard hooks (WH_KEYBOARD, WH_KEYBOARD_LL)
- Analyzes process threads for input capture behavior
- Detects known keylogger naming patterns
- Forcefully unhooks or terminates offending processes

### 3. Process Injection Monitor
- Uses `VirtualQueryEx` to detect RWX (PAGE_EXECUTE_READWRITE) memory regions
- Monitors for rapid handle/thread count growth
- Checks for suspicious process naming (inject, hollow, shellcode, payload)
- Takes snapshots to detect anomalous behavior changes

### 4. Network Protection Engine
- Creates default-deny outbound firewall rule
- Allows only explicitly whitelisted executables
- Permits DNS only to trusted resolvers (1.1.1.1, 8.8.8.8)
- Monitors for suspicious ports (4444, 5555, 31337, etc.)

### 5. Persistence Monitor
- Continuously monitors Registry Run/RunOnce keys
- Audits Scheduled Tasks for new entries
- Validates executable hashes against whitelist
- Automatically removes malicious persistence mechanisms

---

## Security Considerations

### Important Notes

1. **Hash Verification**: Always update the SHA-256 hashes in `whitelist.json` with actual system file hashes before deployment. Placeholder hashes will cause legitimate processes to be blocked.

2. **Administrator Required**: Full protection requires administrator privileges for:
   - Firewall rule creation
   - Process termination
   - Registry modification
   - Service registration

3. **Testing Recommended**: Test thoroughly in a controlled environment before production deployment. The aggressive termination policies may affect legitimate software.

4. **Performance Impact**: Default scan interval is 1000ms. Adjust `scan_interval_ms` based on performance requirements.

### Limitations

- Cannot protect against kernel-mode rootkits
- Requires .NET runtime (can be targeted by attackers)
- May have compatibility issues with some legitimate software
- Screen capture detection is heuristic-based, not absolute

---

## Troubleshooting

### CDS Won't Start
```powershell
# Check if .NET is installed
dotnet --version

# Check event logs
Get-EventLog -LogName Application -Source ".NET Runtime" -Newest 20

# Verify configuration file syntax
Get-Content whitelist.json | ConvertFrom-Json
```

### Legitimate Software Being Blocked
1. Add the software's executable hash to `whitelist.json`
2. Set appropriate permissions (`allow_screen_capture`, etc.)
3. Restart CDS service

### Firewall Issues
```powershell
# View CDS firewall rules
Get-NetFirewallRule -Name "CDS_*" | Format-Table Name, DisplayName, Enabled, Action

# Reset firewall rules
.\Setup-CDS.ps1 -Uninstall
.\Setup-CDS.ps1 -Install
```

---

## Uninstallation

```powershell
# Run as Administrator
.\Setup-CDS.ps1 -Uninstall

# This will:
# 1. Stop and remove the Windows Service
# 2. Remove all firewall rules
# 3. Delete installation directory
```

---

## License

This software is provided for defensive security purposes only. Use responsibly and only on systems you own or have explicit authorization to protect.

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2024 | Initial release with all five protection engines |

---

## Support

For issues, review the audit logs at `C:\ProgramData\CDS\logs\audit.log` and verify configuration in `whitelist.json`.
