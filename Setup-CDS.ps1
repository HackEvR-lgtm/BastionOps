# Capability Denial System (CDS) - Setup Script
# PowerShell Core / Windows PowerShell
# Requires Administrator privileges

param(
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$ConfigureFirewall,
    [switch]$UpdateWhitelist,
    [string]$ConfigPath = ".\whitelist.json"
)

# ================================================================================
# CONFIGURATION
# ================================================================================

$CDS_NAME = "CapabilityDenialSystem"
$CDS_SERVICE_NAME = "CDSDaemon"
$INSTALL_DIR = "C:\ProgramData\CDS"
$LOG_DIR = "$INSTALL_DIR\logs"
$CONFIG_FILE = "$INSTALL_DIR\whitelist.json"
$BINARY_PATH = "$INSTALL_DIR\CapabilityDenialSystem.exe"

# ================================================================================
# HELPER FUNCTIONS
# ================================================================================

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry
    
    if (-not (Test-Path $LOG_DIR)) {
        New-Item -ItemType Directory -Path $LOG_DIR -Force | Out-Null
    }
    
    Add-Content -Path "$LOG_DIR\setup.log" -Value $logEntry
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-FileHash256 {
    param([string]$FilePath)
    if (Test-Path $FilePath) {
        return (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash.ToLower()
    }
    return $null
}

function Get-SystemFileHash {
    param([string]$FilePath)
    if (Test-Path $FilePath) {
        try {
            return (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash.ToLower()
        } catch {
            Write-Log "Failed to get hash for $FilePath : $_" "WARNING"
            return $null
        }
    }
    return $null
}

# ================================================================================
# FIREWALL CONFIGURATION
# ================================================================================

function Configure-CDSFirewall {
    Write-Log "Configuring Windows Defender Firewall rules for CDS..."
    
    try {
        # Default outbound block rule
        $ruleName = "CDS_Default_Block_Outbound"
        $existingRule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
        
        if ($null -eq $existingRule) {
            New-NetFirewallRule `
                -Name $ruleName `
                -DisplayName "CDS Default Block Outbound" `
                -Direction Outbound `
                -Action Block `
                -Enabled True `
                -Profile Any `
                -Description "CDS default policy: Block all outbound traffic unless explicitly allowed"
            Write-Log "Created default outbound block rule"
        } else {
            Write-Log "Default outbound block rule already exists"
        }
        
        # Allow DNS to trusted resolvers
        $dnsResolvers = @("1.1.1.1", "8.8.8.8", "1.0.0.1", "9.9.9.9")
        foreach ($resolver in $dnsResolvers) {
            $dnsRuleName = "CDS_Allow_DNS_$($resolver.Replace('.', '_'))"
            $existingDnsRule = Get-NetFirewallRule -Name $dnsRuleName -ErrorAction SilentlyContinue
            
            if ($null -eq $existingDnsRule) {
                New-NetFirewallRule `
                    -Name $dnsRuleName `
                    -DisplayName "CDS Allow DNS $resolver" `
                    -Direction Outbound `
                    -Action Allow `
                    -Protocol UDP `
                    -RemotePort 53 `
                    -RemoteAddress $resolver `
                    -Enabled True `
                    -Profile Any
                Write-Log "Created DNS allow rule for $resolver"
            }
        }
        
        # Allow CDS executable itself
        if (Test-Path $BINARY_PATH) {
            $cdsRuleName = "CDS_Allow_Self"
            $existingCdsRule = Get-NetFirewallRule -Name $cdsRuleName -ErrorAction SilentlyContinue
            
            if ($null -eq $existingCdsRule) {
                New-NetFirewallRule `
                    -Name $cdsRuleName `
                    -DisplayName "CDS Allow Self" `
                    -Direction Outbound `
                    -Action Allow `
                    -Program $BINARY_PATH `
                    -Enabled True `
                    -Profile Any
                Write-Log "Created firewall rule to allow CDS executable"
            }
        }
        
        Write-Log "Firewall configuration completed successfully"
    } catch {
        Write-Log "Failed to configure firewall: $_" "ERROR"
        throw
    }
}

function Remove-CDSFirewallRules {
    Write-Log "Removing CDS firewall rules..."
    
    try {
        $rules = Get-NetFirewallRule -Name "CDS_*" -ErrorAction SilentlyContinue
        foreach ($rule in $rules) {
            Remove-NetFirewallRule -Name $rule.Name -ErrorAction SilentlyContinue
            Write-Log "Removed firewall rule: $($rule.Name)"
        }
        
        Write-Log "Firewall rules removed successfully"
    } catch {
        Write-Log "Failed to remove firewall rules: $_" "WARNING"
    }
}

# ================================================================================
# WHITELIST MANAGEMENT
# ================================================================================

function Update-WhitelistHashes {
    Write-Log "Updating whitelist with actual system file hashes..."
    
    try {
        $config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
        
        foreach ($process in $config.whitelisted_processes) {
            if (Test-Path $process.path) {
                $actualHash = Get-SystemFileHash -FilePath $process.path
                if ($actualHash) {
                    $process.sha256 = $actualHash
                    Write-Log "Updated hash for $($process.name): $actualHash"
                } else {
                    Write-Log "Could not get hash for $($process.path)" "WARNING"
                }
            } else {
                Write-Log "File not found: $($process.path)" "WARNING"
            }
        }
        
        # Save updated config
        $config | ConvertTo-Json -Depth 10 | Set-Content $ConfigPath -Encoding UTF8
        Write-Log "Whitelist updated successfully"
    } catch {
        Write-Log "Failed to update whitelist: $_" "ERROR"
        throw
    }
}

function Initialize-DefaultWhitelist {
    Write-Log "Creating default whitelist configuration..."
    
    try {
        $explorerHash = Get-SystemFileHash -FilePath "C:\Windows\explorer.exe"
        $svchostHash = Get-SystemFileHash -FilePath "C:\Windows\System32\svchost.exe"
        
        $whitelist = @{
            system_version = "1.0.0"
            security_level = "MAXIMUM_ISOLATION"
            logging = @{
                enabled = $true
                log_path = "$LOG_DIR\audit.log"
            }
            whitelisted_processes = @(
                @{
                    name = "explorer.exe"
                    path = "C:\Windows\explorer.exe"
                    sha256 = $explorerHash
                    allow_screen_capture = $true
                    allow_keyboard_hooks = $true
                    allow_network_outbound = $false
                },
                @{
                    name = "svchost.exe"
                    path = "C:\Windows\System32\svchost.exe"
                    sha256 = $svchostHash
                    allow_screen_capture = $false
                    allow_keyboard_hooks = $false
                    allow_network_outbound = $true
                }
            )
            network_rules = @{
                block_all_outbound_by_default = $true
                allowed_dns_resolvers = @("1.1.1.1", "8.8.8.8")
            }
            registry_monitor_paths = @(
                "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            )
            protection_settings = @{
                enable_screen_protection = $true
                enable_keylog_protection = $true
                enable_process_injection_protection = $true
                enable_network_protection = $true
                enable_persistence_monitor = $true
                scan_interval_ms = 1000
                auto_terminate_threats = $true
            }
        }
        
        if (-not (Test-Path $INSTALL_DIR)) {
            New-Item -ItemType Directory -Path $INSTALL_DIR -Force | Out-Null
        }
        
        $whitelist | ConvertTo-Json -Depth 10 | Set-Content $CONFIG_FILE -Encoding UTF8
        Write-Log "Default whitelist created at $CONFIG_FILE"
    } catch {
        Write-Log "Failed to create default whitelist: $_" "ERROR"
        throw
    }
}

# ================================================================================
# INSTALLATION
# ================================================================================

function Install-CDS {
    Write-Log "Starting CDS installation..."
    
    if (-not (Test-Administrator)) {
        Write-Log "ERROR: This script must be run as Administrator" "ERROR"
        exit 1
    }
    
    try {
        # Create installation directory
        if (-not (Test-Path $INSTALL_DIR)) {
            New-Item -ItemType Directory -Path $INSTALL_DIR -Force | Out-Null
            Write-Log "Created installation directory: $INSTALL_DIR"
        }
        
        # Create log directory
        if (-not (Test-Path $LOG_DIR)) {
            New-Item -ItemType Directory -Path $LOG_DIR -Force | Out-Null
            Write-Log "Created log directory: $LOG_DIR"
        }
        
        # Copy binary if it exists in current directory
        if (Test-Path ".\CapabilityDenialSystem.exe") {
            Copy-Item ".\CapabilityDenialSystem.exe" $BINARY_PATH -Force
            Write-Log "Copied CDS executable to $BINARY_PATH"
        } elseif (Test-Path ".\bin\Release\net8.0-windows\CapabilityDenialSystem.exe") {
            Copy-Item ".\bin\Release\net8.0-windows\CapabilityDenialSystem.exe" $BINARY_PATH -Force
            Write-Log "Copied CDS executable from build output"
        } elseif (Test-Path ".\bin\Release\net48\CapabilityDenialSystem.exe") {
            Copy-Item ".\bin\Release\net48\CapabilityDenialSystem.exe" $BINARY_PATH -Force
            Write-Log "Copied CDS executable from .NET Framework build output"
        } else {
            Write-Log "WARNING: CDS executable not found. Please build first." "WARNING"
        }
        
        # Copy/create configuration
        if (Test-Path $ConfigPath) {
            Copy-Item $ConfigPath $CONFIG_FILE -Force
            Write-Log "Copied configuration to $CONFIG_FILE"
        } elseif (-not (Test-Path $CONFIG_FILE)) {
            Initialize-DefaultWhitelist
        }
        
        # Configure firewall
        Configure-CDSFirewall
        
        # Register as Windows Service (using sc.exe)
        if (Test-Path $BINARY_PATH) {
            $existingService = Get-Service -Name $CDS_SERVICE_NAME -ErrorAction SilentlyContinue
            
            if ($null -eq $existingService) {
                $binaryPathEscaped = $BINARY_PATH -replace '\\', '\\'
                $createCommand = "create $CDS_SERVICE_NAME binPath= `"$BINARY_PATH --service`" start= auto DisplayName= `"$CDS_NAME`""
                
                Start-Process -FilePath "sc.exe" -ArgumentList "create", $CDS_SERVICE_NAME, "binPath=", "`"$BINARY_PATH --service`"", "start=", "auto", "DisplayName=", "`"$CDS_NAME`"" -NoNewWindow -Wait
                
                # Alternative approach using direct sc command
                & sc.exe create $CDS_SERVICE_NAME binPath= "`"$BINARY_PATH --service`"" start= auto DisplayName= "`"$CDS_NAME`""
                
                Write-Log "Registered CDS as Windows Service: $CDS_SERVICE_NAME"
            } else {
                Write-Log "CDS service already registered"
            }
        }
        
        Write-Log "============================================"
        Write-Log "CDS Installation Completed Successfully!"
        Write-Log "============================================"
        Write-Log "Installation Directory: $INSTALL_DIR"
        Write-Log "Configuration File: $CONFIG_FILE"
        Write-Log "Log Directory: $LOG_DIR"
        Write-Log ""
        Write-Log "To start CDS manually:"
        Write-Log "  & '$BINARY_PATH'"
        Write-Log ""
        Write-Log "To start as service:"
        Write-Log "  Start-Service $CDS_SERVICE_NAME"
        Write-Log ""
        Write-Log "To view logs:"
        Write-Log "  Get-Content '$LOG_DIR\audit.log' -Tail 50 -Wait"
        Write-Log "============================================"
        
    } catch {
        Write-Log "Installation failed: $_" "ERROR"
        throw
    }
}

# ================================================================================
# UNINSTALLATION
# ================================================================================

function Uninstall-CDS {
    Write-Log "Starting CDS uninstallation..."
    
    if (-not (Test-Administrator)) {
        Write-Log "ERROR: This script must be run as Administrator" "ERROR"
        exit 1
    }
    
    try {
        # Stop and remove service
        $service = Get-Service -Name $CDS_SERVICE_NAME -ErrorAction SilentlyContinue
        if ($service) {
            Stop-Service -Name $CDS_SERVICE_NAME -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            & sc.exe delete $CDS_SERVICE_NAME
            Write-Log "Removed CDS Windows Service"
        }
        
        # Remove firewall rules
        Remove-CDSFirewallRules
        
        # Remove installation directory
        if (Test-Path $INSTALL_DIR) {
            Remove-Item -Path $INSTALL_DIR -Recurse -Force
            Write-Log "Removed installation directory: $INSTALL_DIR"
        }
        
        Write-Log "============================================"
        Write-Log "CDS Uninstallation Completed!"
        Write-Log "============================================"
        
    } catch {
        Write-Log "Uninstallation failed: $_" "ERROR"
        throw
    }
}

# ================================================================================
# STATUS CHECK
# ================================================================================

function Get-CDSStatus {
    Write-Host "============================================"
    Write-Host "   Capability Denial System Status"
    Write-Host "============================================"
    Write-Host ""
    
    # Service status
    $service = Get-Service -Name $CDS_SERVICE_NAME -ErrorAction SilentlyContinue
    if ($service) {
        Write-Host "Service Name:    $($service.Name)"
        Write-Host "Service Status:  $($service.Status)"
        Write-Host "Startup Type:    $($service.StartType)"
    } else {
        Write-Host "Service:         Not installed"
    }
    Write-Host ""
    
    # Installation status
    Write-Host "Installation Dir: $INSTALL_DIR"
    if (Test-Path $INSTALL_DIR) {
        Write-Host "Installed:       Yes"
        Write-Host "Binary Exists:   $(Test-Path $BINARY_PATH)"
        Write-Host "Config Exists:   $(Test-Path $CONFIG_FILE)"
    } else {
        Write-Host "Installed:       No"
    }
    Write-Host ""
    
    # Firewall rules
    $firewallRules = Get-NetFirewallRule -Name "CDS_*" -ErrorAction SilentlyContinue
    Write-Host "Firewall Rules:  $($firewallRules.Count) rules configured"
    Write-Host ""
    
    # Recent logs
    if (Test-Path "$LOG_DIR\audit.log") {
        Write-Host "Recent Log Entries:"
        Write-Host "----------------------------------------"
        Get-Content "$LOG_DIR\audit.log" -Tail 10 | ForEach-Object { Write-Host $_ }
        Write-Host "----------------------------------------"
    }
    
    Write-Host ""
    Write-Host "============================================"
}

# ================================================================================
# MAIN EXECUTION
# ================================================================================

Write-Host ""
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "   CAPABILITY DENIAL SYSTEM (CDS) Setup" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host ""

if ($Install) {
    Install-CDS
} elseif ($Uninstall) {
    Uninstall-CDS
} elseif ($ConfigureFirewall) {
    Configure-CDSFirewall
} elseif ($UpdateWhitelist) {
    Update-WhitelistHashes
} else {
    # Default: Show status and help
    Get-CDSSStatus
    
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  .\Setup-CDS.ps1 -Install          Install CDS"
    Write-Host "  .\Setup-CDS.ps1 -Uninstall        Uninstall CDS"
    Write-Host "  .\Setup-CDS.ps1 -ConfigureFirewall  Configure firewall rules"
    Write-Host "  .\Setup-CDS.ps1 -UpdateWhitelist  Update hashes in whitelist"
    Write-Host "  .\Setup-CDS.ps1                   Show status"
    Write-Host ""
    Write-Host "Note: Run as Administrator for install/uninstall operations" -ForegroundColor Yellow
}
