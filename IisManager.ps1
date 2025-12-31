# IisManager.ps1
# Manages installation and uninstallation of Internet Information Services (IIS) on Windows
# Run as Administrator: .\IisManager.ps1 [install] [uninstall]

param(
    [string]$Action = $null,
    [switch]$IncludeManagementTools = $true,
    [switch]$IncludeAspNet = $false,
    [switch]$IncludeFtp = $false
)

# Fallback: support positional arguments for backward compatibility
if (-not $Action -and $args.Count -ge 1) {
    $Action = $args[0]
}

# Global Variables
$LOG_FILE = "$env:TEMP\IisManager.log"

# Log function
function Write-Log {
    param (
        [string]$Message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] $Message"
    Write-Output $logMessage | Out-File -FilePath $LOG_FILE -Append
    Write-Output $logMessage
}

# Check for Administrator privileges
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log "ERROR: This script must be run as Administrator."
        exit 1
    }
}

# Check if IIS is already installed
function Test-IisInstalled {
    # Try Get-WindowsFeature first (Windows Server)
    try {
        $iisFeature = Get-WindowsFeature -Name IIS-WebServerRole -ErrorAction SilentlyContinue
        if ($iisFeature -and $iisFeature.InstallState -eq "Installed") {
            return $true
        }
    } catch {
        # Fall back to Get-WindowsOptionalFeature (Windows Client/Server)
        try {
            $iisFeature = Get-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole -ErrorAction SilentlyContinue
            if ($iisFeature -and $iisFeature.State -eq "Enabled") {
                return $true
            }
        } catch {
            # Ignore errors
        }
    }
    return $false
}

# Get IIS version
function Get-IisVersion {
    try {
        $iisVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\InetStp" -ErrorAction SilentlyContinue).MajorVersion
        if ($iisVersion) {
            return $iisVersion
        }
    } catch {
        # Ignore errors
    }
    return $null
}

# Install IIS
function Install-Iis {
    param (
        [bool]$IncludeManagementTools,
        [bool]$IncludeAspNet,
        [bool]$IncludeFtp
    )

    Write-Log "Starting IIS installation process..."

    # Check if IIS is already installed
    if (Test-IisInstalled) {
        $version = Get-IisVersion
        if ($version) {
            Write-Log "IIS version $version is already installed."
        } else {
            Write-Log "IIS is already installed (version could not be determined)."
        }
        Write-Log "To reinstall, please uninstall IIS first using: .\IisManager.ps1 -Action uninstall"
        return
    }

    # Check Windows version
    $osVersion = [System.Environment]::OSVersion.Version
    Write-Log "Detected Windows version: $($osVersion.Major).$($osVersion.Minor)"

    # Build list of features to install
    $featuresToInstall = @("IIS-WebServerRole")

    # Core IIS features
    $featuresToInstall += @(
        "IIS-WebServer",
        "IIS-CommonHttpFeatures",
        "IIS-HttpErrors",
        "IIS-HttpLogging",
        "IIS-RequestFiltering",
        "IIS-StaticContent",
        "IIS-DefaultDocument",
        "IIS-DirectoryBrowsing",
        "IIS-HttpCompressionStatic",
        "IIS-HttpCompressionDynamic",
        "IIS-ApplicationInit",
        "IIS-ISAPIExt",
        "IIS-ISAPIFilter",
        "IIS-NetFxExtensibility45",
        "IIS-HealthAndDiagnostics",
        "IIS-HttpTracing",
        "IIS-Performance",
        "IIS-HttpCompression",
        "IIS-Security",
        "IIS-IpSecurity",
        "IIS-URLAuthorization",
        "IIS-WindowsAuthentication",
        "IIS-BasicAuthentication",
        "IIS-DigestAuthentication"
    )

    # Management Tools
    if ($IncludeManagementTools) {
        Write-Log "Including IIS Management Tools..."
        $featuresToInstall += @(
            "IIS-ManagementConsole",
            "IIS-ManagementService",
            "IIS-IIS6ManagementCompatibility",
            "IIS-Metabase",
            "IIS-WMICompatibility",
            "IIS-LegacySnapIn",
            "IIS-ManagementScriptingTools"
        )
    }

    # ASP.NET support
    if ($IncludeAspNet) {
        Write-Log "Including ASP.NET support..."
        $featuresToInstall += @(
            "IIS-ASPNET45",
            "IIS-ApplicationDevelopment",
            "IIS-ASPNET"
        )
    }

    # FTP Server
    if ($IncludeFtp) {
        Write-Log "Including FTP Server..."
        $featuresToInstall += @(
            "IIS-FTPServer",
            "IIS-FTPSvc",
            "IIS-FTPExtensibility"
        )
    }

    # Remove duplicates
    $featuresToInstall = $featuresToInstall | Select-Object -Unique

    Write-Log "Installing IIS with the following features:"
    foreach ($feature in $featuresToInstall) {
        Write-Log "  - $feature"
    }

    # Install features
    try {
        $installResult = $null
        $restartNeeded = $false
        
        # Try Install-WindowsFeature first (Windows Server)
        try {
            $installResult = Install-WindowsFeature -Name $featuresToInstall -IncludeManagementTools:$IncludeManagementTools -ErrorAction Stop
            if ($installResult.Success) {
                $restartNeeded = $installResult.RestartNeeded
            }
        } catch {
            # Fall back to Enable-WindowsOptionalFeature (Windows Client/Server)
            Write-Log "Install-WindowsFeature not available, using Enable-WindowsOptionalFeature..."
            foreach ($feature in $featuresToInstall) {
                try {
                    $result = Enable-WindowsOptionalFeature -Online -FeatureName $feature -All -NoRestart -ErrorAction Stop
                    if ($result.RestartNeeded) {
                        $restartNeeded = $true
                    }
                } catch {
                    Write-Log "WARNING: Failed to install feature $feature : $_"
                }
            }
            # Create a success result object for consistency
            $installResult = [PSCustomObject]@{ Success = $true; RestartNeeded = $restartNeeded }
        }
        
        if ($installResult -and $installResult.Success) {
            Write-Log "IIS installation completed successfully."
            Write-Log "Restart required: $restartNeeded"
            
            if ($restartNeeded) {
                Write-Log "WARNING: A system restart is required to complete the installation."
            }
        } else {
            Write-Log "ERROR: IIS installation failed."
            if ($installResult.ExitCode) {
                Write-Log "Exit code: $($installResult.ExitCode)"
            }
            if ($installResult.FeatureResult) {
                Write-Log "Failed features: $($installResult.FeatureResult -join ', ')"
            }
            exit 1
        }
    } catch {
        Write-Log "ERROR: Failed to install IIS. Exception: $($_.Exception.Message)"
        Write-Log "Stack trace: $($_.ScriptStackTrace)"
        exit 1
    }

    # Verify installation
    Write-Log "Verifying IIS installation..."
    Start-Sleep -Seconds 3
    
    if (Test-IisInstalled) {
        $version = Get-IisVersion
        if ($version) {
            Write-Log "SUCCESS: IIS version $version is installed and ready."
        } else {
            Write-Log "SUCCESS: IIS is installed (version could not be determined)."
        }

        # Check if IIS service is running
        try {
            $iisService = Get-Service -Name "W3SVC" -ErrorAction SilentlyContinue
            if ($iisService) {
                if ($iisService.Status -eq "Running") {
                    Write-Log "IIS service (W3SVC) is running."
                } else {
                    Write-Log "IIS service (W3SVC) is installed but not running. Starting service..."
                    Start-Service -Name "W3SVC" -ErrorAction SilentlyContinue
                    Start-Sleep -Seconds 2
                    $iisService = Get-Service -Name "W3SVC"
                    if ($iisService.Status -eq "Running") {
                        Write-Log "IIS service started successfully."
                    } else {
                        Write-Log "WARNING: IIS service could not be started automatically."
                    }
                }
            }
        } catch {
            Write-Log "WARNING: Could not check IIS service status. Exception: $($_.Exception.Message)"
        }

        # Verify default website
        try {
            Import-Module WebAdministration -ErrorAction SilentlyContinue
            $defaultSite = Get-Website -Name "Default Web Site" -ErrorAction SilentlyContinue
            if ($defaultSite) {
                Write-Log "Default Web Site found. State: $($defaultSite.State)"
                Write-Log "Default Web Site is accessible at: http://localhost"
            }
        } catch {
            Write-Log "WARNING: Could not verify default website. WebAdministration module may not be available."
        }

        Write-Log "IIS installation completed successfully."
        Write-Log "Default website location: C:\inetpub\wwwroot"
        
        if ($installResult.RestartNeeded) {
            Write-Log ""
            Write-Log "IMPORTANT: A system restart is required to complete the installation."
            Write-Log "Please restart the server when convenient."
        }
    } else {
        Write-Log "ERROR: IIS installation verification failed. IIS does not appear to be installed."
        exit 1
    }
}

# Uninstall IIS
function Uninstall-Iis {
    Write-Log "Starting IIS uninstallation process..."

    if (-not (Test-IisInstalled)) {
        Write-Log "IIS is not installed. Nothing to uninstall."
        return
    }

    Write-Log "Removing IIS and all related features..."
    
    try {
        # Get all IIS-related features
        $iisFeatures = $null
        try {
            # Try Get-WindowsFeature first (Windows Server)
            $iisFeatures = Get-WindowsFeature | Where-Object { $_.Name -like "IIS-*" -and $_.InstallState -eq "Installed" }
        } catch {
            # Fall back to Get-WindowsOptionalFeature (Windows Client/Server)
            try {
                $optionalFeatures = Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -like "IIS-*" -and $_.State -eq "Enabled" }
                if ($optionalFeatures) {
                    # Convert to similar format for consistency
                    $iisFeatures = $optionalFeatures | ForEach-Object { 
                        [PSCustomObject]@{ Name = $_.FeatureName; InstallState = "Installed" }
                    }
                }
            } catch {
                Write-Log "WARNING: Could not enumerate IIS features. Exception: $($_.Exception.Message)"
            }
        }
        
        if ($iisFeatures) {
            Write-Log "Found the following IIS features to remove:"
            foreach ($feature in $iisFeatures) {
                Write-Log "  - $($feature.Name)"
            }

            # Use Uninstall-WindowsFeature for Server, or Disable-WindowsOptionalFeature for Client
            $uninstallResult = $null
            try {
                $uninstallResult = Uninstall-WindowsFeature -Name ($iisFeatures.Name) -Remove
            } catch {
                # Fall back to Disable-WindowsOptionalFeature
                try {
                    foreach ($feature in $iisFeatures) {
                        Disable-WindowsOptionalFeature -Online -FeatureName $feature.Name -Remove -NoRestart
                    }
                    $uninstallResult = [PSCustomObject]@{ Success = $true; RestartNeeded = $true }
                } catch {
                    Write-Log "ERROR: Failed to uninstall IIS features. Exception: $($_.Exception.Message)"
                    exit 1
                }
            }
            
            if ($uninstallResult -and $uninstallResult.Success) {
                Write-Log "IIS uninstallation completed successfully."
                Write-Log "Restart required: $($uninstallResult.RestartNeeded)"
                
                if ($uninstallResult.RestartNeeded) {
                    Write-Log "WARNING: A system restart is required to complete the uninstallation."
                }
            } else {
                Write-Log "ERROR: IIS uninstallation failed."
                exit 1
            }
        } else {
            Write-Log "No IIS features found to remove."
        }
    } catch {
        Write-Log "ERROR: Failed to uninstall IIS. Exception: $($_.Exception.Message)"
        Write-Log "Stack trace: $($_.ScriptStackTrace)"
        exit 1
    }

    # Verify uninstallation
    Write-Log "Verifying IIS uninstallation..."
    Start-Sleep -Seconds 2
    
    if (-not (Test-IisInstalled)) {
        Write-Log "SUCCESS: IIS has been uninstalled successfully."
    } else {
        Write-Log "WARNING: IIS uninstallation verification failed. Some features may still be installed."
    }
}

# Main script execution
Test-Admin

switch ($Action) {
    "install" {
        Install-Iis -IncludeManagementTools $IncludeManagementTools.IsPresent -IncludeAspNet $IncludeAspNet.IsPresent -IncludeFtp $IncludeFtp.IsPresent
    }
    "uninstall" {
        Uninstall-Iis
    }
    default {
        Write-Output ""
        Write-Output "IIS Manager - Installation and Uninstallation Script"
        Write-Output "===================================================="
        Write-Output ""
        Write-Output "Usage: .\IisManager.ps1 -Action [install|uninstall] [options]"
        Write-Output ""
        Write-Output "Actions:"
        Write-Output "  install     - Install IIS with default features"
        Write-Output "  uninstall   - Uninstall IIS and all related features"
        Write-Output ""
        Write-Output "Options:"
        Write-Output "  -IncludeManagementTools  Include IIS Management Tools (default: true)"
        Write-Output "  -IncludeAspNet          Include ASP.NET support (default: false)"
        Write-Output "  -IncludeFtp              Include FTP Server (default: false)"
        Write-Output ""
        Write-Output "Examples:"
        Write-Output "  .\IisManager.ps1 -Action install"
        Write-Output "  .\IisManager.ps1 -Action install -IncludeAspNet -IncludeFtp"
        Write-Output "  .\IisManager.ps1 -Action uninstall"
        Write-Output ""
        exit 1
    }
}

exit 0

