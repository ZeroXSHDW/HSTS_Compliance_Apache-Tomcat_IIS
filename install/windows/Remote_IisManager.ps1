# Remote_IisManager.ps1
# Remote installation and uninstallation of Internet Information Services (IIS) on Windows
# Supports remote execution via PowerShell Remoting (WinRM)
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string[]]$ServerName = @(),
    
    [Parameter(Mandatory=$false)]
    [string]$ServerListFile = $null,
    
    [Parameter(Mandatory=$true)]
    [ValidateSet("install", "uninstall")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeManagementTools = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeAspNet = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeFtp = $false,
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential = $null
)

$ErrorActionPreference = "Stop"

# Function: Load server names from file
function Get-ServersFromFile {
    param(
        [string]$ServerFile
    )
    
    $servers = @()
    if (-not $ServerFile -or -not (Test-Path $ServerFile)) {
        return $servers
    }
    
    try {
        $fileContent = Get-Content -Path $ServerFile -ErrorAction Stop
        foreach ($line in $fileContent) {
            $trimmedLine = $line.Trim()
            if ($trimmedLine -and -not $trimmedLine.StartsWith("#")) {
                $servers += $trimmedLine
            }
        }
        Write-Host "Loaded $($servers.Count) server(s) from file: $ServerFile"
    } catch {
        Write-Host "ERROR: Failed to read server list file: $ServerFile - $_" -ForegroundColor Red
    }
    
    return $servers
}

# Collect servers from parameter and file
$allServers = @()
if ($ServerName.Count -gt 0) {
    $allServers += $ServerName
}
if ($ServerListFile) {
    $fileServers = Get-ServersFromFile -ServerFile $ServerListFile
    $allServers += $fileServers
}

if ($allServers.Count -eq 0) {
    Write-Host "ERROR: No servers specified. Use -ServerName or -ServerListFile parameter." -ForegroundColor Red
    Write-Host "  Example: -ServerName @('server1', 'server2')" -ForegroundColor Yellow
    Write-Host "  Example: -ServerListFile 'C:\servers.txt' (one server per line)" -ForegroundColor Yellow
    exit 1
}

$uniqueServers = $allServers | Select-Object -Unique
Write-Host "Processing $($uniqueServers.Count) unique server(s) for IIS $Action operation"

foreach ($server in $uniqueServers) {
    Write-Host "========================================="
    Write-Host "Processing server: $server"
    Write-Host "========================================="
    
    try {
        # Try multiple authentication methods
        $authMethods = @()
        if ($Credential) {
            $authMethods = @("Negotiate", "Basic", "Kerberos", "CredSSP")
        } else {
            $authMethods = @("Default", "Negotiate", "Kerberos")
        }
        
        $connected = $false
        $lastError = $null
        
        foreach ($authMethod in $authMethods) {
            try {
                Write-Host "Attempting connection to $server using $authMethod authentication..."
                
                $invokeParams = @{
                    ComputerName = $server
                    ScriptBlock = {
                        param($Action, $IncludeManagementTools, $IncludeAspNet, $IncludeFtp)
                        
                        # Global Variables
                        $LOG_FILE = "$env:TEMP\IisManager.log"
                        
                        # Log function
                        function Write-Log {
                            param (
                                [string]$Message
                            )
                            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                            $logMessage = "[$timestamp] [$env:COMPUTERNAME] $Message"
                            Write-Output $logMessage | Out-File -FilePath $LOG_FILE -Append
                            Write-Output $logMessage
                        }
                        
                        # Check for Administrator privileges
                        function Test-Admin {
                            $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
                            if (-not $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
                                Write-Log "ERROR: This script must be run as Administrator."
                                throw "Administrator privileges required"
                            }
                        }
                        
                        # Check if IIS is already installed
                        function Test-IisInstalled {
                            try {
                                $iisFeature = Get-WindowsFeature -Name IIS-WebServerRole -ErrorAction SilentlyContinue
                                if ($iisFeature -and $iisFeature.InstallState -eq "Installed") {
                                    return $true
                                }
                            } catch {
                                try {
                                    $iisFeature = Get-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole -ErrorAction SilentlyContinue
                                    if ($iisFeature -and $iisFeature.State -eq "Enabled") {
                                        return $true
                                    }
                                } catch { }
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
                            } catch { }
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
                            
                            $osVersion = [System.Environment]::OSVersion.Version
                            Write-Log "Detected Windows version: $($osVersion.Major).$($osVersion.Minor)"
                            
                            $featuresToInstall = @("IIS-WebServerRole")
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
                            
                            if ($IncludeAspNet) {
                                Write-Log "Including ASP.NET support..."
                                $featuresToInstall += @(
                                    "IIS-ASPNET45",
                                    "IIS-ApplicationDevelopment",
                                    "IIS-ASPNET"
                                )
                            }
                            
                            if ($IncludeFtp) {
                                Write-Log "Including FTP Server..."
                                $featuresToInstall += @(
                                    "IIS-FTPServer",
                                    "IIS-FTPSvc",
                                    "IIS-FTPExtensibility"
                                )
                            }
                            
                            $featuresToInstall = $featuresToInstall | Select-Object -Unique
                            
                            Write-Log "Installing IIS with the following features:"
                            foreach ($feature in $featuresToInstall) {
                                Write-Log "  - $feature"
                            }
                            
                            try {
                                $installResult = $null
                                $restartNeeded = $false
                                
                                try {
                                    $installResult = Install-WindowsFeature -Name $featuresToInstall -IncludeManagementTools:$IncludeManagementTools -ErrorAction Stop
                                    if ($installResult.Success) {
                                        $restartNeeded = $installResult.RestartNeeded
                                    }
                                } catch {
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
                                    throw "Installation failed"
                                }
                            } catch {
                                Write-Log "ERROR: Failed to install IIS. Exception: $($_.Exception.Message)"
                                throw
                            }
                            
                            Write-Log "Verifying IIS installation..."
                            Start-Sleep -Seconds 3
                            
                            if (Test-IisInstalled) {
                                $version = Get-IisVersion
                                if ($version) {
                                    Write-Log "SUCCESS: IIS version $version is installed and ready."
                                } else {
                                    Write-Log "SUCCESS: IIS is installed (version could not be determined)."
                                }
                                
                                try {
                                    $iisService = Get-Service -Name "W3SVC" -ErrorAction SilentlyContinue
                                    if ($iisService) {
                                        if ($iisService.Status -eq "Running") {
                                            Write-Log "IIS service (W3SVC) is running."
                                        } else {
                                            Write-Log "Starting IIS service..."
                                            Start-Service -Name "W3SVC" -ErrorAction SilentlyContinue
                                            Start-Sleep -Seconds 2
                                            $iisService = Get-Service -Name "W3SVC"
                                            if ($iisService.Status -eq "Running") {
                                                Write-Log "IIS service started successfully."
                                            }
                                        }
                                    }
                                } catch {
                                    Write-Log "WARNING: Could not check IIS service status: $($_.Exception.Message)"
                                }
                                
                                Write-Log "IIS installation completed successfully."
                                Write-Log "Default website location: C:\inetpub\wwwroot"
                            } else {
                                Write-Log "ERROR: IIS installation verification failed."
                                throw "Verification failed"
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
                                $iisFeatures = $null
                                try {
                                    $iisFeatures = Get-WindowsFeature | Where-Object { $_.Name -like "IIS-*" -and $_.InstallState -eq "Installed" }
                                } catch {
                                    try {
                                        $optionalFeatures = Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -like "IIS-*" -and $_.State -eq "Enabled" }
                                        if ($optionalFeatures) {
                                            $iisFeatures = $optionalFeatures | ForEach-Object { 
                                                [PSCustomObject]@{ Name = $_.FeatureName; InstallState = "Installed" }
                                            }
                                        }
                                    } catch {
                                        Write-Log "WARNING: Could not enumerate IIS features: $($_.Exception.Message)"
                                    }
                                }
                                
                                if ($iisFeatures) {
                                    Write-Log "Found the following IIS features to remove:"
                                    foreach ($feature in $iisFeatures) {
                                        Write-Log "  - $($feature.Name)"
                                    }
                                    
                                    $uninstallResult = $null
                                    try {
                                        $uninstallResult = Uninstall-WindowsFeature -Name ($iisFeatures.Name) -Remove
                                    } catch {
                                        try {
                                            foreach ($feature in $iisFeatures) {
                                                Disable-WindowsOptionalFeature -Online -FeatureName $feature.Name -Remove -NoRestart
                                            }
                                            $uninstallResult = [PSCustomObject]@{ Success = $true; RestartNeeded = $true }
                                        } catch {
                                            Write-Log "ERROR: Failed to uninstall IIS features: $($_.Exception.Message)"
                                            throw
                                        }
                                    }
                                    
                                    if ($uninstallResult -and $uninstallResult.Success) {
                                        Write-Log "IIS uninstallation completed successfully."
                                        Write-Log "Restart required: $($uninstallResult.RestartNeeded)"
                                    } else {
                                        Write-Log "ERROR: IIS uninstallation failed."
                                        throw "Uninstallation failed"
                                    }
                                } else {
                                    Write-Log "No IIS features found to remove."
                                }
                            } catch {
                                Write-Log "ERROR: Failed to uninstall IIS: $($_.Exception.Message)"
                                throw
                            }
                            
                            Write-Log "Verifying IIS uninstallation..."
                            Start-Sleep -Seconds 2
                            
                            if (-not (Test-IisInstalled)) {
                                Write-Log "SUCCESS: IIS has been uninstalled successfully."
                            } else {
                                Write-Log "WARNING: IIS uninstallation verification failed. Some features may still be installed."
                            }
                        }
                        
                        # Main execution
                        Test-Admin
                        
                        if ($Action -eq "install") {
                            Install-Iis -IncludeManagementTools $IncludeManagementTools -IncludeAspNet $IncludeAspNet -IncludeFtp $IncludeFtp
                        } elseif ($Action -eq "uninstall") {
                            Uninstall-Iis
                        }
                        
                        return @{ Success = $true; Message = "Operation completed" }
                    }
                    ArgumentList = @($Action, $IncludeManagementTools.IsPresent, $IncludeAspNet.IsPresent, $IncludeFtp.IsPresent)
                    ErrorAction = "Stop"
                }
                
                if ($Credential) {
                    $invokeParams.Credential = $Credential
                }
                
                if ($authMethod -ne "Default") {
                    $invokeParams.Authentication = $authMethod
                }
                
                $result = Invoke-Command @invokeParams
                $connected = $true
                Write-Host "SUCCESS: Connected to $server using $authMethod authentication" -ForegroundColor Green
                Write-Host "Result: $($result.Message)" -ForegroundColor Green
                break
                
            } catch {
                $lastError = $_
                Write-Host "Failed to connect using $authMethod: $($_.Exception.Message)" -ForegroundColor Yellow
                continue
            }
        }
        
        if (-not $connected) {
            Write-Host "ERROR: Failed to connect to $server using all authentication methods" -ForegroundColor Red
            Write-Host "Last error: $($lastError.Exception.Message)" -ForegroundColor Red
            Write-Host "Ensure WinRM is enabled and configured on the target server." -ForegroundColor Yellow
            continue
        }
        
    } catch {
        Write-Host "ERROR: Failed to process server $server : $_" -ForegroundColor Red
        continue
    }
}

Write-Host ""
Write-Host "Remote IIS management operation completed."
Write-Host "Check individual server logs at: \\$server\C$\Users\$env:USERNAME\AppData\Local\Temp\IisManager.log"

