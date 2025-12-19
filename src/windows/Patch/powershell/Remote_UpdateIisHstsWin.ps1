# Remote_UpdateIisHstsWin.ps1
# Remote Audit and Configure HSTS (HTTP Strict Transport Security) in IIS
# For Windows Server environments only
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string[]]$ServerName,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("audit", "configure")]
    [string]$Mode = "configure",
    
    [Parameter(Mandatory=$false)]
    [string]$ConfigPath = $null,
    
    [Parameter(Mandatory=$false)]
    [switch]$DryRun = $false,
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential = $null
)

$ErrorActionPreference = "Stop"
$uniqueServers = $ServerName | Select-Object -Unique

foreach ($server in $uniqueServers) {
    Write-Host "========================================="
    Write-Host "Processing server: $server"
    Write-Host "========================================="
    
    try {
        $scriptBlock = {
            param($Mode, $ConfigPath, $DryRun)
            
            $ErrorActionPreference = "Stop"
            $RecommendedHsts = "max-age=31536000; includeSubDomains"
            $LogFile = "$env:LOCALAPPDATA\Temp\IisHsts.log"
            $Hostname = $env:COMPUTERNAME
            $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            
            function Log-Message {
                param([string]$Message)
                $logEntry = "[$Timestamp] $Message"
                Write-Host $logEntry
                try {
                    Add-Content -Path $LogFile -Value $logEntry -ErrorAction SilentlyContinue
                } catch { }
            }
            
            function Log-Error {
                param([string]$Message)
                Log-Message "ERROR: $Message"
            }
            
            try {
                $null = New-Item -Path $LogFile -ItemType File -Force -ErrorAction Stop
            } catch {
                Log-Error "Cannot create log file: $LogFile"
            }
            
            Log-Message "========================================="
            Log-Message "IIS HSTS Configuration Tool (Remote)"
            Log-Message "Hostname: $Hostname"
            Log-Message "Execution Time: $Timestamp"
            Log-Message "Mode: $Mode"
            Log-Message "========================================="
            
            # Include all HSTS functions from iis_hsts.ps1 (abbreviated for remote execution)
            function Test-ValidXml {
                param([string]$XmlFilePath)
                try {
                    $xmlContent = Get-Content -Path $XmlFilePath -Raw -ErrorAction Stop
                    [xml]$null = $xmlContent
                    return $true
                } catch {
                    return $false
                }
            }
            
            function Test-ValidFilePath {
                param([string]$FilePath)
                if ($FilePath -match '\.\.') {
                    Log-Error "Invalid path: contains '..'"
                    return $false
                }
                if ($FilePath -match '\0') {
                    Log-Error "Invalid path: contains null byte"
                    return $false
                }
                return $true
            }
            
            function Load-Config {
                param([string]$ConfigPath)
                if (-not (Test-ValidFilePath -FilePath $ConfigPath)) {
                    throw "Invalid path"
                }
                if (-not (Test-Path -Path $ConfigPath)) {
                    Log-Error "Configuration file not found: $ConfigPath"
                    throw "File not found"
                }
                $fileInfo = Get-Item -Path $ConfigPath -ErrorAction Stop
                if ($fileInfo.Length -eq 0) {
                    Log-Error "Configuration file is empty: $ConfigPath"
                    throw "Empty file"
                }
                try {
                    $configContent = Get-Content -Path $ConfigPath -Raw -ErrorAction Stop
                    if (-not (Test-ValidXml -XmlFilePath $ConfigPath)) {
                        Log-Error "Configuration file contains invalid XML: $ConfigPath"
                        throw "Invalid XML"
                    }
                    [xml]$xmlConfig = $configContent
                    return $xmlConfig
                } catch {
                    Log-Error "Failed to load configuration file: $_"
                    throw "Load error"
                }
            }
            
            function Test-CompliantHeader {
                param([string]$HeaderValue)
                if ([string]::IsNullOrWhiteSpace($HeaderValue)) {
                    return $false
                }
                if ($HeaderValue -notmatch "max-age=31536000") {
                    return $false
                }
                if ($HeaderValue -notmatch "includeSubDomains") {
                    return $false
                }
                return $true
            }
            
            function Find-AllHstsHeaders {
                param([xml]$ParsedConfig)
                $headers = @()
                try {
                    $httpProtocol = $ParsedConfig.configuration.'system.webServer'.httpProtocol
                    if ($null -eq $httpProtocol) {
                        return $headers
                    }
                    $customHeaders = $httpProtocol.customHeaders
                    if ($null -eq $customHeaders) {
                        return $headers
                    }
                    if ($null -ne $customHeaders.add) {
                        $allAdds = @()
                        try {
                            if ($customHeaders.add -is [System.Array]) {
                                $allAdds = $customHeaders.add
                            } else {
                                $allAdds = @($customHeaders.add)
                            }
                            $hstsHeaders = $allAdds | Where-Object { 
                                $null -ne $_ -and $null -ne $_.name -and $_.name -eq "Strict-Transport-Security" 
                            }
                            if ($null -ne $hstsHeaders) {
                                if ($hstsHeaders -is [System.Array]) {
                                    foreach ($header in $hstsHeaders) {
                                        if ($null -ne $header) {
                                            $headers += $header
                                        }
                                    }
                                } else {
                                    $headers += $hstsHeaders
                                }
                            }
                        } catch {
                            Log-Error "Error processing custom headers: $_"
                        }
                    }
                } catch {
                    Log-Error "Error finding HSTS headers: $_"
                }
                return $headers
            }
            
            function Audit-HstsHeaders {
                param([xml]$ParsedConfig)
                $isCorrect = $false
                $details = ""
                $headerCount = 0
                $compliantCount = 0
                $nonCompliantCount = 0
                $compliantHeaders = @()
                $nonCompliantHeaders = @()
                try {
                    $allHeaders = Find-AllHstsHeaders -ParsedConfig $ParsedConfig
                    $headerCount = $allHeaders.Count
                    if ($headerCount -eq 0) {
                        $details = "No HSTS header definitions found in configuration"
                        return @{
                            IsCorrect = $false
                            Details = $details
                            HeaderCount = 0
                            CompliantCount = 0
                            NonCompliantCount = 0
                            CompliantHeaders = @()
                            NonCompliantHeaders = @()
                        }
                    }
                    Log-Message "Found $headerCount HSTS header definition(s)"
                    foreach ($header in $allHeaders) {
                        $headerValue = $header.value
                        if ([string]::IsNullOrWhiteSpace($headerValue)) {
                            $nonCompliantCount++
                            $nonCompliantHeaders += "Empty HSTS header value"
                            continue
                        }
                        if (Test-CompliantHeader -HeaderValue $headerValue) {
                            $compliantCount++
                            $compliantHeaders += "Compliant: $headerValue"
                        } else {
                            $nonCompliantCount++
                            $nonCompliantHeaders += "Non-compliant: $headerValue"
                        }
                    }
                    if ($headerCount -gt 1) {
                        $details = "Multiple HSTS header definitions found ($headerCount total). Only one compliant configuration should exist."
                        $isCorrect = $false
                    } elseif ($compliantCount -eq 1 -and $nonCompliantCount -eq 0) {
                        $details = "HSTS is correctly configured with exactly one compliant definition: max-age=31536000; includeSubDomains"
                        $isCorrect = $true
                    } elseif ($compliantCount -eq 0 -and $nonCompliantCount -gt 0) {
                        $details = "HSTS header(s) found but none are compliant. Found $nonCompliantCount non-compliant definition(s)."
                        $isCorrect = $false
                    } elseif ($compliantCount -gt 0 -and $nonCompliantCount -gt 0) {
                        $details = "Mixed configuration: $compliantCount compliant and $nonCompliantCount non-compliant HSTS definition(s) found."
                        $isCorrect = $false
                    } else {
                        $details = "HSTS configuration issue detected"
                        $isCorrect = $false
                    }
                    if ($compliantHeaders.Count -gt 0) {
                        Log-Message "Compliant headers found:"
                        foreach ($header in $compliantHeaders) {
                            Log-Message "  - $header"
                        }
                    }
                    if ($nonCompliantHeaders.Count -gt 0) {
                        Log-Message "Non-compliant headers found:"
                        foreach ($header in $nonCompliantHeaders) {
                            Log-Message "  - $header"
                        }
                    }
                } catch {
                    $details = "Error checking HSTS configuration: $_"
                    $isCorrect = $false
                }
                return @{
                    IsCorrect = $isCorrect
                    Details = $details
                    HeaderCount = $headerCount
                    CompliantCount = $compliantCount
                    NonCompliantCount = $nonCompliantCount
                    CompliantHeaders = $compliantHeaders
                    NonCompliantHeaders = $nonCompliantHeaders
                }
            }
            
            function Remove-AllHstsHeaders {
                param([xml]$ParsedConfig)
                try {
                    $httpProtocol = $ParsedConfig.configuration.'system.webServer'.httpProtocol
                    if ($null -eq $httpProtocol) {
                        return
                    }
                    $customHeaders = $httpProtocol.customHeaders
                    if ($null -eq $customHeaders) {
                        return
                    }
                    if ($null -ne $customHeaders.add) {
                        $allAdds = @()
                        try {
                            if ($customHeaders.add -is [System.Array]) {
                                $allAdds = $customHeaders.add
                            } else {
                                $allAdds = @($customHeaders.add)
                            }
                            $hstsHeaders = $allAdds | Where-Object { 
                                $null -ne $_ -and $null -ne $_.name -and $_.name -eq "Strict-Transport-Security" 
                            }
                            if ($null -ne $hstsHeaders) {
                                $headersToRemove = @()
                                if ($hstsHeaders -is [System.Array]) {
                                    foreach ($header in $hstsHeaders) {
                                        if ($null -ne $header) {
                                            $headersToRemove += $header
                                        }
                                    }
                                } else {
                                    $headersToRemove += $hstsHeaders
                                }
                                foreach ($header in $headersToRemove) {
                                    try {
                                        $null = $customHeaders.RemoveChild($header)
                                    } catch {
                                        Log-Error "Error removing header: $_"
                                    }
                                }
                            }
                        } catch {
                            Log-Error "Error processing custom headers for removal: $_"
                            throw
                        }
                    }
                } catch {
                    Log-Error "Error removing HSTS headers: $_"
                    throw
                }
            }
            
            function Apply-CompliantHsts {
                param([xml]$ParsedConfig, [string]$ConfigPath)
                $success = $false
                $message = ""
                try {
                    Remove-AllHstsHeaders -ParsedConfig $ParsedConfig
                    if ($null -eq $ParsedConfig.configuration.'system.webServer') {
                        $systemWebServer = $ParsedConfig.CreateElement("system.webServer")
                        $null = $ParsedConfig.configuration.AppendChild($systemWebServer)
                    }
                    $systemWebServer = $ParsedConfig.configuration.'system.webServer'
                    if ($null -eq $systemWebServer.httpProtocol) {
                        $httpProtocol = $ParsedConfig.CreateElement("httpProtocol")
                        $null = $systemWebServer.AppendChild($httpProtocol)
                    }
                    $httpProtocol = $systemWebServer.httpProtocol
                    $customHeadersNode = $httpProtocol.SelectSingleNode("customHeaders")
                    if ($null -eq $customHeadersNode) {
                        $customHeaders = $ParsedConfig.CreateElement("customHeaders")
                        $null = $httpProtocol.AppendChild($customHeaders)
                    } else {
                        $customHeaders = $customHeadersNode
                    }
                    $existingHeader = $null
                    if ($null -ne $customHeaders.add) {
                        try {
                            $allAdds = @()
                            if ($customHeaders.add -is [System.Array]) {
                                $allAdds = $customHeaders.add
                            } else {
                                $allAdds = @($customHeaders.add)
                            }
                            $existingHeader = $allAdds | Where-Object { 
                                $null -ne $_ -and $null -ne $_.name -and $_.name -eq "Strict-Transport-Security" 
                            } | Select-Object -First 1
                        } catch { }
                    }
                    if ($null -eq $existingHeader) {
                        $newHeader = $ParsedConfig.CreateElement("add")
                        $nameAttr = $ParsedConfig.CreateAttribute("name")
                        $nameAttr.Value = "Strict-Transport-Security"
                        $null = $newHeader.Attributes.Append($nameAttr)
                        $valueAttr = $ParsedConfig.CreateAttribute("value")
                        $valueAttr.Value = $RecommendedHsts
                        $null = $newHeader.Attributes.Append($valueAttr)
                        $null = $customHeaders.AppendChild($newHeader)
                    } else {
                        $existingHeader.value = $RecommendedHsts
                    }
                    if ($DryRun) {
                        Log-Message "DRY RUN: Would apply compliant HSTS configuration"
                        $success = $true
                        $message = "DRY RUN: Would apply compliant HSTS configuration"
                    } else {
                        $tempXmlPath = $null
                        try {
                            $tempXmlPath = [System.IO.Path]::GetTempFileName()
                            $ParsedConfig.Save($tempXmlPath)
                            if (-not (Test-ValidXml -XmlFilePath $tempXmlPath)) {
                                if ($null -ne $tempXmlPath -and (Test-Path $tempXmlPath)) {
                                    Remove-Item -Path $tempXmlPath -Force -ErrorAction SilentlyContinue
                                }
                                throw "Generated XML failed validation"
                            }
                            Copy-Item -Path $tempXmlPath -Destination $ConfigPath -Force -ErrorAction Stop
                            if ($null -ne $tempXmlPath -and (Test-Path $tempXmlPath)) {
                                Remove-Item -Path $tempXmlPath -Force -ErrorAction SilentlyContinue
                            }
                            if (-not (Test-ValidXml -XmlFilePath $ConfigPath)) {
                                throw "Final configuration file failed validation"
                            }
                            $success = $true
                            $message = "Compliant HSTS configuration applied successfully. All duplicate/non-compliant headers removed."
                        } catch {
                            $message = "Failed to save configuration: $_"
                            $success = $false
                            if ($null -ne $tempXmlPath -and (Test-Path $tempXmlPath)) {
                                Remove-Item -Path $tempXmlPath -Force -ErrorAction SilentlyContinue
                            }
                        }
                    }
                } catch {
                    $message = "Failed to apply compliant HSTS configuration: $_"
                    $success = $false
                }
                return @{
                    Success = $success
                    Message = $message
                }
            }
            
            function Backup-Config {
                param([string]$ConfigPath)
                if (-not (Test-Path -Path $ConfigPath)) {
                    Log-Error "Configuration file not found: $ConfigPath"
                    throw "File not found"
                }
                $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                $backupPath = "$ConfigPath.backup.$timestamp"
                try {
                    Copy-Item -Path $ConfigPath -Destination $backupPath -ErrorAction Stop
                    Log-Message "Backup created: $backupPath"
                    return $backupPath
                } catch {
                    Log-Error "Failed to create backup: $_"
                    throw "Backup failed"
                }
            }
            
            function Find-IisWebConfigFiles {
                $webConfigFiles = @()
                $defaultWebConfig = "C:\inetpub\wwwroot\web.config"
                if (Test-Path $defaultWebConfig) {
                    $webConfigFiles += $defaultWebConfig
                    Log-Message "Found: $defaultWebConfig (default wwwroot)"
                }
                $wwwrootPath = "C:\inetpub\wwwroot"
                if (Test-Path $wwwrootPath) {
                    $appDirs = Get-ChildItem -Path $wwwrootPath -Directory -ErrorAction SilentlyContinue
                    foreach ($appDir in $appDirs) {
                        $appWebConfig = Join-Path $appDir.FullName "web.config"
                        if (Test-Path $appWebConfig) {
                            $webConfigFiles += $appWebConfig
                            Log-Message "Found: $appWebConfig (application-specific)"
                        }
                    }
                }
                if (Get-Module -ListAvailable -Name WebAdministration) {
                    try {
                        Import-Module WebAdministration -ErrorAction SilentlyContinue
                        $sites = Get-WebSite -ErrorAction SilentlyContinue
                        foreach ($site in $sites) {
                            $sitePath = $site.PhysicalPath
                            if ($sitePath -and (Test-Path $sitePath)) {
                                $siteWebConfig = Join-Path $sitePath "web.config"
                                if (Test-Path $siteWebConfig) {
                                    if ($webConfigFiles -notcontains $siteWebConfig) {
                                        $webConfigFiles += $siteWebConfig
                                        Log-Message "Found: $siteWebConfig (IIS site: $($site.Name))"
                                    }
                                }
                            }
                        }
                    } catch {
                        Log-Message "WARNING: Could not query IIS sites: $_"
                    }
                }
                Log-Message "Found $($webConfigFiles.Count) web.config file(s) to process"
                return $webConfigFiles
            }
            
            function Process-WebConfig {
                param([string]$WebConfigPath, [string]$Mode)
                Log-Message ""
                Log-Message "========================================="
                Log-Message "Processing: $WebConfigPath"
                Log-Message "========================================="
                try {
                    $parsedConfig = Load-Config -ConfigPath $WebConfigPath
                    if ($Mode -eq "audit") {
                        $auditResult = Audit-HstsHeaders -ParsedConfig $parsedConfig
                        if ($auditResult.IsCorrect) {
                            Log-Message "SUCCESS: $($auditResult.Details)"
                            Log-Message "HSTS configuration is compliant."
                            return 0
                        } else {
                            Log-Message "FAILURE: $($auditResult.Details)"
                            Log-Message "HSTS configuration needs to be updated."
                            return 1
                        }
                    } elseif ($Mode -eq "configure") {
                        if ($DryRun) {
                            Log-Message "DRY RUN mode: No changes will be made"
                        }
                        $auditResult = Audit-HstsHeaders -ParsedConfig $parsedConfig
                        Log-Message "Current state: $($auditResult.Details)"
                        if ($auditResult.CompliantCount -eq 1 -and $auditResult.NonCompliantCount -eq 0 -and $auditResult.HeaderCount -eq 1) {
                            Log-Message "SUCCESS: HSTS is already correctly configured with exactly one compliant definition"
                            return 0
                        }
                        Log-Message "Configuration required: Ensuring exactly one compliant HSTS definition exists"
                        $backupPath = Backup-Config -ConfigPath $WebConfigPath
                        $configureResult = Apply-CompliantHsts -ParsedConfig $parsedConfig -ConfigPath $WebConfigPath
                        if (-not $configureResult.Success) {
                            Log-Error "Failed to configure HSTS: $($configureResult.Message)"
                            Log-Message "Backup available at: $backupPath"
                            return 1
                        }
                        Log-Message "SUCCESS: $($configureResult.Message)"
                        Log-Message "Backup available at: $backupPath"
                        return 0
                    }
                } catch {
                    Log-Error "Error processing $WebConfigPath : $_"
                    return 1
                }
            }
            
            # Main execution
            $webConfigFiles = @()
            if ($ConfigPath) {
                $ConfigPath = $ConfigPath.Trim()
                if (Test-Path $ConfigPath) {
                    $webConfigFiles += $ConfigPath
                    Log-Message "Using provided web.config path: $ConfigPath"
                } else {
                    Log-Error "Provided web.config path not found: $ConfigPath"
                    return @{ Success = $false; Message = "Config path not found" }
                }
            } else {
                $webConfigFiles = Find-IisWebConfigFiles
                if ($webConfigFiles.Count -eq 0) {
                    Log-Error "No web.config files found to process"
                    return @{ Success = $false; Message = "No web.config files found" }
                }
            }
            
            $overallSuccess = 0
            $processedCount = 0
            $successCount = 0
            $failureCount = 0
            
            foreach ($webConfig in $webConfigFiles) {
                $result = Process-WebConfig -WebConfigPath $webConfig -Mode $Mode
                $processedCount++
                if ($result -eq 0) {
                    $successCount++
                } else {
                    $failureCount++
                    $overallSuccess = 1
                }
            }
            
            Log-Message ""
            Log-Message "========================================="
            Log-Message "Summary"
            Log-Message "========================================="
            Log-Message "Total files processed: $processedCount"
            Log-Message "Successful: $successCount"
            Log-Message "Failed: $failureCount"
            
            return @{
                Success = ($overallSuccess -eq 0)
                ProcessedCount = $processedCount
                SuccessCount = $successCount
                FailureCount = $failureCount
                LogFile = $LogFile
            }
        }
        
        $invokeParams = @{
            ComputerName = $server
            ScriptBlock = $scriptBlock
            ArgumentList = @($Mode, $ConfigPath, $DryRun.IsPresent)
        }
        
        if ($Credential) {
            $invokeParams.Credential = $Credential
        }
        
        $result = Invoke-Command @invokeParams
        
        Write-Host "Result from $server :"
        Write-Host "  Success: $($result.Success)"
        Write-Host "  Processed: $($result.ProcessedCount)"
        Write-Host "  Successful: $($result.SuccessCount)"
        Write-Host "  Failed: $($result.FailureCount)"
        if ($result.LogFile) {
            Write-Host "  Log file: $($result.LogFile)"
        }
        
    } catch {
        Write-Host "ERROR: Failed to process server $server : $_" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "========================================="
Write-Host "Remote execution completed"
Write-Host "========================================="

