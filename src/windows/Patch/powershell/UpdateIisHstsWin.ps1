# UpdateIisHstsWin.ps1
# Audit and Configure HSTS (HTTP Strict Transport Security) in IIS
# For Windows Server environments only
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("audit", "configure")]
    [string]$Mode = "configure",
    
    [Parameter(Mandatory=$false)]
    [string]$ConfigPath = $null,
    
    [Parameter(Mandatory=$false)]
    [string[]]$CustomPaths = @(),
    
    [Parameter(Mandatory=$false)]
    [string]$CustomPathsFile = $null,
    
    [Parameter(Mandatory=$false)]
    [string]$LogFile = "$env:LOCALAPPDATA\Temp\IisHsts.log",
    
    [Parameter(Mandatory=$false)]
    [switch]$DryRun = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force = $false
)

$ErrorActionPreference = "Stop"
$RecommendedHsts = "max-age=31536000; includeSubDomains"
$Hostname = $env:COMPUTERNAME
$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Initialize log file
if ($LogFile -eq "") {
    $LogFile = "$env:LOCALAPPDATA\Temp\IisHsts.log"
}
try {
    $null = New-Item -Path $LogFile -ItemType File -Force -ErrorAction Stop
} catch {
    Write-Host "WARNING: Cannot create log file: $LogFile"
}

# Function: Log message to console and optionally to file
function Log-Message {
    param(
        [string]$Message
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $Message"
    
    Write-Host $logEntry
    
    if ($LogFile -ne "") {
        try {
            Add-Content -Path $LogFile -Value $logEntry -ErrorAction SilentlyContinue
        } catch {
            # Silently fail if log file cannot be written
        }
    }
}

# Function: Log error message
function Log-Error {
    param(
        [string]$Message
    )
    
    Log-Message "ERROR: $Message"
}

Log-Message "========================================="
Log-Message "IIS HSTS Configuration Tool"
Log-Message "Hostname: $Hostname"
Log-Message "Execution Time: $Timestamp"
Log-Message "Mode: $Mode"
if ($Force) {
    Log-Message "Force Mode: Enabled (auto-approve all changes)"
}
Log-Message "========================================="

# Function: Load custom paths from file
function Get-CustomPathsFromFile {
    param([string]$PathsFile)
    
    $paths = @()
    if (-not $PathsFile -or -not (Test-Path $PathsFile)) {
        return $paths
    }
    
    try {
        $fileContent = Get-Content -Path $PathsFile -ErrorAction Stop
        foreach ($line in $fileContent) {
            $trimmedLine = $line.Trim()
            if ($trimmedLine -and -not $trimmedLine.StartsWith("#")) {
                $paths += $trimmedLine
            }
        }
        Log-Message "Loaded $($paths.Count) custom path(s) from file: $PathsFile"
    } catch {
        Log-Error "Failed to read custom paths file: $PathsFile - $_"
    }
    
    return $paths
}

# Function: Auto-detect IIS web.config files
function Find-IisWebConfigFiles {
    param(
        [string]$CustomConfigPath,
        [string[]]$CustomPathsArray,
        [string]$CustomPathsFile
    )
    
    $webConfigFiles = @()
    
    # Add custom paths first
    $allCustomPaths = @()
    
    # Add single custom path if provided
    if ($CustomConfigPath) {
        if ((Test-Path $CustomConfigPath) -and (Test-Path $CustomConfigPath -PathType Leaf)) {
            # It's a file
            if ($webConfigFiles -notcontains $CustomConfigPath) {
                $webConfigFiles += $CustomConfigPath
                Log-Message "Found: $CustomConfigPath (custom file path)"
            }
        } elseif ((Test-Path $CustomConfigPath) -and (Test-Path $CustomConfigPath -PathType Container)) {
            # It's a directory, look for web.config
            $customWebConfig = Join-Path $CustomConfigPath "web.config"
            if (Test-Path $customWebConfig) {
                if ($webConfigFiles -notcontains $customWebConfig) {
                    $webConfigFiles += $customWebConfig
                    Log-Message "Found: $customWebConfig (custom directory path)"
                }
            }
        }
    }
    
    # Add custom paths from array
    foreach ($path in $CustomPathsArray) {
        if ($path) {
            if ((Test-Path $path) -and (Test-Path $path -PathType Leaf)) {
                # It's a file
                if ($webConfigFiles -notcontains $path) {
                    $webConfigFiles += $path
                    Log-Message "Found: $path (custom file path)"
                }
            } elseif ((Test-Path $path) -and (Test-Path $path -PathType Container)) {
                # It's a directory, look for web.config
                $customWebConfig = Join-Path $path "web.config"
                if (Test-Path $customWebConfig) {
                    if ($webConfigFiles -notcontains $customWebConfig) {
                        $webConfigFiles += $customWebConfig
                        Log-Message "Found: $customWebConfig (custom directory path)"
                    }
                }
            }
        }
    }
    
    # Add custom paths from file
    if ($CustomPathsFile) {
        $filePaths = Get-CustomPathsFromFile -PathsFile $CustomPathsFile
        foreach ($path in $filePaths) {
            if ($path) {
                if ((Test-Path $path) -and (Test-Path $path -PathType Leaf)) {
                    # It's a file
                    if ($webConfigFiles -notcontains $path) {
                        $webConfigFiles += $path
                        Log-Message "Found: $path (custom file path from file)"
                    }
                } elseif ((Test-Path $path) -and (Test-Path $path -PathType Container)) {
                    # It's a directory, look for web.config
                    $customWebConfig = Join-Path $path "web.config"
                    if (Test-Path $customWebConfig) {
                        if ($webConfigFiles -notcontains $customWebConfig) {
                            $webConfigFiles += $customWebConfig
                            Log-Message "Found: $customWebConfig (custom directory path from file)"
                        }
                    }
                }
            }
        }
    }
    
    # Check default wwwroot
    $defaultWebConfig = "C:\inetpub\wwwroot\web.config"
    if (Test-Path $defaultWebConfig) {
        if ($webConfigFiles -notcontains $defaultWebConfig) {
            $webConfigFiles += $defaultWebConfig
            Log-Message "Found: $defaultWebConfig (default wwwroot)"
        }
    }
    
    # Check application-specific web.config files in wwwroot
    $wwwrootPath = "C:\inetpub\wwwroot"
    if (Test-Path $wwwrootPath) {
        $appDirs = Get-ChildItem -Path $wwwrootPath -Directory -ErrorAction SilentlyContinue
        foreach ($appDir in $appDirs) {
            $appWebConfig = Join-Path $appDir.FullName "web.config"
            if (Test-Path $appWebConfig) {
                if ($webConfigFiles -notcontains $appWebConfig) {
                    $webConfigFiles += $appWebConfig
                    Log-Message "Found: $appWebConfig (application-specific)"
                }
            }
        }
    }
    
    # Use IIS WebAdministration module if available
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

# Function: Validate XML file
# Parameters: xml_file_path
# Returns: Boolean indicating if valid
function Test-ValidXml {
    param(
        [string]$XmlFilePath
    )
    
    try {
        $xmlContent = Get-Content -Path $XmlFilePath -Raw -ErrorAction Stop
        [xml]$null = $xmlContent
        return $true
    } catch {
        return $false
    }
}

# Function: Validate file path
# Parameters: file_path
# Returns: Boolean indicating if valid
function Test-ValidFilePath {
    param(
        [string]$FilePath
    )
    
    # Check for path traversal attempts
    if ($FilePath -match '\.\.') {
        Log-Error "Invalid path: contains '..' (path traversal attempt)"
        return $false
    }
    
    # Check for null bytes
    if ($FilePath -match '\0') {
        Log-Error "Invalid path: contains null byte"
        return $false
    }
    
    return $true
}

# Function: Load and parse IIS web.config file
# Parameters: config_path
# Returns: Parsed XML object
function Load-Config {
    param(
        [string]$ConfigPath
    )
    
    # Validate path first
    if (-not (Test-ValidFilePath -FilePath $ConfigPath)) {
        throw "Invalid path"
    }
    
    if (-not (Test-Path -Path $ConfigPath)) {
        Log-Error "Configuration file not found: $ConfigPath"
        throw "File not found"
    }
    
    # Check if it's a symlink/junction (warn but allow)
    $item = Get-Item -Path $ConfigPath -ErrorAction SilentlyContinue
    if ($null -ne $item -and $item.LinkType) {
        Log-Message "WARNING: Configuration path is a $($item.LinkType): $ConfigPath"
    }
    
    # Check if file is empty
    $fileInfo = Get-Item -Path $ConfigPath -ErrorAction Stop
    if ($fileInfo.Length -eq 0) {
        Log-Error "Configuration file is empty: $ConfigPath"
        throw "Empty file"
    }
    
    try {
        $configContent = Get-Content -Path $ConfigPath -Raw -ErrorAction Stop
        
        # Validate XML before parsing
        if (-not (Test-ValidXml -XmlFilePath $ConfigPath)) {
            Log-Error "Configuration file contains invalid XML: $ConfigPath"
            throw "Invalid XML"
        }
        
        [xml]$xmlConfig = $configContent
        return $xmlConfig
    } catch {
        if ($_.Exception.Message -match "Parse error|Invalid XML|Empty file") {
            Log-Error "Failed to parse configuration file as XML: $_"
            throw $_.Exception.Message
        } else {
            Log-Error "Failed to load configuration file: $_"
            throw "Load error"
        }
    }
}

# Function: Check if HSTS header value is compliant
# Parameters: header_value
# Returns: Boolean indicating if compliant
# Compliance per OWASP HSTS Cheat Sheet:
# - Required: max-age=31536000 (1 year)
# - Required: includeSubDomains
# - Optional: preload (allowed but not required)
function Test-CompliantHeader {
    param(
        [string]$HeaderValue
    )
    
    if ([string]::IsNullOrWhiteSpace($HeaderValue)) {
        return $false
    }
    
    # Check for max-age=31536000 (required per OWASP recommendation)
    if ($HeaderValue -notmatch "max-age=31536000") {
        return $false
    }
    
    # Check for includeSubDomains (required per OWASP recommendation)
    if ($HeaderValue -notmatch "includeSubDomains") {
        return $false
    }
    
    # Note: preload directive is optional and allowed but not required for compliance
    # per OWASP HSTS Cheat Sheet recommendations
    
    return $true
}

# Function: Find all HSTS header definitions
# Parameters: parsed_config
# Returns: Array of HSTS header objects
function Find-AllHstsHeaders {
    param(
        [xml]$ParsedConfig
    )
    
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
        
        # Find all Strict-Transport-Security headers (case-insensitive)
        # Handle both single add element and array of add elements
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
                    # Handle both single object and array
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

# Function: Audit HSTS header configuration
# Parameters: parsed_config
# Returns: Hashtable with audit results
function Audit-HstsHeaders {
    param(
        [xml]$ParsedConfig
    )
    
    $isCorrect = $false
    $details = ""
    $headerCount = 0
    $compliantCount = 0
    $nonCompliantCount = 0
    $compliantHeaders = @()
    $nonCompliantHeaders = @()
    
    try {
        # Find all HSTS headers
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
        
        # Check each header for compliance
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
        
        # Determine overall status
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
        
        # Log detailed findings
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

# Function: Remove all existing HSTS headers
# Parameters: parsed_config
# Returns: None (modifies XML in place)
function Remove-AllHstsHeaders {
    param(
        [xml]$ParsedConfig
    )
    
    try {
        $httpProtocol = $ParsedConfig.configuration.'system.webServer'.httpProtocol
        
        if ($null -eq $httpProtocol) {
            return
        }
        
        $customHeaders = $httpProtocol.customHeaders
        
        if ($null -eq $customHeaders) {
            return
        }
        
        # Find and remove all Strict-Transport-Security headers (case-insensitive)
        # Handle both single add element and array of add elements
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
                    # Collect headers to remove first (to avoid modification during iteration)
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
                    
                    # Now remove them
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

# Function: Apply compliant HSTS configuration
# Parameters: parsed_config, config_path
# Returns: Hashtable with success status and message
function Apply-CompliantHsts {
    param(
        [xml]$ParsedConfig,
        [string]$ConfigPath
    )
    
    $success = $false
    $message = ""
    
    try {
        # First, remove all existing HSTS headers
        Remove-AllHstsHeaders -ParsedConfig $ParsedConfig
        
        # Ensure system.webServer section exists
        if ($null -eq $ParsedConfig.configuration.'system.webServer') {
            $systemWebServer = $ParsedConfig.CreateElement("system.webServer")
            $null = $ParsedConfig.configuration.AppendChild($systemWebServer)
        }
        
        $systemWebServer = $ParsedConfig.configuration.'system.webServer'
        
        # Ensure httpProtocol section exists
        if ($null -eq $systemWebServer.httpProtocol) {
            $httpProtocol = $ParsedConfig.CreateElement("httpProtocol")
            $null = $systemWebServer.AppendChild($httpProtocol)
        }
        
        $httpProtocol = $systemWebServer.httpProtocol
        
        # Ensure customHeaders section exists
        # Check if customHeaders element exists in the XML structure
        $customHeadersNode = $httpProtocol.SelectSingleNode("customHeaders")
        if ($null -eq $customHeadersNode) {
            # Element doesn't exist, create it
            $customHeaders = $ParsedConfig.CreateElement("customHeaders")
            $null = $httpProtocol.AppendChild($customHeaders)
        } else {
            # Element exists, get it as XML element (not string property)
            $customHeaders = $customHeadersNode
        }
        
        # Verify we don't already have a compliant header (shouldn't happen after Remove-AllHstsHeaders, but check anyway)
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
            } catch {
                # Ignore errors, just proceed to add new header
            }
        }
        
        if ($null -eq $existingHeader) {
            # Add new compliant HSTS header
            $newHeader = $ParsedConfig.CreateElement("add")
            $nameAttr = $ParsedConfig.CreateAttribute("name")
            $nameAttr.Value = "Strict-Transport-Security"
            $null = $newHeader.Attributes.Append($nameAttr)
            
            $valueAttr = $ParsedConfig.CreateAttribute("value")
            $valueAttr.Value = $RecommendedHsts
            $null = $newHeader.Attributes.Append($valueAttr)
            
            $null = $customHeaders.AppendChild($newHeader)
        } else {
            # Update existing header if somehow it still exists
            $existingHeader.value = $RecommendedHsts
        }
        
        if ($DryRun) {
            Log-Message "DRY RUN: Would apply compliant HSTS configuration"
            Log-Message "Modified configuration would be:"
            $ParsedConfig.Save([System.Console]::Out)
            $success = $true
            $message = "DRY RUN: Would apply compliant HSTS configuration"
        } else {
            # Validate XML before saving
            $tempXmlPath = $null
            try {
                $tempXmlPath = [System.IO.Path]::GetTempFileName()
                $ParsedConfig.Save($tempXmlPath)
                
                # Verify the saved XML is valid
                if (-not (Test-ValidXml -XmlFilePath $tempXmlPath)) {
                    if ($null -ne $tempXmlPath -and (Test-Path $tempXmlPath)) {
                        Remove-Item -Path $tempXmlPath -Force -ErrorAction SilentlyContinue
                    }
                    throw "Generated XML failed validation"
                }
                
                # Copy validated XML to target location
                Copy-Item -Path $tempXmlPath -Destination $ConfigPath -Force -ErrorAction Stop
                
                # Clean up temp file
                if ($null -ne $tempXmlPath -and (Test-Path $tempXmlPath)) {
                    Remove-Item -Path $tempXmlPath -Force -ErrorAction SilentlyContinue
                }
                
                # Verify the final file is valid
                if (-not (Test-ValidXml -XmlFilePath $ConfigPath)) {
                    throw "Final configuration file failed validation"
                }
                
                $success = $true
                $message = "Compliant HSTS configuration applied successfully. All duplicate/non-compliant headers removed."
            } catch {
                $message = "Failed to save configuration: $_"
                $success = $false
                # Clean up temp file if it exists
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

# Function: Create backup of configuration file
# Parameters: config_path
# Returns: Path to backup file
function Backup-Config {
    param(
        [string]$ConfigPath
    )
    
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

# Function: Log audit results
function Log-AuditResults {
    param(
        [bool]$IsCorrect,
        [string]$Details
    )
    
    if ($IsCorrect) {
        Log-Message "SUCCESS: $Details"
        Log-Message "HSTS configuration is compliant."
    } else {
        Log-Message "FAILURE: $Details"
        Log-Message "HSTS configuration needs to be updated."
    }
}

# Function: Prompt for confirmation
function Confirm-Configure {
    if ($DryRun) {
        return $true
    }
    
    if ($Force) {
        Log-Message "Force mode enabled: Auto-approving configuration changes"
        return $true
    }
    
    Write-Host ""
    Write-Host "WARNING: This will modify the configuration file: $ConfigPath"
    Write-Host "All existing HSTS configurations will be removed and replaced with one compliant version."
    Write-Host "A backup will be created before making changes."
    Write-Host ""
    $response = Read-Host "Do you want to continue? (yes/no)"
    
    if ($response -match "^(yes|y)$") {
        return $true
    } else {
        Log-Message "Configuration operation cancelled by user"
        return $false
    }
}

# Function: Process a single web.config file
function Process-WebConfig {
    param(
        [string]$WebConfigPath,
        [string]$Mode
    )
    
    Log-Message ""
    Log-Message "========================================="
    Log-Message "Processing: $WebConfigPath"
    Log-Message "========================================="
    
    try {
        $parsedConfig = Load-Config -ConfigPath $WebConfigPath
        
        if ($Mode -eq "audit") {
            $auditResult = Audit-HstsHeaders -ParsedConfig $parsedConfig
            Log-AuditResults -IsCorrect $auditResult.IsCorrect -Details $auditResult.Details
            
            if ($auditResult.IsCorrect) {
                return 0
            } else {
                if ($auditResult.HeaderCount -gt 1) {
                    Log-Message "ACTION REQUIRED: Remove duplicate HSTS definitions. Only one compliant configuration should exist."
                }
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
            
            if (-not $DryRun) {
                if (-not $Force) {
                    Write-Host ""
                    Write-Host "WARNING: This will modify: $WebConfigPath"
                    Write-Host "A backup will be created before making changes."
                    $response = Read-Host "Do you want to continue? (yes/no)"
                    if ($response -notmatch "^(yes|y)$") {
                        Log-Message "Configuration operation cancelled by user"
                        return 2
                    }
                } else {
                    Log-Message "Force mode enabled: Auto-approving configuration changes"
                }
            }
            
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
try {
    # Auto-detect or use provided paths
    $webConfigFiles = Find-IisWebConfigFiles -CustomConfigPath $ConfigPath -CustomPathsArray $CustomPaths -CustomPathsFile $CustomPathsFile
    
    if ($webConfigFiles.Count -eq 0) {
        Log-Error "No web.config files found to process"
        Log-Error "  - Ensure IIS is installed on this Windows Server"
        Log-Error "  - Or specify a custom path: -ConfigPath 'C:\path\to\web.config'"
        Log-Error "  - Or specify multiple paths: -CustomPaths @('C:\path1\web.config', 'C:\path2')"
        Log-Error "  - Or specify a paths file: -CustomPathsFile 'C:\paths.txt' (one path per line)"
        exit 1
    }
    
    # Process each web.config file
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
            if ($result -ne 2) {  # Don't count user cancellation as failure
                $overallSuccess = 1
            }
        }
    }
    
    # Summary
    Log-Message ""
    Log-Message "========================================="
    Log-Message "Summary"
    Log-Message "========================================="
    Log-Message "Total files processed: $processedCount"
    Log-Message "Successful: $successCount"
    Log-Message "Failed: $failureCount"
    
    if ($overallSuccess -eq 0) {
        Log-Message "Overall Status: SUCCESS"
    } else {
        Log-Message "Overall Status: FAILURE (some files failed)"
    }
    
    Log-Message "Log file: $LogFile"
    
    exit $overallSuccess
    
} catch {
    Log-Error "An error occurred during execution: $_"
    exit 2
}

