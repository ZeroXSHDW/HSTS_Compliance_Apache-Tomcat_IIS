# UpdateIisHstsWin.ps1
# Audit and Configure HSTS (HTTP Strict Transport Security) in IIS
# For Windows Server environments only
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("audit", "configure")]
    [string]$Mode = "configure",
    
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = $null,
    
    [Parameter(Mandatory = $false)]
    [string[]]$CustomPaths = @(),
    
    [Parameter(Mandatory = $false)]
    [string]$CustomPathsFile = $null,
    
    [Parameter(Mandatory = $false)]
    [string]$LogFile = $null,
    
    [Parameter(Mandatory = $false)]
    [switch]$DryRun = $false,
    
    [Parameter(Mandatory = $false)]
    [switch]$Force = $false,

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = $null,

    [Parameter(Mandatory = $false)]
    [ValidateSet("json", "csv", "text")]
    [string]$OutputFormat = "text",

    [Parameter(Mandatory = $false)]
    [ValidateSet("basic", "high", "veryhigh", "maximum")]
    [string]$SecurityLevel = "high"
)

$ErrorActionPreference = "Stop"
$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Security Level Definitions
$MinMaxAge = 31536000
$RequireSubDomains = $true
$RequirePreload = $false

switch ($SecurityLevel.ToLower()) {
    "basic" {
        $MinMaxAge = 31536000
        $RequireSubDomains = $false
        $RequirePreload = $false
    }
    "high" {
        $MinMaxAge = 31536000
        $RequireSubDomains = $true
        $RequirePreload = $false
    }
    "veryhigh" {
        $MinMaxAge = 31536000
        $RequireSubDomains = $true
        $RequirePreload = $true
    }
    "maximum" {
        $MinMaxAge = 63072000
        $RequireSubDomains = $true
        $RequirePreload = $true
    }
}

$RecommendedHsts = "max-age=$MinMaxAge"
if ($RequireSubDomains) { $RecommendedHsts += "; includeSubDomains" }
if ($RequirePreload) { $RecommendedHsts += "; preload" }

# Initialize log file
if ($LogFile -eq "" -or $null -eq $LogFile) {
    if ($env:TEMP) {
        $LogFile = Join-Path $env:TEMP "IisHsts_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    }
    else {
        $LogFile = "/tmp/IisHsts_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    }
}
try {
    $null = New-Item -Path $LogFile -ItemType File -Force -ErrorAction Stop
}
catch {
    Write-Host "WARNING: Cannot create log file: $LogFile"
    # Fallback to current directory
    try {
        $LogFile = "./IisHsts_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        $null = New-Item -Path $LogFile -ItemType File -Force -ErrorAction Stop
        Write-Host "Logging to: $LogFile"
    }
    catch {
        Write-Host "WARNING: Still cannot create log file. Console only."
        $LogFile = $null
    }
}

# Function: Log message to console and optionally to file
function Write-LogMessage {
    param(
        [string]$Message
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $Message"
    
    Write-Host $logEntry
    
    if ($LogFile -ne "") {
        try {
            Add-Content -Path $LogFile -Value $logEntry -ErrorAction SilentlyContinue
        }
        catch {
            # Silently fail if log file cannot be written
        }
    }
}

# Function: Log error message
function Write-LogError {
    param(
        [string]$Message
    )
    
    Write-LogMessage "ERROR: $Message"
}

Write-LogMessage "========================================="
Write-LogMessage "IIS HSTS Configuration Tool"
Write-LogMessage "Hostname: $Hostname"
Write-LogMessage "Execution Time: $Timestamp"
Write-LogMessage "Mode: $Mode"
if ($Force) {
    Write-LogMessage "Force Mode: Enabled (auto-approve all changes)"
}
Write-LogMessage "========================================="

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
        Write-LogMessage "Loaded $($paths.Count) custom path(s) from file: $PathsFile"
    }
    catch {
        Write-LogError "Failed to read custom paths file: $PathsFile - $_"
    }
    
    return $paths
}

# Function: Detect IIS version from registry
function Get-IisVersion {
    $version = "Unknown"
    try {
        $iisRegPath = "HKLM:\SOFTWARE\Microsoft\InetStp"
        if (Test-Path $iisRegPath) {
            $major = (Get-ItemProperty -Path $iisRegPath -Name "MajorVersion" -ErrorAction SilentlyContinue).MajorVersion
            $minor = (Get-ItemProperty -Path $iisRegPath -Name "MinorVersion" -ErrorAction SilentlyContinue).MinorVersion
            if ($null -ne $major) {
                if ($null -ne $minor) {
                    $version = "$major.$minor"
                }
                else {
                    $version = "$major.0"
                }
            }
        }
    }
    catch { }
    return $version
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
    
    # Add single custom path if provided
    if ($CustomConfigPath) {
        if ((Test-Path $CustomConfigPath) -and (Test-Path $CustomConfigPath -PathType Leaf)) {
            # It's a file
            if ($webConfigFiles -notcontains $CustomConfigPath) {
                $webConfigFiles += $CustomConfigPath
                Write-LogMessage "Found: $CustomConfigPath (custom file path)"
            }
        }
        elseif ((Test-Path $CustomConfigPath) -and (Test-Path $CustomConfigPath -PathType Container)) {
            # It's a directory, look for web.config
            $customWebConfig = Join-Path $CustomConfigPath "web.config"
            if (Test-Path $customWebConfig) {
                if ($webConfigFiles -notcontains $customWebConfig) {
                    $webConfigFiles += $customWebConfig
                    Write-LogMessage "Found: $customWebConfig (custom directory path)"
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
                    Write-LogMessage "Found: $path (custom file path)"
                }
            }
            elseif ((Test-Path $path) -and (Test-Path $path -PathType Container)) {
                # It's a directory, look for web.config
                $customWebConfig = Join-Path $path "web.config"
                if (Test-Path $customWebConfig) {
                    if ($webConfigFiles -notcontains $customWebConfig) {
                        $webConfigFiles += $customWebConfig
                        Write-LogMessage "Found: $customWebConfig (custom directory path)"
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
                        Write-LogMessage "Found: $path (custom file path from file)"
                    }
                }
                elseif ((Test-Path $path) -and (Test-Path $path -PathType Container)) {
                    # It's a directory, look for web.config
                    $customWebConfig = Join-Path $path "web.config"
                    if (Test-Path $customWebConfig) {
                        if ($webConfigFiles -notcontains $customWebConfig) {
                            $webConfigFiles += $customWebConfig
                            Write-LogMessage "Found: $customWebConfig (custom directory path from file)"
                        }
                    }
                }
            }
        }
    }
    
    # Build comprehensive list of possible wwwroot paths (similar to Tomcat approach)
    $possibleWwwrootPaths = @(
        "C:\inetpub\wwwroot",
        "D:\inetpub\wwwroot",
        "E:\inetpub\wwwroot",
        "F:\inetpub\wwwroot",
        "G:\inetpub\wwwroot",
        "H:\inetpub\wwwroot",
        "I:\inetpub\wwwroot",
        "J:\inetpub\wwwroot",
        "K:\inetpub\wwwroot",
        "C:\wwwroot",
        "D:\wwwroot",
        "E:\wwwroot",
        "F:\wwwroot",
        "G:\wwwroot",
        "H:\wwwroot",
        "I:\wwwroot",
        "J:\wwwroot",
        "K:\wwwroot",
        "C:\WebSites",
        "D:\WebSites",
        "E:\WebSites",
        "F:\WebSites",
        "G:\WebSites",
        "H:\WebSites",
        "I:\WebSites",
        "J:\WebSites",
        "K:\WebSites",
        "C:\IIS\wwwroot",
        "D:\IIS\wwwroot",
        "E:\IIS\wwwroot",
        "F:\IIS\wwwroot",
        "G:\IIS\wwwroot",
        "H:\IIS\wwwroot",
        "I:\IIS\wwwroot",
        "J:\IIS\wwwroot",
        "K:\IIS\wwwroot",
        "C:\Apps\WebSites",
        "C:\Applications\WebSites",
        "C:\Sites",
        "D:\Apps\WebSites",
        "D:\Sites",
        "E:\Sites"
    )
    
    # Check inetpub root and scan for wwwroot subdirectories
    $inetpubRoots = @("C:\inetpub", "D:\inetpub", "E:\inetpub", "F:\inetpub", "G:\inetpub", "H:\inetpub", "I:\inetpub", "J:\inetpub", "K:\inetpub")
    foreach ($inetpubRoot in $inetpubRoots) {
        if (Test-Path $inetpubRoot) {
            $subDirs = Get-ChildItem -Path $inetpubRoot -Directory -ErrorAction SilentlyContinue
            foreach ($dir in $subDirs) {
                $wwwrootPath = $dir.FullName
                if ($possibleWwwrootPaths -notcontains $wwwrootPath) {
                    $possibleWwwrootPaths += $wwwrootPath
                }
            }
        }
    }
    
    # Check alternative IIS installation directories
    $alternativeIISRoots = @("C:\Apps", "C:\Applications", "C:\Sites", "D:\Apps", "D:\Sites", "E:\Sites")
    foreach ($root in $alternativeIISRoots) {
        if (Test-Path $root) {
            Write-LogMessage "Searching alternative IIS root: $root"
            $subDirs = Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue
            foreach ($dir in $subDirs) {
                if ($possibleWwwrootPaths -notcontains $dir.FullName) {
                    $possibleWwwrootPaths += $dir.FullName
                }
            }
        }
    }
    
    # Check environment variables for IIS paths
    $iisPath = $env:IIS_PATH
    if ($iisPath -and (Test-Path $iisPath)) {
        if ($possibleWwwrootPaths -notcontains $iisPath) {
            $possibleWwwrootPaths += $iisPath
            Write-LogMessage "Added IIS_PATH environment variable to search paths: $iisPath"
        }
    }
    
    $wwwrootEnv = $env:WWWROOT
    if ($wwwrootEnv -and (Test-Path $wwwrootEnv)) {
        if ($possibleWwwrootPaths -notcontains $wwwrootEnv) {
            $possibleWwwrootPaths += $wwwrootEnv
            Write-LogMessage "Added WWWROOT environment variable to search paths: $wwwrootEnv"
        }
    }
    
    $iisHome = $env:IIS_HOME
    if ($iisHome -and (Test-Path $iisHome)) {
        $iisHomeWwwroot = Join-Path $iisHome "wwwroot"
        if (Test-Path $iisHomeWwwroot) {
            if ($possibleWwwrootPaths -notcontains $iisHomeWwwroot) {
                $possibleWwwrootPaths += $iisHomeWwwroot
                Write-LogMessage "Added IIS_HOME/wwwroot to search paths: $iisHomeWwwroot"
            }
        }
    }
    
    # Check registry for IIS installation paths
    try {
        $iisRegPath = "HKLM:\SOFTWARE\Microsoft\InetStp"
        if (Test-Path $iisRegPath) {
            $iisPathValue = (Get-ItemProperty -Path $iisRegPath -Name "PathWWWRoot" -ErrorAction SilentlyContinue).PathWWWRoot
            if ($iisPathValue -and (Test-Path $iisPathValue)) {
                if ($possibleWwwrootPaths -notcontains $iisPathValue) {
                    $possibleWwwrootPaths += $iisPathValue
                    Write-LogMessage "Added registry PathWWWRoot to search paths: $iisPathValue"
                }
            }
            
            # Check for other registry values
            $majorVersion = (Get-ItemProperty -Path $iisRegPath -Name "MajorVersion" -ErrorAction SilentlyContinue).MajorVersion
            if ($majorVersion) {
                Write-LogMessage "Detected IIS version: $majorVersion"
            }
        }
        
        # Check WOW64 registry path (32-bit on 64-bit systems)
        $iisRegPath32 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\InetStp"
        if (Test-Path $iisRegPath32) {
            $iisPathValue32 = (Get-ItemProperty -Path $iisRegPath32 -Name "PathWWWRoot" -ErrorAction SilentlyContinue).PathWWWRoot
            if ($iisPathValue32 -and (Test-Path $iisPathValue32)) {
                if ($possibleWwwrootPaths -notcontains $iisPathValue32) {
                    $possibleWwwrootPaths += $iisPathValue32
                    Write-LogMessage "Added registry PathWWWRoot (32-bit) to search paths: $iisPathValue32"
                }
            }
        }
    }
    catch {
        # Ignore registry errors
    }
    
    # Check IIS services to find installation paths
    try {
        $iisServices = Get-Service -ErrorAction SilentlyContinue | Where-Object { 
            $_.Name -like "*W3SVC*" -or $_.Name -like "*IIS*" -or $_.DisplayName -like "*IIS*" -or $_.DisplayName -like "*World Wide Web*"
        }
        foreach ($iisService in $iisServices) {
            try {
                $servicePath = (Get-WmiObject Win32_Service -Filter "Name='$($iisService.Name)'" -ErrorAction SilentlyContinue).PathName
                if ($servicePath) {
                    # Extract path from service executable path
                    # Service path format: C:\Windows\System32\inetsrv\w3wp.exe or similar
                    $serviceDir = Split-Path $servicePath -Parent
                    $systemRoot = $env:SystemRoot
                    if ($serviceDir -like "*\inetsrv*") {
                        # Found inetsrv, go up to Windows, then check for inetpub
                        $windowsDir = Split-Path $serviceDir -Parent
                        if ($windowsDir -and (Test-Path $windowsDir)) {
                            $parentDir = Split-Path $windowsDir -Parent
                            $serviceWwwroot = Join-Path $parentDir "inetpub\wwwroot"
                            if (Test-Path $serviceWwwroot) {
                                if ($possibleWwwrootPaths -notcontains $serviceWwwroot) {
                                    $possibleWwwrootPaths += $serviceWwwroot
                                    Write-LogMessage "Added service-based path to search paths: $serviceWwwroot (from service: $($iisService.Name))"
                                }
                            }
                        }
                    }
                }
            }
            catch {
                # Ignore errors for individual services
            }
        }
    }
    catch {
        # Ignore errors if service query fails
    }
    
    # Now check all possible wwwroot paths for web.config files
    foreach ($wwwrootPath in $possibleWwwrootPaths) {
        if (Test-Path $wwwrootPath) {
            # Check root web.config
            $rootWebConfig = Join-Path $wwwrootPath "web.config"
            if (Test-Path $rootWebConfig) {
                if ($webConfigFiles -notcontains $rootWebConfig) {
                    $webConfigFiles += $rootWebConfig
                    Write-LogMessage "Found: $rootWebConfig (wwwroot: $wwwrootPath)"
                }
            }
            
            # Check application-specific web.config files in subdirectories
            $appDirs = Get-ChildItem -Path $wwwrootPath -Directory -ErrorAction SilentlyContinue
            foreach ($appDir in $appDirs) {
                $appWebConfig = Join-Path $appDir.FullName "web.config"
                if (Test-Path $appWebConfig) {
                    if ($webConfigFiles -notcontains $appWebConfig) {
                        $webConfigFiles += $appWebConfig
                        Write-LogMessage "Found: $appWebConfig (application in $wwwrootPath)"
                    }
                }
                
                # Also check nested subdirectories (up to 2 levels deep for performance)
                $nestedDirs = Get-ChildItem -Path $appDir.FullName -Directory -ErrorAction SilentlyContinue
                foreach ($nestedDir in $nestedDirs) {
                    $nestedWebConfig = Join-Path $nestedDir.FullName "web.config"
                    if (Test-Path $nestedWebConfig) {
                        if ($webConfigFiles -notcontains $nestedWebConfig) {
                            $webConfigFiles += $nestedWebConfig
                            Write-LogMessage "Found: $nestedWebConfig (nested application)"
                        }
                    }
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
                            Write-LogMessage "Found: $siteWebConfig (IIS site: $($site.Name))"
                        }
                    }
                }
            }
            
            # Also check application pools and their paths
            try {
                $appPools = Get-WebAppPoolState -ErrorAction SilentlyContinue
                foreach ($pool in $appPools) {
                    try {
                        $poolPath = (Get-ItemProperty "IIS:\AppPools\$($pool.Name)" -ErrorAction SilentlyContinue).applicationPool
                        if ($poolPath -and (Test-Path $poolPath)) {
                            $poolWebConfig = Join-Path $poolPath "web.config"
                            if (Test-Path $poolWebConfig) {
                                if ($webConfigFiles -notcontains $poolWebConfig) {
                                    $webConfigFiles += $poolWebConfig
                                    Write-LogMessage "Found: $poolWebConfig (IIS app pool: $($pool.Name))"
                                }
                            }
                        }
                    }
                    catch {
                        # Ignore errors for individual app pools
                    }
                }
            }
            catch {
                # Ignore errors if app pool query fails
            }
        }
        catch {
            Write-LogMessage "WARNING: Could not query IIS sites: $_"
        }
    }
    
    Write-LogMessage "Found $($webConfigFiles.Count) web.config file(s) to process"
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
    }
    catch {
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
        Write-LogError "Invalid path: contains '..' (path traversal attempt)"
        return $false
    }
    
    # Check for null bytes
    if ($FilePath -match '\0') {
        Write-LogError "Invalid path: contains null byte"
        return $false
    }
    
    return $true
}

# Function: Load and parse IIS web.config file
# Parameters: config_path
# Returns: Parsed XML object
function Import-HstsConfig {
    param(
        [string]$ConfigPath
    )
    
    # Validate path first
    if (-not (Test-ValidFilePath -FilePath $ConfigPath)) {
        throw "Invalid path"
    }
    
    if (-not (Test-Path -Path $ConfigPath)) {
        Write-LogError "Configuration file not found: $ConfigPath"
        throw "File not found"
    }
    
    # Check if it's a symlink/junction (warn but allow)
    $item = Get-Item -Path $ConfigPath -ErrorAction SilentlyContinue
    if ($null -ne $item -and $item.LinkType) {
        Write-LogMessage "WARNING: Configuration path is a $($item.LinkType): $ConfigPath"
    }
    
    # Check if file is empty
    $fileInfo = Get-Item -Path $ConfigPath -ErrorAction Stop
    if ($fileInfo.Length -eq 0) {
        Write-LogError "Configuration file is empty: $ConfigPath"
        throw "Empty file"
    }
    
    try {
        $configContent = Get-Content -Path $ConfigPath -Raw -ErrorAction Stop
        
        # Validate XML before parsing
        if (-not (Test-ValidXml -XmlFilePath $ConfigPath)) {
            Write-LogError "Configuration file contains invalid XML: $ConfigPath"
            throw "Invalid XML"
        }
        
        [xml]$xmlConfig = $configContent
        return $xmlConfig
    }
    catch {
        if ($_.Exception.Message -match "Parse error|Invalid XML|Empty file") {
            Write-LogError "Failed to parse configuration file as XML: $_"
            throw $_.Exception.Message
        }
        else {
            Write-LogError "Failed to load configuration file: $_"
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
    
    # Extract max-age value
    $maxAge = $null
    if ($HeaderValue -match "max-age=([0-9]+)") {
        $maxAge = [int64]$Matches[1]
    }
    
    if ($null -eq $maxAge) {
        return $false  # Missing max-age
    }
    
    # Check for max-age
    if ($maxAge -lt $MinMaxAge) {
        return $false  # max-age too short
    }
    
    # Check for includeSubDomains if required
    if ($RequireSubDomains -and $HeaderValue -notmatch "includeSubDomains") {
        return $false
    }

    # Check for preload if required
    if ($RequirePreload -and $HeaderValue -notmatch "preload") {
        return $false
    }
    
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
                }
                else {
                    $allAdds = @($customHeaders.add)
                }
                
                $hstsHeaders = $allAdds | Where-Object { 
                    $null -ne $_ -and $null -ne $_.name -and $_.name -eq "Strict-Transport-Security" 
                }
                
                if ($null -ne $hstsHeaders) {
                    # Handle both single object and array
                    $hList = if ($hstsHeaders -is [System.Array]) { $hstsHeaders } else { @($hstsHeaders) }
                    foreach ($header in $hList) {
                        if ($null -ne $header) {
                            $hName = if ($header.Attributes['name']) { $header.Attributes['name'].Value } else { $header.name }
                            $hValue = if ($header.Attributes['value']) { $header.Attributes['value'].Value } else { $header.value }
                            $headers += [PSCustomObject]@{
                                name   = $hName
                                value  = $hValue
                                source = "CustomHeader"
                            }
                        }
                    }
                }
            }
            catch {
                Write-LogError "Error processing custom headers: $_"
            }
        }
        
        # Detect native IIS 10+ HSTS (introduced in Windows Server 2019 / IIS 10 version 1709)
        $hstsTag = $ParsedConfig.configuration.'system.webServer'.hsts
        if ($null -ne $hstsTag -and $hstsTag.enabled -eq "true") {
            $val = "max-age=$($hstsTag.'max-age')"
            if ($hstsTag.includeSubDomains -eq "true") { $val += "; includeSubDomains" }
            if ($hstsTag.preload -eq "true") { $val += "; preload" }
            
            $headers += [PSCustomObject]@{
                name   = "Strict-Transport-Security (IIS Native)"
                value  = $val
                source = "NativeHsts"
            }
        }
        
    }
    catch {
        Write-LogError "Error finding HSTS headers: $_"
    }
    
    return $headers
}

# Function: Audit HSTS header configuration
# Parameters: parsed_config
# Returns: Hashtable with audit results
function Test-HstsHeaders {
    param(
        [xml]$ParsedConfig
    )
    
    $isCorrect = $false
    $details = ""
    $headerCount = 0
    $compliantCount = 0
    $nonCompliantCount = 0
    $compliantHeaders = @()
    $weakHeaders = @()
    $nonCompliantHeaders = @()
    
    try {
        # Find all custom headers for context
        $customHeaders = @()
        try {
            # XPath for IIS customHeaders (handles both native and local-name)
            $headerNodes = $ParsedConfig.SelectNodes("//customHeaders/add")
            if (-not $headerNodes) { $headerNodes = $ParsedConfig.SelectNodes("//*[local-name()='customHeaders']/*[local-name()='add']") }
            
            if ($headerNodes) {
                foreach ($node in $headerNodes) {
                    $customHeaders += @{
                        name  = if ($node.Attributes['name']) { $node.Attributes['name'].Value } else { $node.name }
                        value = if ($node.Attributes['value']) { $node.Attributes['value'].Value } else { $node.value }
                    }
                }
            }
        }
        catch { }

        # Find all HSTS headers
        $allHeaders = Find-AllHstsHeaders -ParsedConfig $ParsedConfig
        $headerCount = $allHeaders.Count
        
        if ($headerCount -eq 0) {
            $details = "No HSTS header definitions found in configuration"
            Write-LogMessage "=== AUDIT: No HSTS Configuration Found ==="
            Write-LogMessage "No HSTS headers or native IIS HSTS settings detected."
            Write-LogMessage ""
            Write-LogMessage "Configuration Context:"
            
            if ($customHeaders.Count -gt 0) {
                Write-LogMessage "Custom headers found in configuration:"
                foreach ($h in ($customHeaders | Select-Object -First 10)) {
                    $hName = $h.name ?? "(unnamed)"
                    $hValue = $h.value ?? "(no value)"
                    Write-LogMessage "  - ${hName}: ${hValue}"
                }
            }
            else {
                Write-LogMessage "  No custom headers found in configuration"
            }
            
            # Check for httpProtocol section
            $httpProtocol = $ParsedConfig.SelectSingleNode("//httpProtocol")
            if (-not $httpProtocol) { $httpProtocol = $ParsedConfig.SelectSingleNode("//*[local-name()='httpProtocol']") }
            
            if ($httpProtocol) {
                Write-LogMessage "  <httpProtocol> section exists"
            }
            else {
                Write-LogMessage "  <httpProtocol> section is missing"
            }

            Write-LogMessage ""
            Write-LogMessage "Recommended Action:"
            Write-LogMessage "  Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains"
            Write-LogMessage ""
            Write-LogMessage "To fix, run the configure command:"
            Write-LogMessage "  .\UpdateIisHstsWin.ps1 -Mode configure -SecurityLevel $SecurityLevel"
            Write-LogMessage ""
            Write-LogMessage "Available security levels:"
            Write-LogMessage "  -SecurityLevel basic     (max-age only)"
            Write-LogMessage "  -SecurityLevel high      (max-age + includeSubDomains) [default]"
            Write-LogMessage "  -SecurityLevel veryhigh  (max-age + includeSubDomains + preload)"
            Write-LogMessage "  -SecurityLevel maximum   (2yr max-age + includeSubDomains + preload)"
            Write-LogMessage "=========================================="

            return @{
                IsCorrect           = $false
                Details             = $details
                HeaderCount         = 0
                CompliantCount      = 0
                NonCompliantCount   = 0
                CompliantHeaders    = @()
                NonCompliantHeaders = @()
            }
        }
        
        Write-LogMessage "Found $headerCount HSTS header definition(s)"
        Write-LogMessage "=== Audit Result Breakdown ==="
        
        # Check each header for compliance
        foreach ($header in $allHeaders) {
            $headerValue = $header.value
            $source = $header.source
            if (-not $source) { $source = "Unknown" }
            
            if ([string]::IsNullOrWhiteSpace($headerValue)) {
                $nonCompliantCount++
                $nonCompliantHeaders += "[FAIL] Source: ${source} (empty value)"
                Write-LogMessage "  [FAIL] Source: ${source} (empty value)"
                continue
            }
            
            $result = Test-CompliantHeader -HeaderValue $headerValue
            
            # Additional details for reporting
            $maxAge = if ($headerValue -match "max-age=([0-9]+)") { $Matches[1] } else { "not found" }
            $hasSub = $headerValue -match "includeSubDomains"
            $hasPreload = $headerValue -match "preload"

            if ($result) {
                $compliantCount++
                $compliantHeaders += "[PASS] Source: ${source} (Level: $SecurityLevel): max-age=$maxAge, includeSubDomains=$hasSub, preload=$hasPreload"
                Write-LogMessage "  [PASS] Source: ${source} (Level: $SecurityLevel): max-age=$maxAge, includeSubDomains=$hasSub, preload=$hasPreload"
            }
            else {
                $nonCompliantCount++
                $nonCompliantHeaders += "[FAIL] Source: ${source} (Target Level: $SecurityLevel): max-age=$maxAge, includeSubDomains=$hasSub, preload=$hasPreload"
                Write-LogMessage "  [FAIL] Source: ${source} (Target Level: $SecurityLevel): max-age=$maxAge, includeSubDomains=$hasSub, preload=$hasPreload"
                
                # Breakdown of why it's non-compliant
                if ($null -eq $maxAge -or $maxAge -eq "not found" -or [int64]$maxAge -lt $MinMaxAge) {
                    Write-LogMessage "    - max-age too short or missing (required: $MinMaxAge)"
                }
                if ($RequireSubDomains -and -not $hasSub) {
                    Write-LogMessage "    - Missing includeSubDomains directive (required for level: $SecurityLevel)"
                }
                if ($RequirePreload -and -not $hasPreload) {
                    Write-LogMessage "    - Missing preload directive (required for level: $SecurityLevel)"
                }
            }
        }
        Write-LogMessage "=== Audit Result Breakdown ==="
        foreach ($h in $compliantHeaders) { Write-LogMessage "  $h" }
        foreach ($h in $weakHeaders) { Write-LogMessage "  $h" }
        foreach ($h in $nonCompliantHeaders) { Write-LogMessage "  $h" }
        Write-LogMessage "=============================="
        
        # Determine overall status
        $headerCount = $compliantCount + $nonCompliantCount
        if ($headerCount -gt 1) {
            $details = "Multiple HSTS header definitions found ($headerCount total). Only one compliant configuration should exist."
            $isCorrect = $false
        }
        elseif ($compliantCount -eq 1 -and $nonCompliantCount -eq 0) {
            if ($weakHeaders.Count -gt 0) {
                $details = "HSTS is compliant but weak (missing includeSubDomains directive)."
                $isCorrect = $true
            }
            else {
                $details = "HSTS is correctly configured with exactly one compliant definition."
                $isCorrect = $true
            }
        }
        elseif ($headerCount -eq 0) {
            $details = "No HSTS header definitions found in configuration"
            $isCorrect = $false
        }
        else {
            $details = "Non-compliant HSTS configuration found: $nonCompliantCount failed issues."
            $isCorrect = $false
        }
        
    }
    catch {
        $details = "Error checking HSTS configuration: $_"
        $isCorrect = $false
    }
    
    return @{
        IsCorrect           = $isCorrect
        Details             = $details
        HeaderCount         = $headerCount
        CompliantCount      = $compliantCount
        NonCompliantCount   = $nonCompliantCount
        CompliantHeaders    = $compliantHeaders
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
                }
                else {
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
                    }
                    else {
                        $headersToRemove += $hstsHeaders
                    }
                    
                    # Now remove them
                    foreach ($header in $headersToRemove) {
                        try {
                            $null = $customHeaders.RemoveChild($header)
                        }
                        catch {
                            Write-LogError "Error removing header: $_"
                        }
                    }
                }
            }
            catch {
                Write-LogError "Error processing custom headers for removal: $_"
                throw
            }
        }
        
        # Also disable native IIS 10+ HSTS if present
        $hstsTag = $ParsedConfig.configuration.'system.webServer'.hsts
        if ($null -ne $hstsTag) {
            $hstsTag.SetAttribute("enabled", "false")
        }
    }
    catch {
        Write-LogError "Error removing HSTS headers: $_"
        throw
    }
}

# Function: Apply compliant HSTS configuration
# Parameters: parsed_config, config_path
# Returns: Hashtable with success status and message
function Invoke-HstsCompliantPatch {
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
        $systemWebServerNode = $ParsedConfig.configuration.SelectSingleNode("system.webServer")
        if ($null -eq $systemWebServerNode) {
            $systemWebServer = $ParsedConfig.CreateElement("system.webServer")
            $null = $ParsedConfig.configuration.AppendChild($systemWebServer)
        }
        else {
            $systemWebServer = $systemWebServerNode
        }
        
        # Ensure httpProtocol section exists (use SelectSingleNode to get XML element)
        $httpProtocolNode = $systemWebServer.SelectSingleNode("httpProtocol")
        if ($null -eq $httpProtocolNode) {
            $httpProtocol = $ParsedConfig.CreateElement("httpProtocol")
            $null = $systemWebServer.AppendChild($httpProtocol)
        }
        else {
            $httpProtocol = $httpProtocolNode
        }
        
        # Ensure customHeaders section exists (use SelectSingleNode to get XML element)
        $customHeadersNode = $httpProtocol.SelectSingleNode("customHeaders")
        if ($null -eq $customHeadersNode) {
            $customHeaders = $ParsedConfig.CreateElement("customHeaders")
            $null = $httpProtocol.AppendChild($customHeaders)
        }
        else {
            $customHeaders = $customHeadersNode
        }
        
        # Verify we don't already have a compliant header (shouldn't happen after Remove-AllHstsHeaders, but check anyway)
        $existingHeader = $null
        if ($null -ne $customHeaders.add) {
            try {
                $allAdds = @()
                if ($customHeaders.add -is [System.Array]) {
                    $allAdds = $customHeaders.add
                }
                else {
                    $allAdds = @($customHeaders.add)
                }
                $existingHeader = $allAdds | Where-Object { 
                    $null -ne $_ -and $null -ne $_.name -and $_.name -eq "Strict-Transport-Security" 
                } | Select-Object -First 1
            }
            catch {
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
        }
        else {
            # Update existing header if somehow it still exists
            $existingHeader.value = $RecommendedHsts
        }
        
        if ($DryRun) {
            Write-LogMessage "DRY RUN: Would apply compliant HSTS configuration"
            Write-LogMessage "Modified configuration would be:"
            # Use StringWriter for safer output in all contexts
            $stringWriter = New-Object System.IO.StringWriter
            $ParsedConfig.Save($stringWriter)
            Write-LogMessage $stringWriter.ToString()
            $stringWriter.Dispose()
            $success = $true
            $message = "DRY RUN: Would apply compliant HSTS configuration"
        }
        else {
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
            }
            catch {
                $message = "Failed to save configuration: $_"
                $success = $false
                # Clean up temp file if it exists
                if ($null -ne $tempXmlPath -and (Test-Path $tempXmlPath)) {
                    Remove-Item -Path $tempXmlPath -Force -ErrorAction SilentlyContinue
                }
            }
        }
        
    }
    catch {
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
function New-ConfigBackup {
    param(
        [string]$ConfigPath
    )
    
    if (-not (Test-Path -Path $ConfigPath)) {
        Write-LogError "Configuration file not found: $ConfigPath"
        throw "File not found"
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupPath = "$ConfigPath.backup.$timestamp"
    
    try {
        Copy-Item -Path $ConfigPath -Destination $backupPath -ErrorAction Stop
        Write-LogMessage "Backup created: $backupPath"
        return $backupPath
    }
    catch {
        Write-LogError "Failed to create backup: $_"
        throw "Backup failed"
    }
}

# Function: Log audit results
function Write-AuditResults {
    param(
        [bool]$IsCorrect,
        [string]$Details
    )
    
    if ($IsCorrect) {
        Write-LogMessage "SUCCESS: $Details"
        Write-LogMessage "HSTS configuration is compliant."
    }
    else {
        Write-LogMessage "FAILURE: $Details"
        Write-LogMessage "HSTS configuration needs to be updated."
    }
}

# Function: Prompt for confirmation
function Confirm-Configure {
    if ($DryRun) {
        return $true
    }
    
    if ($Force) {
        Write-LogMessage "Force mode enabled: Auto-approving configuration changes"
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
    }
    else {
        Write-LogMessage "Configuration operation cancelled by user"
        return $false
    }
}

# Function: Process a single web.config file
function Invoke-WebConfigPatch {
    param(
        [string]$WebConfigPath,
        [string]$Mode
    )
    
    Write-LogMessage ""
    Write-LogMessage "========================================="
    Write-LogMessage "Processing: $WebConfigPath"
    Write-LogMessage "========================================="
    
    try {
        $parsedConfig = Import-HstsConfig -ConfigPath $WebConfigPath
        
        if ($Mode -eq "audit") {
            $auditResult = Test-HstsHeaders -ParsedConfig $parsedConfig
            Write-AuditResults -IsCorrect $auditResult.IsCorrect -Details $auditResult.Details
            
            if ($auditResult.IsCorrect) {
                return 0
            }
            else {
                if ($auditResult.HeaderCount -gt 1) {
                    Write-LogMessage "ACTION REQUIRED: Remove duplicate HSTS definitions. Only one compliant configuration should exist."
                }
                return 1
            }
            
        }
        elseif ($Mode -eq "configure") {
            if ($DryRun) {
                Write-LogMessage "DRY RUN mode: No changes will be made"
            }
            
            $auditResult = Test-HstsHeaders -ParsedConfig $parsedConfig
            Write-LogMessage "Current state: $($auditResult.Details)"
            
            if ($auditResult.CompliantCount -eq 1 -and $auditResult.NonCompliantCount -eq 0 -and $auditResult.HeaderCount -eq 1) {
                Write-LogMessage "SUCCESS: HSTS is already correctly configured with exactly one compliant definition"
                return 0
            }
            
            Write-LogMessage "Configuration required: Ensuring exactly one compliant HSTS definition exists"
            
            if (-not $DryRun) {
                if (-not $Force) {
                    Write-Host ""
                    Write-Host "WARNING: This will modify: $WebConfigPath"
                    Write-Host "A backup will be created before making changes."
                    $response = Read-Host "Do you want to continue? (yes/no)"
                    if ($response -notmatch "^(yes|y)$") {
                        Write-LogMessage "Configuration operation cancelled by user"
                        return 2
                    }
                }
                else {
                    Write-LogMessage "Force mode enabled: Auto-approving configuration changes"
                }
            }
            
            if (-not $DryRun) {
                # SAFETY: Create backup before making any changes
                $backupPath = New-ConfigBackup -ConfigPath $WebConfigPath
                
                try {
                    # Apply compliant HSTS configuration
                    $configureResult = Invoke-HstsCompliantPatch -ParsedConfig $parsedConfig -ConfigPath $WebConfigPath
                    
                    if (-not $configureResult.Success) {
                        throw $configureResult.Message
                    }
                    
                    Write-LogMessage "SUCCESS: $($configureResult.Message)"
                    Write-LogMessage "Backup available at: $backupPath"
                }
                catch {
                    # AUTOMATIC ROLLBACK: Restore from backup on any failure
                    Write-LogError "Configuration failed: $_"
                    Write-LogMessage "ROLLBACK: Restoring original configuration from backup..."
                    
                    try {
                        Copy-Item -Path $backupPath -Destination $WebConfigPath -Force -ErrorAction Stop
                        Write-LogMessage "ROLLBACK: Successfully restored original configuration from $backupPath"
                    }
                    catch {
                        Write-LogError "CRITICAL: Rollback failed! Manual restoration required from: $backupPath"
                        Write-LogError "Rollback error: $_"
                    }
                    return 1
                }
            }
            else {
                # Dry run - apply to in-memory copy and show what would change
                $configureResult = Invoke-HstsCompliantPatch -ParsedConfig $parsedConfig -ConfigPath $WebConfigPath
                
                if (-not $configureResult.Success) {
                    Write-LogError "DRY RUN: Configuration would fail: $($configureResult.Message)"
                    return 1
                }
                
                Write-LogMessage "DRY RUN: $($configureResult.Message)"
            }

            
            return 0
        }
        
    }
    catch {
        Write-LogError "Error processing $WebConfigPath : $_"
        return 1
    }
}

# Main execution
try {
    # Auto-detect or use provided paths
    $webConfigFiles = Find-IisWebConfigFiles -CustomConfigPath $ConfigPath -CustomPathsArray $CustomPaths -CustomPathsFile $CustomPathsFile
    
    if ($webConfigFiles.Count -eq 0) {
        Write-LogError "No web.config files found to process"
        Write-LogError "  - Ensure IIS is installed on this Windows Server"
        Write-LogError "  - Or specify a custom path: -ConfigPath 'C:\path\to\web.config'"
        Write-LogError "  - Or specify multiple paths: -CustomPaths @('C:\path1\web.config', 'C:\path2')"
        Write-LogError "  - Or specify a paths file: -CustomPathsFile 'C:\paths.txt' (one path per line)"
        return 1
    }
    
    # Detect and log IIS version
    $iisVer = Get-IisVersion
    Write-LogMessage "Detected IIS Version: $iisVer"
    Write-LogMessage ""

    # Process each web.config file
    $overallSuccess = 0
    $processedCount = 0
    $successCount = 0
    $failureCount = 0
    $reportEntries = @()
    
    foreach ($webConfig in $webConfigFiles) {
        $result = Invoke-WebConfigPatch -WebConfigPath $webConfig -Mode $Mode
        $processedCount++
        
        $status = if ($result -eq 0) { "SUCCESS" } else { "FAILURE" }
        $reportEntries += [PSCustomObject]@{
            FileName   = $webConfig
            Status     = $status
            Hostname   = $Hostname
            IISVersion = $iisVer
            Time       = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }

        if ($result -eq 0) {
            $successCount++
        }
        else {
            $failureCount++
            if ($result -ne 2) {
                # Don't count user cancellation as failure
                $overallSuccess = 1
            }
        }
    }
    
    # Summary
    Write-LogMessage ""
    Write-LogMessage "========================================="
    Write-LogMessage "Summary"
    Write-LogMessage "========================================="
    Write-LogMessage "Total files processed: $processedCount"
    Write-LogMessage "Successful: $successCount"
    Write-LogMessage "Failed: $failureCount"
    
    if ($overallSuccess -eq 0) {
        Write-LogMessage "Overall Status: SUCCESS"
    }
    else {
        Write-LogMessage "Overall Status: FAILURE (some files failed)"
    }

    # Generate Report
    if ($ReportPath) {
        try {
            if ($OutputFormat -eq "json") {
                $reportEntries | ConvertTo-Json | Set-Content -Path $ReportPath -ErrorAction Stop
            }
            elseif ($OutputFormat -eq "csv") {
                $reportEntries | Export-Csv -Path $ReportPath -NoTypeInformation -ErrorAction Stop
            }
            else {
                $reportEntries | Out-File -FilePath $ReportPath -ErrorAction Stop
            }
            Write-LogMessage "Report saved to: $ReportPath"
        }
        catch {
            Write-LogError "Failed to save report to $ReportPath : $_"
        }
    }
    
    Write-LogMessage "Log file: $LogFile"
    
    # Return results object for remote scripts
    $finalResult = [PSCustomObject]@{
        Hostname       = $Hostname
        Success        = ($overallSuccess -eq 0)
        ProcessedCount = $processedCount
        SuccessCount   = $successCount
        FailureCount   = $failureCount
        LogFile        = $LogFile
        Details        = $reportEntries
    }
    Write-Output $finalResult
    
    return $overallSuccess
}
catch {
    Write-LogError "An unexpected error occurred: $_"
    return 2
}

