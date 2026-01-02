# Remote_UpdateIisHstsWin.ps1
# Remote Audit and Configure HSTS (HTTP Strict Transport Security) in IIS
# For Windows Server environments only
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string[]]$ServerName = @(),
    
    [Parameter(Mandatory = $false)]
    [string]$ServerListFile = $null,
    
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
    [switch]$DryRun = $false,
    
    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$Credential = $null,

    [Parameter(Mandatory = $false)]
    [string]$ConsolidatedReportPath = $null,

    [Parameter(Mandatory = $false)]
    [ValidateSet("json", "csv")]
    [string]$OutputFormat = "csv",

    [Parameter(Mandatory = $false)]
    [ValidateSet("basic", "high", "veryhigh", "maximum", "1", "2", "3", "4")]
    [string]$SecurityLevel = "high",

    [Parameter(Mandatory = $false)]
    [switch]$All = $false
)

$ErrorActionPreference = "Stop"

# Function: Load server names from file
function Get-ServersFromFile {
    param([string]$ServerFile)
    
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
    }
    catch {
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
Write-Host "Processing $($uniqueServers.Count) unique server(s)"

$allResults = @()
foreach ($server in $uniqueServers) {
    Write-Host "========================================="
    Write-Host "Processing server: $server"
    Write-Host "========================================="
    
    try {
        $invokeParams = @{
            ComputerName = $server
            ScriptBlock  = {
                param($Mode, $ConfigPath, $CustomPaths, $CustomPathsFile, $DryRun, $Force, $SecurityLevel)
            
                # Rename parameter for internal use to match function expectations
                $CustomPathsArray = $CustomPaths
            
                $ErrorActionPreference = "Stop"
                $Hostname = $env:COMPUTERNAME
                $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

                # Security Level Definitions
                $MinMaxAge = 31536000
                $RequireSubDomains = $true
                $RequirePreload = $false

                switch ($SecurityLevel.ToLower()) {
                    "1" {
                        $SecurityLevel = "basic"
                        $MinMaxAge = 31536000
                        $RequireSubDomains = $false
                        $RequirePreload = $false
                    }
                    "basic" {
                        $MinMaxAge = 31536000
                        $RequireSubDomains = $false
                        $RequirePreload = $false
                    }
                    "2" {
                        $SecurityLevel = "high"
                        $MinMaxAge = 31536000
                        $RequireSubDomains = $true
                        $RequirePreload = $false
                    }
                    "high" {
                        $MinMaxAge = 31536000
                        $RequireSubDomains = $true
                        $RequirePreload = $false
                    }
                    "3" {
                        $SecurityLevel = "veryhigh"
                        $MinMaxAge = 31536000
                        $RequireSubDomains = $true
                        $RequirePreload = $true
                    }
                    "veryhigh" {
                        $MinMaxAge = 31536000
                        $RequireSubDomains = $true
                        $RequirePreload = $true
                    }
                    "4" {
                        $SecurityLevel = "maximum"
                        $MinMaxAge = 63072000
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
                
                $LogFile = "$env:LOCALAPPDATA\Temp\IisHsts.log"
            
                function Write-LogMessage {
                    param([string]$Message)
                    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    $logEntry = "[$timestamp] $Message"
                    Write-Host $logEntry
                    try {
                        Add-Content -Path $LogFile -Value $logEntry -ErrorAction SilentlyContinue
                    }
                    catch { }
                }
            
                function Write-LogError {
                    param([string]$Message)
                    Write-LogMessage "ERROR: $Message"
                }
            
                try {
                    $null = New-Item -Path $LogFile -ItemType File -Force -ErrorAction Stop
                }
                catch {
                    Write-LogError "Cannot create log file: $LogFile"
                }
            
                Write-LogMessage "========================================="
                Write-LogMessage "IIS HSTS Configuration Tool (Remote)"
                Write-LogMessage "Hostname: $Hostname"
                Write-LogMessage "Execution Time: $Timestamp"
                Write-LogMessage "Mode: $Mode"
                if ($Force) {
                    Write-LogMessage "Force Mode: Enabled (auto-approve all changes)"
                }
                Write-LogMessage "========================================="
            
                # Auto-detect IIS web.config files
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
                        "C:\wwwroot",
                        "D:\wwwroot",
                        "E:\wwwroot",
                        "F:\wwwroot",
                        "C:\WebSites",
                        "D:\WebSites",
                        "E:\WebSites",
                        "C:\IIS\wwwroot",
                        "D:\IIS\wwwroot",
                        "E:\IIS\wwwroot"
                    )
                
                    # Check inetpub root and scan for wwwroot subdirectories
                    $inetpubRoots = @("C:\inetpub", "D:\inetpub", "E:\inetpub", "F:\inetpub")
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

                # Function: Validate XML file
                function Test-ValidXml {
                    param([string]$XmlFilePath)
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
                function Test-ValidFilePath {
                    param([string]$FilePath)
                
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
                function Import-HstsConfig {
                    param([string]$ConfigPath)
                
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
                function Test-CompliantHeader {
                    param([string]$HeaderValue)
                
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
                
                    # Check for max-age against target level
                    if ($maxAge -lt $MinMaxAge) {
                        return $false  # max-age too short for selected level
                    }
                
                    # Check for includeSubDomains if required for selected level
                    if ($RequireSubDomains) {
                        if ($HeaderValue -notmatch "includeSubDomains") {
                            return $false
                        }
                    }
                
                    # Check for preload if required for selected level
                    if ($RequirePreload) {
                        if ($HeaderValue -notmatch "preload") {
                            return $false
                        }
                    }
                
                    return $true
                }
            
                # Function: Find all HSTS header definitions
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
                    
                        # Find all Strict-Transport-Security headers (case-insensitive)
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
                function Test-HstsHeaders {
                    param([xml]$ParsedConfig)
                
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
                            $headerNodes = $ParsedConfig.SelectNodes("//customHeaders/add") -or $ParsedConfig.SelectNodes("//*[local-name()='customHeaders']/*[local-name()='add']")
                            if ($headerNodes) {
                                foreach ($node in $headerNodes) {
                                    $customHeaders += @{
                                        name  = $node.name
                                        value = $node.value
                                    }
                                }
                            }
                        }
                        catch { }

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
                            Write-LogMessage "=== Current HSTS Configuration ==="
                            Write-LogMessage "  Status: NOT CONFIGURED"
                            Write-LogMessage "  Header: (none)"
                            Write-LogMessage ""
                            Write-LogMessage "=== Available Security Levels ==="
                            Write-LogMessage ""
                            Write-LogMessage "  [1] BASIC - Minimum HSTS protection"
                            Write-LogMessage "      Header: Strict-Transport-Security: max-age=31536000"
                            Write-LogMessage "      Use when: Subdomains should NOT be affected"
                            Write-LogMessage ""
                            Write-LogMessage "  [2] HIGH - OWASP Recommended (Default)"
                            Write-LogMessage "      Header: Strict-Transport-Security: max-age=31536000; includeSubDomains"
                            Write-LogMessage "      Use when: All subdomains also use HTTPS"
                            Write-LogMessage ""
                            Write-LogMessage "  [3] VERY HIGH - Preload Ready"
                            Write-LogMessage "      Header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
                            Write-LogMessage "      Use when: Ready for browser preload list submission"
                            Write-LogMessage ""
                            Write-LogMessage "  [4] MAXIMUM - Highest Security"
                            Write-LogMessage "      Header: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload"
                            Write-LogMessage "      Use when: Maximum protection with 2-year cache"
                            Write-LogMessage ""
                            Write-LogMessage "=== Configure Commands (copy and run) ==="
                            Write-LogMessage ""
                            Write-LogMessage "  Option 1: .\Remote_UpdateIisHstsWin.ps1 -ServerName $env:COMPUTERNAME -Mode configure -SecurityLevel basic"
                            Write-LogMessage "  Option 2: .\Remote_UpdateIisHstsWin.ps1 -ServerName $env:COMPUTERNAME -Mode configure -SecurityLevel high"
                            Write-LogMessage "  Option 3: .\Remote_UpdateIisHstsWin.ps1 -ServerName $env:COMPUTERNAME -Mode configure -SecurityLevel veryhigh"
                            Write-LogMessage "  Option 4: .\Remote_UpdateIisHstsWin.ps1 -ServerName $env:COMPUTERNAME -Mode configure -SecurityLevel maximum"
                            Write-LogMessage ""
                            Write-LogMessage "  Add -DryRun to preview changes without applying"
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
                    
                        foreach ($header in $allHeaders) {
                            $headerValue = $header.value
                            $source = $header.source
                            
                            if ([string]::IsNullOrWhiteSpace($headerValue)) {
                                $nonCompliantCount++
                                $nonCompliantHeaders += "[FAIL] Source: $source (empty value)"
                                Write-LogMessage "  [FAIL] Source: $source (empty value)"
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
                                $nonCompliantHeaders += "[FAIL] Source: $source (Target Level: $SecurityLevel): max-age=$maxAge, includeSubDomains=$hasSub, preload=$hasPreload"
                                Write-LogMessage "  [FAIL] Source: $source (Target Level: $SecurityLevel): max-age=$maxAge, includeSubDomains=$hasSub, preload=$hasPreload"
                            }
                        }
                        Write-LogMessage "=== Audit Result Breakdown ==="
                        foreach ($h in $compliantHeaders) { Write-LogMessage "  $h" }
                        foreach ($h in $nonCompliantHeaders) { Write-LogMessage "  $h" }
                        Write-LogMessage "=============================="
                    
                        # Determine overall status
                        $headerCount = $compliantCount + $nonCompliantCount
                        if ($headerCount -gt 1) {
                            $details = "Multiple HSTS configuration definitions found ($headerCount total). Only one compliant configuration should exist."
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
                                }
                                else {
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
                                    }
                                    else {
                                        $headersToRemove += $hstsHeaders
                                    }
                                
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
                function Invoke-HstsCompliantPatch {
                    param([xml]$ParsedConfig, [string]$ConfigPath)
                
                    $success = $false
                    $message = ""
                
                    try {
                        Remove-AllHstsHeaders -ParsedConfig $ParsedConfig
                    
                        # Ensure system.webServer section exists (use SelectSingleNode for XML element)
                        $systemWebServerNode = $ParsedConfig.configuration.SelectSingleNode("system.webServer")
                        if ($null -eq $systemWebServerNode) {
                            $systemWebServer = $ParsedConfig.CreateElement("system.webServer")
                            $null = $ParsedConfig.configuration.AppendChild($systemWebServer)
                        }
                        else {
                            $systemWebServer = $systemWebServerNode
                        }
                    
                        # Ensure httpProtocol section exists (use SelectSingleNode for XML element)
                        $httpProtocolNode = $systemWebServer.SelectSingleNode("httpProtocol")
                        if ($null -eq $httpProtocolNode) {
                            $httpProtocol = $ParsedConfig.CreateElement("httpProtocol")
                            $null = $systemWebServer.AppendChild($httpProtocol)
                        }
                        else {
                            $httpProtocol = $httpProtocolNode
                        }
                    
                        # Ensure customHeaders section exists (use SelectSingleNode for XML element)
                        $customHeadersNode = $httpProtocol.SelectSingleNode("customHeaders")
                        if ($null -eq $customHeadersNode) {
                            $customHeaders = $ParsedConfig.CreateElement("customHeaders")
                            $null = $httpProtocol.AppendChild($customHeaders)
                        }
                        else {
                            $customHeaders = $customHeadersNode
                        }
                    
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
                            catch { }
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
                        }
                        else {
                            $existingHeader.value = $RecommendedHsts
                        }
                    
                        if ($DryRun) {
                            Write-LogMessage "DRY RUN: Would apply compliant HSTS configuration"
                            $success = $true
                            $message = "DRY RUN: Would apply compliant HSTS configuration"
                        }
                        else {
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
                            }
                            catch {
                                $message = "Failed to save configuration: $_"
                                $success = $false
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
            
                # Function: Create backup
                function New-ConfigBackup {
                    param([string]$ConfigPath)
                    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                    $backupPath = "$ConfigPath.backup.$timestamp"
                    try {
                        Copy-Item -Path $ConfigPath -Destination $backupPath -Force -ErrorAction Stop
                        Write-LogMessage "Backup created: $backupPath"
                        return $backupPath
                    }
                    catch {
                        Write-LogError "Failed to create backup: $_"
                        throw
                    }
                }
            
                # Function: Process a single web.config file
                function Invoke-WebConfigPatch {
                    param([string]$WebConfigPath, [string]$Mode)
                
                    Write-LogMessage ""
                    Write-LogMessage "========================================="
                    Write-LogMessage "Processing: $WebConfigPath"
                    Write-LogMessage "========================================="
                
                    try {
                        $parsedConfig = Import-HstsConfig -ConfigPath $WebConfigPath
                    
                        if ($Mode -eq "audit") {
                            $auditResult = Test-HstsHeaders -ParsedConfig $parsedConfig
                            if ($auditResult.IsCorrect) {
                                Write-LogMessage "SUCCESS: $($auditResult.Details)"
                                Write-LogMessage "HSTS configuration is compliant."
                                return 0
                            }
                            else {
                                Write-LogMessage "FAILURE: $($auditResult.Details)"
                                Write-LogMessage "HSTS configuration needs to be updated."
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
                                if ($Force) {
                                    Write-LogMessage "Force mode enabled: Auto-approving configuration changes"
                                }
                                # Note: Interactive prompts are skipped in remote execution
                                # Use -Force parameter to auto-approve changes
                            }
                        
                            $backupPath = New-ConfigBackup -ConfigPath $WebConfigPath
                            
                            try {
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
                        
                            return 0
                        }
                    
                    }
                    catch {
                        Write-LogError "Error processing $WebConfigPath : $_"
                        return 1
                    }
                }
            
                # Main execution
                # Detect and log IIS version
                $iisVer = Get-IisVersion
                Write-LogMessage "Detected IIS Version: $iisVer"
                Write-LogMessage ""

                $webConfigFiles = Find-IisWebConfigFiles -CustomConfigPath $ConfigPath -CustomPathsArray $CustomPathsArray -CustomPathsFile $CustomPathsFile
            
                if ($webConfigFiles.Count -eq 0) {
                    Write-LogError "No web.config files found to process"
                    Write-LogError "  - Ensure IIS is installed on this Windows Server"
                    Write-LogError "  - Or specify a custom path: -ConfigPath 'C:\path\to\web.config'"
                    Write-LogError "  - Or specify multiple paths: -CustomPaths @('C:\path1\web.config', 'C:\path2')"
                    Write-LogError "  - Or specify a paths file: -CustomPathsFile 'C:\paths.txt' (one path per line)"
                    return @{ Success = $false; Message = "No web.config files found" }
                }
            
                $overallSuccess = 0
                $processedCount = 0
                $successCount = 0
                $failureCount = 0
                $failedPaths = @()
            
                foreach ($webConfig in $webConfigFiles) {
                    $result = Invoke-WebConfigPatch -WebConfigPath $webConfig -Mode $Mode
                    $processedCount++
                
                    if ($result -eq 0) {
                        $successCount++
                    }
                    else {
                        $failureCount++
                        $overallSuccess = 1
                        $failedPaths += $webConfig
                    }
                }
            
                Write-LogMessage ""
                Write-LogMessage "========================================="
                Write-LogMessage "Summary"
                Write-LogMessage "========================================="
                Write-LogMessage "Total files processed: $processedCount"
                Write-LogMessage "Successful: $successCount"
                Write-LogMessage "Failed: $failureCount"

                if ($failedPaths.Count -gt 0 -and $Mode -eq "audit") {
                    Write-LogMessage ""
                    Write-LogMessage "========================================="
                    Write-LogMessage "CONFIGURATION COMMANDS FOR FAILED PATHS"
                    Write-LogMessage "========================================="
                    Write-LogMessage ""
                    Write-LogMessage "Copy and run the appropriate command for each installation:"
                    Write-LogMessage ""
                    
                    $pathNum = 1
                    foreach ($failedPath in $failedPaths) {
                        Write-LogMessage "--- Installation $pathNum`: $failedPath ---"
                        Write-LogMessage ""
                        Write-LogMessage "  [1] BASIC (max-age=31536000):"
                        Write-LogMessage "      .\Remote_UpdateIisHstsWin.ps1 -ServerName $env:COMPUTERNAME -Mode configure -SecurityLevel 1 -CustomPaths @('$failedPath')"
                        Write-LogMessage ""
                        Write-LogMessage "  [2] HIGH - OWASP Recommended (max-age=31536000; includeSubDomains):"
                        Write-LogMessage "      .\Remote_UpdateIisHstsWin.ps1 -ServerName $env:COMPUTERNAME -Mode configure -SecurityLevel 2 -CustomPaths @('$failedPath')"
                        Write-LogMessage ""
                        Write-LogMessage "  [3] VERY HIGH - Preload Ready (max-age=31536000; includeSubDomains; preload):"
                        Write-LogMessage "      .\Remote_UpdateIisHstsWin.ps1 -ServerName $env:COMPUTERNAME -Mode configure -SecurityLevel 3 -CustomPaths @('$failedPath')"
                        Write-LogMessage ""
                        Write-LogMessage "  [4] MAXIMUM - Highest Security (max-age=63072000; includeSubDomains; preload):"
                        Write-LogMessage "      .\Remote_UpdateIisHstsWin.ps1 -ServerName $env:COMPUTERNAME -Mode configure -SecurityLevel 4 -CustomPaths @('$failedPath')"
                        Write-LogMessage ""
                        $pathNum++
                    }
                    
                    Write-LogMessage ""
                    Write-LogMessage "========================================="
                    Write-LogMessage "CONFIGURE ALL FAILED PATHS (QUICK FIX)"
                    Write-LogMessage "========================================="
                    Write-LogMessage ""
                    Write-LogMessage "To configure ALL failed installations at once, run ONE of these commands:"
                    Write-LogMessage ""
                    Write-LogMessage "  [1] Apply BASIC to ALL:      .\Remote_UpdateIisHstsWin.ps1 -ServerName $env:COMPUTERNAME -Mode configure -SecurityLevel 1"
                    Write-LogMessage "  [2] Apply HIGH to ALL:       .\Remote_UpdateIisHstsWin.ps1 -ServerName $env:COMPUTERNAME -Mode configure -SecurityLevel 2"
                    Write-LogMessage "  [3] Apply VERY HIGH to ALL:  .\Remote_UpdateIisHstsWin.ps1 -ServerName $env:COMPUTERNAME -Mode configure -SecurityLevel 3"
                    Write-LogMessage "  [4] Apply MAXIMUM to ALL:    .\Remote_UpdateIisHstsWin.ps1 -ServerName $env:COMPUTERNAME -Mode configure -SecurityLevel 4"
                    Write-LogMessage ""
                    Write-LogMessage "TIP: Add -DryRun to preview changes without applying"
                    Write-LogMessage "========================================="

                    # Interactive mode removed per user request.
                }
            
                return @{
                    Success        = ($overallSuccess -eq 0)
                    ProcessedCount = $processedCount
                    SuccessCount   = $successCount
                    FailureCount   = $failureCount
                    LogFile        = $LogFile
                }
            }
            ArgumentList = @($Mode, $ConfigPath, $CustomPaths, $CustomPathsFile, $DryRun.IsPresent, $Force.IsPresent, $SecurityLevel)
        }
        
        if ($Credential) {
            $invokeParams.Credential = $Credential
        }
        
        $result = Invoke-Command @invokeParams
        
        if ($result) {
            $status = if ($result.Success) { "SUCCESS" } else { "FAILURE" }
            $allResults += [PSCustomObject]@{
                Server         = $server
                Success        = $result.Success
                ProcessedCount = $result.ProcessedCount
                SuccessCount   = $result.SuccessCount
                FailureCount   = $result.FailureCount
                LogFile        = $result.LogFile
                Timestamp      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
            Write-Host "Result from $server : $status"
        }
    }
    catch {
        Write-Host "ERROR: Failed to process server $server : $_" -ForegroundColor Red
        $allResults += [PSCustomObject]@{
            Server    = $server
            Success   = $false
            Error     = $_.ToString()
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
    }
}

# Save consolidated report
if ($ConsolidatedReportPath) {
    try {
        if ($OutputFormat -eq "json") {
            $allResults | ConvertTo-Json | Set-Content -Path $ConsolidatedReportPath -ErrorAction Stop
        }
        else {
            $allResults | Export-Csv -Path $ConsolidatedReportPath -NoTypeInformation -ErrorAction Stop
        }
        Write-Host "Consolidated report saved to: $ConsolidatedReportPath" -ForegroundColor Green
    }
    catch {
        Write-Host "ERROR: Failed to save consolidated report: $_" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "========================================="
Write-Host "Remote execution completed"
Write-Host "========================================="

