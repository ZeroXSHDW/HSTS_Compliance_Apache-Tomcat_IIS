# Remote_UpdateTomcatHstsWin.ps1
# Remote Audit and Configure HSTS (HTTP Strict Transport Security) in Apache Tomcat
# For Windows Server environments only
# Note: Requires admin rights on remote servers for configure mode

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
    [string]$TomcatConfPath = $null,
    
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
    [switch]$All = $false,

    [Parameter(Mandatory = $false)]
    [switch]$Force = $false,

    [Parameter(Mandatory = $false)]
    [switch]$Quiet = $false
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
                param($Mode, $TomcatConfPath, $CustomPaths, $CustomPathsFile, $DryRun, $Force, $SecurityLevel)
            
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
                
                # Global variables for compliance tracking (table output)
                $script:ComplianceTableRows = @()
                $script:CompliantCount = 0
                $script:NonCompliantCount = 0
                $script:NotConfiguredCount = 0
                
                $LogFile = "$env:LOCALAPPDATA\Temp\TomcatHsts.log"
            
                # Function: Log message
                function Write-LogMessage {
                    param(
                        [string]$Message,
                        [string]$Color = "White",
                        [switch]$NoNewline = $false
                    )
                    
                    if (-not $Quiet) {
                        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        $logEntry = "[$timestamp] $Message"
                        if ($NoNewline) {
                            Write-Host $Message -ForegroundColor $Color -NoNewline
                        }
                        else {
                            Write-Host $Message -ForegroundColor $Color
                        }
                        
                        if ($LogFile) {
                            try {
                                Add-Content -Path $LogFile -Value $logEntry -ErrorAction SilentlyContinue
                            }
                            catch {
                                # Silently fail if log file cannot be written
                            }
                        }
                    }
                }
            
                # Function: Log error message
                function Write-LogError {
                    param(
                        [string]$Message
                    )
                    
                    Write-LogMessage "ERROR: $Message" -Color Red
                }

                # Function: Write compliance status with color
                function Write-ComplianceStatus {
                    param(
                        [string]$FilePath,
                        [string]$Status,
                        [string]$Details = ""
                    )
                    
                    $fileName = Split-Path $FilePath -Leaf
                    
                    switch ($Status) {
                        "COMPLIANT" {
                            Write-Host "  " -NoNewline
                            Write-Host "[PASS]" -ForegroundColor Green -NoNewline
                            Write-Host " $fileName" -NoNewline
                            Write-Host " [COMPLIANT]" -ForegroundColor Green -NoNewline
                            if ($Details) { Write-Host " - $Details" -ForegroundColor Gray }
                            else { Write-Host "" }
                        }
                        "NOT_CONFIGURED" {
                            Write-Host "  " -NoNewline
                            Write-Host "[FAIL]" -ForegroundColor Red -NoNewline
                            Write-Host " $fileName" -NoNewline
                            Write-Host " [NOT CONFIGURED]" -ForegroundColor Red -NoNewline
                            if ($Details) { Write-Host " - $Details" -ForegroundColor Gray }
                            else { Write-Host "" }
                        }
                        "WEAK" {
                            Write-Host "  " -NoNewline
                            Write-Host "[WARN]" -ForegroundColor Yellow -NoNewline
                            Write-Host " $fileName" -NoNewline
                            Write-Host " [WEAK]" -ForegroundColor Yellow -NoNewline
                            if ($Details) { Write-Host " - $Details" -ForegroundColor Gray }
                            else { Write-Host "" }
                        }
                        "NON_COMPLIANT" {
                            Write-Host "  " -NoNewline
                            Write-Host "[FAIL]" -ForegroundColor Red -NoNewline
                            Write-Host " $fileName" -NoNewline
                            Write-Host " [NON-COMPLIANT]" -ForegroundColor Red -NoNewline
                            if ($Details) { Write-Host " - $Details" -ForegroundColor Gray }
                            else { Write-Host "" }
                        }
                        "SUCCESS" {
                            Write-Host "  " -NoNewline
                            Write-Host "[PASS]" -ForegroundColor Green -NoNewline
                            Write-Host " $fileName" -NoNewline
                            Write-Host " [CONFIGURED]" -ForegroundColor Green -NoNewline
                            if ($Details) { Write-Host " - $Details" -ForegroundColor Gray }
                            else { Write-Host "" }
                        }
                    }
                }
            
                # Initialize log file
                if ($LogFile -eq "") {
                    $LogFile = "$env:LOCALAPPDATA\Temp\TomcatHsts.log"
                }
                try {
                    $null = New-Item -Path $LogFile -ItemType File -Force -ErrorAction Stop
                }
                catch {
                    Write-Host "WARNING: Cannot create log file: $LogFile"
                }
            
                Write-LogMessage "========================================="
                Write-LogMessage "Tomcat HSTS Configuration Tool (Remote)"
                Write-LogMessage "Hostname: $Hostname"
                Write-LogMessage "Execution Time: $Timestamp"
                Write-LogMessage "Mode: $Mode"
                Write-LogMessage "========================================="
            
                # Function: Load custom paths from file
                function Get-CustomPathsFromFile {
                    param(
                        [string]$PathsFile
                    )
                
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
            
                # Auto-detect Tomcat configuration directories
                function Get-TomcatConfigPaths {
                    param(
                        [string]$CustomPath,
                        [string[]]$CustomPathsArray,
                        [string]$CustomPathsFile
                    )
                
                    $allCustomPaths = @()
                
                    # Add single custom path if provided
                    if ($CustomPath -and (Test-Path $CustomPath)) {
                        $allCustomPaths += $CustomPath
                    }
                
                    # Add custom paths from array
                    foreach ($path in $CustomPathsArray) {
                        if ($path -and (Test-Path $path)) {
                            $allCustomPaths += $path
                        }
                    }
                
                    # Add custom paths from file
                    if ($CustomPathsFile) {
                        $filePaths = Get-CustomPathsFromFile -PathsFile $CustomPathsFile
                        foreach ($path in $filePaths) {
                            if ($path -and (Test-Path $path)) {
                                $allCustomPaths += $path
                            }
                        }
                    }
                
                    # Deduplicate custom paths (in case same path specified multiple times)
                    $allCustomPaths = $allCustomPaths | Select-Object -Unique
                
                    # Check custom paths first - collect all valid custom paths
                    $validCustomPaths = @()
                    foreach ($customPath in $allCustomPaths) {
                        $serverXml = Join-Path $customPath "server.xml"
                        if (Test-Path $serverXml) {
                            $validCustomPaths += $customPath
                            Write-LogMessage "Found Tomcat configuration at custom path: $customPath"
                        }
                    }
                
                    # If any valid custom paths were found, return them (don't check auto-detection)
                    if ($validCustomPaths.Count -gt 0) {
                        return $validCustomPaths
                    }
                
                    $possiblePaths = @(
                        "C:\Program Files\Apache Software Foundation\Tomcat 7.0\conf",
                        "C:\Program Files\Apache Software Foundation\Tomcat 8.0\conf",
                        "C:\Program Files\Apache Software Foundation\Tomcat 8.5\conf",
                        "C:\Program Files\Apache Software Foundation\Tomcat 9.0\conf",
                        "C:\Program Files\Apache Software Foundation\Tomcat 10.0\conf",
                        "C:\Program Files\Apache Software Foundation\Tomcat 10.1\conf",
                        "C:\Program Files\Apache Software Foundation\Tomcat 11.0\conf",
                        "C:\Program Files (x86)\Apache Software Foundation\Tomcat 7.0\conf",
                        "C:\Program Files (x86)\Apache Software Foundation\Tomcat 8.0\conf",
                        "C:\Program Files (x86)\Apache Software Foundation\Tomcat 8.5\conf",
                        "C:\Program Files (x86)\Apache Software Foundation\Tomcat 9.0\conf",
                        "C:\Program Files (x86)\Apache Software Foundation\Tomcat 10.0\conf",
                        "C:\Program Files (x86)\Apache Software Foundation\Tomcat 10.1\conf",
                        "C:\Program Files (x86)\Apache Software Foundation\Tomcat 11.0\conf",
                        "C:\Tomcat\conf",
                        "C:\Tomcat7\conf",
                        "C:\Tomcat8\conf",
                        "C:\Tomcat9\conf",
                        "C:\Tomcat10\conf",
                        "C:\Tomcat11\conf",
                        "C:\Apache\Tomcat\conf",
                        "C:\Apache\Tomcat7\conf",
                        "C:\Apache\Tomcat8\conf",
                        "C:\Apache\Tomcat9\conf",
                        "C:\Apache\Tomcat10\conf",
                        "C:\Apache\Tomcat11\conf",
                        "D:\Program Files\Apache Software Foundation\Tomcat 7.0\conf",
                        "D:\Program Files\Apache Software Foundation\Tomcat 8.5\conf",
                        "D:\Program Files\Apache Software Foundation\Tomcat 9.0\conf",
                        "D:\Program Files\Apache Software Foundation\Tomcat 10.0\conf",
                        "D:\Program Files\Apache Software Foundation\Tomcat 10.1\conf",
                        "D:\Program Files\Apache Software Foundation\Tomcat 11.0\conf",
                        "D:\Tomcat\conf",
                        "E:\Program Files\Apache Software Foundation\Tomcat 7.0\conf",
                        "E:\Program Files\Apache Software Foundation\Tomcat 8.5\conf",
                        "E:\Program Files\Apache Software Foundation\Tomcat 9.0\conf",
                        "E:\Program Files\Apache Software Foundation\Tomcat 10.0\conf",
                        "E:\Program Files\Apache Software Foundation\Tomcat 10.1\conf",
                        "E:\Program Files\Apache Software Foundation\Tomcat 11.0\conf",
                        "E:\Tomcat\conf",
                        "F:\Program Files\Apache Software Foundation\Tomcat 7.0\conf",
                        "F:\Program Files\Apache Software Foundation\Tomcat 8.5\conf",
                        "F:\Program Files\Apache Software Foundation\Tomcat 9.0\conf",
                        "F:\Program Files\Apache Software Foundation\Tomcat 10.0\conf",
                        "F:\Program Files\Apache Software Foundation\Tomcat 10.1\conf",
                        "F:\Program Files\Apache Software Foundation\Tomcat 11.0\conf",
                        "F:\Tomcat\conf",
                        "G:\Program Files\Apache Software Foundation\Tomcat 7.0\conf",
                        "G:\Program Files\Apache Software Foundation\Tomcat 8.5\conf",
                        "G:\Program Files\Apache Software Foundation\Tomcat 9.0\conf",
                        "G:\Program Files\Apache Software Foundation\Tomcat 10.0\conf",
                        "G:\Program Files\Apache Software Foundation\Tomcat 10.1\conf",
                        "G:\Program Files\Apache Software Foundation\Tomcat 11.0\conf",
                        "G:\Tomcat\conf",
                        "H:\Program Files\Apache Software Foundation\Tomcat 7.0\conf",
                        "H:\Program Files\Apache Software Foundation\Tomcat 8.5\conf",
                        "H:\Program Files\Apache Software Foundation\Tomcat 9.0\conf",
                        "H:\Program Files\Apache Software Foundation\Tomcat 10.0\conf",
                        "H:\Program Files\Apache Software Foundation\Tomcat 10.1\conf",
                        "H:\Program Files\Apache Software Foundation\Tomcat 11.0\conf",
                        "H:\Tomcat\conf",
                        "I:\Program Files\Apache Software Foundation\Tomcat 7.0\conf",
                        "I:\Program Files\Apache Software Foundation\Tomcat 8.5\conf",
                        "I:\Program Files\Apache Software Foundation\Tomcat 9.0\conf",
                        "I:\Program Files\Apache Software Foundation\Tomcat 10.0\conf",
                        "I:\Program Files\Apache Software Foundation\Tomcat 10.1\conf",
                        "I:\Program Files\Apache Software Foundation\Tomcat 11.0\conf",
                        "I:\Tomcat\conf",
                        "J:\Program Files\Apache Software Foundation\Tomcat 7.0\conf",
                        "J:\Program Files\Apache Software Foundation\Tomcat 8.5\conf",
                        "J:\Program Files\Apache Software Foundation\Tomcat 9.0\conf",
                        "J:\Program Files\Apache Software Foundation\Tomcat 10.0\conf",
                        "J:\Program Files\Apache Software Foundation\Tomcat 10.1\conf",
                        "J:\Program Files\Apache Software Foundation\Tomcat 11.0\conf",
                        "J:\Tomcat\conf",
                        "K:\Program Files\Apache Software Foundation\Tomcat 7.0\conf",
                        "K:\Program Files\Apache Software Foundation\Tomcat 8.5\conf",
                        "K:\Program Files\Apache Software Foundation\Tomcat 9.0\conf",
                        "K:\Program Files\Apache Software Foundation\Tomcat 10.0\conf",
                        "K:\Program Files\Apache Software Foundation\Tomcat 10.1\conf",
                        "K:\Program Files\Apache Software Foundation\Tomcat 11.0\conf",
                        "K:\Tomcat\conf",
                        "C:\Apps\Tomcat\conf",
                        "C:\Apps\Tomcat7\conf",
                        "C:\Apps\Tomcat8\conf",
                        "C:\Apps\Tomcat9\conf",
                        "C:\Apps\Tomcat10\conf",
                        "C:\Apps\Tomcat11\conf",
                        "C:\Applications\Tomcat\conf",
                        "C:\Applications\Tomcat7\conf",
                        "C:\Applications\Tomcat8\conf",
                        "C:\Applications\Tomcat9\conf",
                        "C:\Applications\Tomcat10\conf",
                        "C:\Applications\Tomcat11\conf",
                        "C:\Software\Tomcat\conf",
                        "C:\Software\Apache\Tomcat\conf",
                        "D:\Apps\Tomcat\conf",
                        "D:\Applications\Tomcat\conf",
                        "E:\Apps\Tomcat\conf",
                        "E:\Applications\Tomcat\conf"
                    )
                
                    # Recursively search common Tomcat installation roots
                    $tomcatRoots = @(
                        "C:\Program Files\Apache Software Foundation",
                        "C:\Program Files (x86)\Apache Software Foundation",
                        "D:\Program Files\Apache Software Foundation",
                        "E:\Program Files\Apache Software Foundation",
                        "F:\Program Files\Apache Software Foundation",
                        "G:\Program Files\Apache Software Foundation",
                        "H:\Program Files\Apache Software Foundation",
                        "I:\Program Files\Apache Software Foundation",
                        "J:\Program Files\Apache Software Foundation",
                        "K:\Program Files\Apache Software Foundation"
                    )
                    
                    foreach ($root in $tomcatRoots) {
                        if (Test-Path $root) {
                            Write-LogMessage "Searching for Tomcat installations in: $root"
                            try {
                                $subDirs = Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*Tomcat*" }
                                foreach ($dir in $subDirs) {
                                    $confPath = Join-Path $dir.FullName "conf"
                                    if (Test-Path (Join-Path $confPath "server.xml")) {
                                        if ($possiblePaths -notcontains $confPath) {
                                            $possiblePaths += $confPath
                                            Write-LogMessage "Found Tomcat installation via recursive search: $confPath"
                                        }
                                    }
                                }
                            }
                            catch {
                                Write-LogMessage "Warning: Could not search directory $root - $_"
                            }
                        }
                    }
                
                    # Search alternative installation directories
                    $alternativeRoots = @(
                        "C:\Apps",
                        "C:\Applications",
                        "C:\Software",
                        "D:\Apps",
                        "D:\Applications",
                        "E:\Apps",
                        "E:\Applications"
                    )
                    
                    foreach ($altRoot in $alternativeRoots) {
                        if (Test-Path $altRoot) {
                            Write-LogMessage "Searching alternative installation root: $altRoot"
                            try {
                                $subDirs = Get-ChildItem -Path $altRoot -Directory -ErrorAction SilentlyContinue | 
                                Where-Object { $_.Name -like "*Tomcat*" -or $_.Name -like "*Apache*" }
                                foreach ($dir in $subDirs) {
                                    $confPath = Join-Path $dir.FullName "conf"
                                    if (Test-Path (Join-Path $confPath "server.xml")) {
                                        if ($possiblePaths -notcontains $confPath) {
                                            $possiblePaths += $confPath
                                            Write-LogMessage "Found Tomcat in alternative directory: $confPath"
                                        }
                                    }
                                }
                            }
                            catch {
                                Write-LogMessage "Warning: Could not search alternative directory $altRoot - $_"
                            }
                        }
                    }
                    
                    # Check mapped network drives for Tomcat installations
                    Write-LogMessage "Checking mapped network drives for Tomcat installations..."
                    try {
                        $networkDrives = Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue | 
                        Where-Object { $_.DisplayRoot -like "\\*" }
                        
                        foreach ($drive in $networkDrives) {
                            $driveLetter = $drive.Name
                            Write-LogMessage "Scanning network drive ${driveLetter}: ($($drive.DisplayRoot))"
                            
                            # Check common paths on network drive
                            $networkPaths = @(
                                "${driveLetter}:\Program Files\Apache Software Foundation\Tomcat",
                                "${driveLetter}:\Tomcat",
                                "${driveLetter}:\Apache\Tomcat",
                                "${driveLetter}:\Apps\Tomcat",
                                "${driveLetter}:\Applications\Tomcat"
                            )
                            
                            foreach ($netPath in $networkPaths) {
                                if (Test-Path $netPath) {
                                    $subDirs = Get-ChildItem -Path $netPath -Directory -ErrorAction SilentlyContinue | 
                                    Where-Object { $_.Name -like "*Tomcat*" -or $_.Name -match "^\d+\.\d+" }
                                    foreach ($dir in $subDirs) {
                                        $confPath = Join-Path $dir.FullName "conf"
                                        if (Test-Path (Join-Path $confPath "server.xml")) {
                                            if ($possiblePaths -notcontains $confPath) {
                                                $possiblePaths += $confPath
                                                Write-LogMessage "Found Tomcat on network drive: $confPath"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    catch {
                        Write-LogMessage "Warning: Could not query network drives"
                    }
                
                    # Check environment variables (CATALINA_HOME, CATALINA_BASE)
                    $catalinaHome = $env:CATALINA_HOME
                    if ($catalinaHome -and (Test-Path $catalinaHome)) {
                        $envConfPath = Join-Path $catalinaHome "conf"
                        if (Test-Path (Join-Path $envConfPath "server.xml")) {
                            if ($possiblePaths -notcontains $envConfPath) {
                                $possiblePaths += $envConfPath
                                Write-LogMessage "Found Tomcat via CATALINA_HOME: $envConfPath"
                            }
                        }
                    }
                
                    $catalinaBase = $env:CATALINA_BASE
                    if ($catalinaBase -and (Test-Path $catalinaBase)) {
                        $envConfPath = Join-Path $catalinaBase "conf"
                        if (Test-Path (Join-Path $envConfPath "server.xml")) {
                            if ($possiblePaths -notcontains $envConfPath) {
                                $possiblePaths += $envConfPath
                                Write-LogMessage "Found Tomcat via CATALINA_BASE: $envConfPath"
                            }
                        }
                    }
                
                    # Check Windows Registry for Tomcat installations
                    try {
                        $regPaths = @(
                            "HKLM:\SOFTWARE\Apache Software Foundation\Tomcat",
                            "HKLM:\SOFTWARE\WOW6432Node\Apache Software Foundation\Tomcat"
                        )
                        
                        foreach ($regPath in $regPaths) {
                            if (Test-Path $regPath) {
                                Write-LogMessage "Checking registry path: $regPath"
                                $tomcatVersions = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue
                                foreach ($version in $tomcatVersions) {
                                    try {
                                        $installPath = (Get-ItemProperty -Path $version.PSPath -Name "InstallPath" -ErrorAction SilentlyContinue).InstallPath
                                        if ($installPath -and (Test-Path $installPath)) {
                                            $regConfPath = Join-Path $installPath "conf"
                                            if (Test-Path (Join-Path $regConfPath "server.xml")) {
                                                if ($possiblePaths -notcontains $regConfPath) {
                                                    $possiblePaths += $regConfPath
                                                    Write-LogMessage "Found Tomcat via registry ($($version.PSChildName)): $regConfPath"
                                                }
                                            }
                                        }
                                    }
                                    catch {
                                        # Ignore errors for individual registry entries
                                    }
                                }
                            }
                        }
                    }
                    catch {
                        Write-LogMessage "Warning: Could not search Windows Registry for Tomcat installations"
                    }
                
                    # Check running Java processes for Tomcat via WMI
                    try {
                        Write-LogMessage "Checking running Java processes for Tomcat installations..."
                        $javaProcesses = Get-WmiObject Win32_Process -Filter "Name='java.exe' OR Name='javaw.exe'" -ErrorAction SilentlyContinue
                        foreach ($process in $javaProcesses) {
                            try {
                                $commandLine = $process.CommandLine
                                if ($commandLine) {
                                    # Look for -Dcatalina.home= or -Dcatalina.base= in command line
                                    if ($commandLine -match '-Dcatalina\.(home|base)=([^"\s]+)') {
                                        $catalinaPath = $Matches[2]
                                        # Remove quotes if present
                                        $catalinaPath = $catalinaPath.Trim('"').Trim("'")
                                        if (Test-Path $catalinaPath) {
                                            $wmiConfPath = Join-Path $catalinaPath "conf"
                                            if (Test-Path (Join-Path $wmiConfPath "server.xml")) {
                                                if ($possiblePaths -notcontains $wmiConfPath) {
                                                    $possiblePaths += $wmiConfPath
                                                    Write-LogMessage "Found Tomcat via running Java process (PID $($process.ProcessId)): $wmiConfPath"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            catch {
                                # Ignore errors for individual processes
                            }
                        }
                    }
                    catch {
                        Write-LogMessage "Warning: Could not query Java processes via WMI"
                    }
                
                    # Check Tomcat services to find installation paths
                    try {
                        $tomcatServices = Get-Service -ErrorAction SilentlyContinue | Where-Object { 
                            $_.Name -like "*Tomcat*" -or $_.DisplayName -like "*Tomcat*" 
                        }
                        foreach ($service in $tomcatServices) {
                            try {
                                $servicePath = (Get-WmiObject Win32_Service -Filter "Name='$($service.Name)'" -ErrorAction SilentlyContinue).PathName
                                if ($servicePath) {
                                    # Extract path from service executable path (usually bin\catalina.bat or bin\tomcat9.exe)
                                    $serviceDir = Split-Path $servicePath -Parent
                                    $tomcatHome = Split-Path $serviceDir -Parent
                                    $serviceConfPath = Join-Path $tomcatHome "conf"
                                    if (Test-Path (Join-Path $serviceConfPath "server.xml")) {
                                        if ($possiblePaths -notcontains $serviceConfPath) {
                                            $possiblePaths += $serviceConfPath
                                            Write-LogMessage "Found Tomcat via service '$($service.Name)': $serviceConfPath"
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
                
                    # Check all possible paths and return all found
                    $foundPaths = @()
                    foreach ($path in $possiblePaths) {
                        if (Test-Path $path) {
                            $serverXml = Join-Path $path "server.xml"
                            if (Test-Path $serverXml) {
                                Write-LogMessage "Found Tomcat configuration at: $path"
                                $foundPaths += $path
                            }
                        }
                    }
                
                    return $foundPaths
                }
            
                # Find web.xml files
                function Find-WebXmlFiles {
                    param(
                        [string]$ConfPath
                    )
                
                    $webXmlFiles = @()
                    $tomcatHome = Split-Path $ConfPath
                
                    $globalWebXml = Join-Path $ConfPath "web.xml"
                    if (Test-Path $globalWebXml) {
                        $webXmlFiles += $globalWebXml
                        Write-LogMessage "Found: $globalWebXml (global configuration)"
                    }
                
                    $contextXml = Join-Path $ConfPath "context.xml"
                    if (Test-Path $contextXml) {
                        $webXmlFiles += $contextXml
                        Write-LogMessage "Found: $contextXml (context configuration)"
                    }
                
                    $webappsPath = Join-Path $tomcatHome "webapps"
                    if (Test-Path $webappsPath) {
                        $appWebXmls = Get-ChildItem -Path $webappsPath -Recurse -Filter "web.xml" -ErrorAction SilentlyContinue | 
                        Where-Object { $_.FullName -like "*\WEB-INF\web.xml" }
                        foreach ($webxml in $appWebXmls) {
                            $webXmlFiles += $webxml.FullName
                            Write-LogMessage "Found: $($webxml.FullName) (application-specific)"
                        }
                    }
                
                    Write-LogMessage "Found $($webXmlFiles.Count) web.xml file(s) to process"
                    return $webXmlFiles
                }
            
                # Function: Detect Tomcat version from installation directory
                function Get-TomcatVersion {
                    param(
                        [string]$ConfPath
                    )
                
                    $version = "Unknown"
                    $tomcatHome = Split-Path $ConfPath
                
                    # Try Release-Notes
                    $releaseNotes = Join-Path $tomcatHome "RELEASE-NOTES"
                    if (Test-Path $releaseNotes) {
                        try {
                            $content = Get-Content $releaseNotes -TotalCount 20
                            if ($content -match "Apache Tomcat Version ([\d\.]+)") {
                                $version = $Matches[1]
                                return $version
                            }
                        }
                        catch {}
                    }
                
                    # Try version.bat
                    $versionBat = Join-Path $tomcatHome "bin\version.bat"
                    if (Test-Path $versionBat) {
                        try {
                            $output = & $versionBat | Out-String
                            if ($output -match "Server version: Apache Tomcat/([\d\.]+)") {
                                $version = $Matches[1]
                            }
                        }
                        catch {}
                    }
                
                    return $version
                }

                # Function: Check if Tomcat version supports HSTS HttpHeaderSecurityFilter natively
                function Test-HstsSupport {
                    param(
                        [string]$Version
                    )
                
                    if ($Version -eq "Unknown") { return $true }
                
                    try {
                        $v = [version]$Version
                        $major = $v.Major
                        $minor = $v.Minor
                        $build = $v.Build
                        $patch = $v.Revision
                        if ($patch -eq -1) { $patch = 0 }
                    
                        # Support added in:
                        # 9.0.0.M6, 8.5.1, 8.0.35, 7.0.69
                        if ($major -ge 10) { return $true }
                        if ($major -eq 9) { return $true }
                        if ($major -eq 8) {
                            if ($minor -ge 5) {
                                if ($build -ge 1) { return $true }
                            }
                            elseif ($minor -eq 0) {
                                if ($build -ge 35) { return $true }
                            }
                        }
                        if ($major -eq 7 -and $build -ge 69) { return $true }
                    }
                    catch {
                        return $true
                    }
                
                    return $false
                }

                # Test-ValidXml, Import-WebXml, Test-CompliantHsts, Test-HstsHeaders, Remove-AllHstsConfigs, Invoke-HstsCompliantPatch, New-ConfigBackup, Invoke-WebXmlPatch
                # (Same functions as UpdateTomcatHstsWin.ps1 - included inline for remote execution)
            
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
            
                function Import-WebXml {
                    param(
                        [string]$WebXmlPath
                    )
                    if (-not (Test-Path $WebXmlPath)) {
                        throw "File not found: $WebXmlPath"
                    }
                    if (-not (Test-ValidXml -XmlFilePath $WebXmlPath)) {
                        throw "Invalid XML: $WebXmlPath"
                    }
                    [xml]$xml = Get-Content -Path $WebXmlPath -Raw
                
                    # Create namespace manager for XPath queries (handles XML namespaces)
                    $nsManager = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
                    # Register common Tomcat namespaces
                    $nsManager.AddNamespace("ns", "http://xmlns.jcp.org/xml/ns/javaee")
                    $nsManager.AddNamespace("javaee", "http://xmlns.jcp.org/xml/ns/javaee")
                    $nsManager.AddNamespace("jakartaee", "https://jakarta.ee/xml/ns/jakartaee")
                
                    # Store namespace manager in XML document for later use
                    $xml | Add-Member -MemberType NoteProperty -Name "NamespaceManager" -Value $nsManager -Force
                
                    return $xml
                }
            
                function Test-FilterCompliant {
                    param(
                        [System.Xml.XmlElement]$Filter
                    )
                    $maxAge = $null
                    $includeSubDomains = $null
                    $preload = $null
                
                    # Robust finding of params using ChildNodes iteration (ignores namespace issues)
                    foreach ($node in $Filter.ChildNodes) {
                        if ($node.LocalName -eq "init-param") {
                            $name = $null
                            $value = $null
                            
                            foreach ($child in $node.ChildNodes) {
                                if ($child.LocalName -eq "param-name") { $name = $child }
                                if ($child.LocalName -eq "param-value") { $value = $child }
                            }
                            
                            if ($name -and $value) {
                                if ($name.InnerText -eq "hstsMaxAgeSeconds") { $maxAge = [int64]$value.InnerText }
                                if ($name.InnerText -eq "hstsIncludeSubDomains") { $includeSubDomains = $value.InnerText -eq "true" }
                                if ($name.InnerText -eq "hstsPreload") { $preload = $value.InnerText -eq "true" }
                            }
                        }
                    }
                    
                    $isCompliant = $true
                    $isWeak = $false
                    
                    if ($null -eq $maxAge -or $maxAge -lt $MinMaxAge) {
                        $isCompliant = $false
                    }
                    
                    if ($RequireSubDomains -and $includeSubDomains -ne $true) {
                        $isCompliant = $false
                        $isWeak = $true
                    }
                    
                    if ($RequirePreload -and $preload -ne $true) {
                        $isCompliant = $false
                    }
                    
                    return [PSCustomObject]@{
                        IsCompliant       = $isCompliant
                        IsWeak            = $isWeak
                        MaxAge            = $maxAge
                        IncludeSubDomains = $includeSubDomains
                        Preload           = $preload
                    }
                }
            
                function Test-CompliantHsts {
                    param(
                        [xml]$WebXml
                    )
                    # Try XPath with and without namespace handling
                    $filters = $null
                    $xpaths = @(
                        "//filter[filter-name[text()='HstsHeaderFilter' or text()='HttpHeaderSecurityFilter']]",
                        "//*[local-name()='filter'][*[local-name()='filter-name'][text()='HstsHeaderFilter' or text()='HttpHeaderSecurityFilter']]"
                    )
                
                    foreach ($xpath in $xpaths) {
                        try {
                            $filters = $WebXml.SelectNodes($xpath)
                            if ($filters -and $filters.Count -gt 0) {
                                break
                            }
                        }
                        catch { }
                    }
                
                    if ($filters) {
                        foreach ($filter in $filters) {
                            $result = Test-FilterCompliant -Filter $filter
                            if ($result.IsCompliant) {
                                return $true
                            }
                        }
                    }
                    return $false
                }
            
                function Test-HstsHeaders {
                    param(
                        [xml]$WebXml
                    )
                    $headerCount = 0
                    $compliantCount = 0
                    $nonCompliantCount = 0
                    $details = ""
                    $isCorrect = $false
                
                    # Try XPath with and without namespace handling
                    $filters = $null
                    $xpaths = @(
                        "//filter[filter-name[text()='HstsHeaderFilter' or text()='HttpHeaderSecurityFilter']]",
                        "//*[local-name()='filter'][*[local-name()='filter-name'][text()='HstsHeaderFilter' or text()='HttpHeaderSecurityFilter']]"
                    )
                
                    foreach ($xpath in $xpaths) {
                        try {
                            $filters = $WebXml.SelectNodes($xpath)
                            if ($filters -and $filters.Count -gt 0) {
                                break
                            }
                        }
                        catch { }
                    }
                
                    if (-not $filters) {
                        $filters = @()
                    }
                    $headerCount = $filters.Count
                    if ($headerCount -eq 0) {
                        $details = "No HSTS header definitions found in configuration"
                        Write-LogMessage "=== AUDIT: No HSTS Configuration Found ==="
                        Write-LogMessage "No HSTS filters detected in the configuration file."
                        Write-LogMessage ""
                        Write-LogMessage "Configuration Context:"
                        
                        # Show what filters ARE present
                        $allFilters = @()
                        $filterXpaths = @("//filter-name", "//*[local-name()='filter-name']")
                        foreach ($xpath in $filterXpaths) {
                            try {
                                $nodes = $WebXml.SelectNodes($xpath)
                                if ($nodes) {
                                    foreach ($node in $nodes) { $allFilters += $node.InnerText }
                                    break
                                }
                            }
                            catch { }
                        }
                        
                        if ($allFilters.Count -gt 0) {
                            Write-LogMessage "Other filters found in configuration:"
                            foreach ($f in ($allFilters | Select-Object -First 10)) {
                                Write-LogMessage "  - $f"
                            }
                        }
                        else {
                            Write-LogMessage "  No filters found in configuration"
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
                        Write-LogMessage "  Option 1: .\Remote_UpdateTomcatHstsWin.ps1 -ServerName $env:COMPUTERNAME -Mode configure -SecurityLevel basic"
                        Write-LogMessage "  Option 2: .\Remote_UpdateTomcatHstsWin.ps1 -ServerName $env:COMPUTERNAME -Mode configure -SecurityLevel high"
                        Write-LogMessage "  Option 3: .\Remote_UpdateTomcatHstsWin.ps1 -ServerName $env:COMPUTERNAME -Mode configure -SecurityLevel veryhigh"
                        Write-LogMessage "  Option 4: .\Remote_UpdateTomcatHstsWin.ps1 -ServerName $env:COMPUTERNAME -Mode configure -SecurityLevel maximum"
                        Write-LogMessage ""
                        Write-LogMessage "  Add -DryRun to preview changes without applying"
                        Write-LogMessage "=========================================="

                        return @{
                            IsCorrect         = $false
                            Details           = "No HSTS configuration found"
                            HeaderCount       = 0
                            CompliantCount    = 0
                            NonCompliantCount = 0
                        }
                    }
                
                    Write-LogMessage "Found $headerCount HSTS filter definition(s)"
                    Write-LogMessage "=== Audit Result Breakdown ==="
                    
                    $compliantHeaders = @()
                    $nonCompliantHeaders = @()
                    
                    foreach ($filter in $filters) {
                        $result = Test-FilterCompliant -Filter $filter
                        $filterName = "Unknown"
                        try {
                            $nameNode = $filter.SelectSingleNode("filter-name")
                            if (-not $nameNode) { $nameNode = $filter.SelectSingleNode(".//*[local-name()='filter-name']") }
                            if ($nameNode) { $filterName = $nameNode.InnerText.Trim() }
                        }
                        catch { }
                        
                        $maxAge = if ($null -ne $result.MaxAge) { $result.MaxAge } else { 'not found' }
                        $includeSub = if ($null -ne $result.IncludeSubDomains) { $result.IncludeSubDomains } else { 'not found' }
                        $preload = if ($null -ne $result.Preload) { $result.Preload } else { 'not found' }

                        if ($result.IsCompliant) {
                            $compliantCount++
                            $compliantHeaders += "[PASS] Filter: $filterName (Level: $SecurityLevel): max-age=$maxAge, includeSubDomains=$includeSub, preload=$preload"
                            Write-LogMessage "  [PASS] Filter: $filterName (Level: $SecurityLevel): max-age=$maxAge, includeSubDomains=$includeSub, preload=$preload"
                        }
                        else {
                            $nonCompliantCount++
                            $nonCompliantHeaders += "[FAIL] Filter: $filterName (Target Level: $SecurityLevel): max-age=$maxAge, includeSubDomains=$includeSub, preload=$preload"
                            Write-LogMessage "  [FAIL] Filter: $filterName (Target Level: $SecurityLevel): max-age=$maxAge, includeSubDomains=$includeSub, preload=$preload"
                        }
                    }
                    Write-LogMessage "=============================="
                    $isCorrect = $false
                    $details = "HSTS configuration status unknown"

                    if ($headerCount -gt 1) {
                        $details = "Multiple HSTS configuration definitions found ($headerCount total). Only one compliant configuration should exist."
                        $isCorrect = $false
                    }
                    elseif ($compliantCount -eq 1 -and $nonCompliantCount -eq 0) {
                        $details = "HSTS is correctly configured with exactly one compliant definition."
                        $isCorrect = $true
                    }
                    else {
                        $details = "Non-compliant HSTS configuration found: $nonCompliantCount failed issues."
                        $isCorrect = $false
                    }
                    return @{
                        IsCorrect         = $isCorrect
                        Details           = $details
                        HeaderCount       = $headerCount
                        CompliantCount    = $compliantCount
                        NonCompliantCount = $nonCompliantCount
                    }
                }
            
                function Remove-AllHstsConfigs {
                    param(
                        [xml]$WebXml
                    )
                
                    # SAFETY: Only remove HSTS-related filters and mappings
                    # This function is designed to ONLY target HSTS filters to prevent accidental removal of other filters
                
                    # Try XPath with and without namespace handling for filters
                    $filters = $null
                    $xpaths = @(
                        "//filter[filter-name[text()='HstsHeaderFilter' or text()='HttpHeaderSecurityFilter']]",
                        "//*[local-name()='filter'][*[local-name()='filter-name'][text()='HstsHeaderFilter' or text()='HttpHeaderSecurityFilter']]"
                    )
                
                    foreach ($xpath in $xpaths) {
                        try {
                            $filters = $WebXml.SelectNodes($xpath)
                            if ($filters -and $filters.Count -gt 0) {
                                break
                            }
                        }
                        catch {
                            # Continue to next XPath
                        }
                    }
                
                    # SAFETY: Verify each filter is actually an HSTS filter before removal
                    if ($filters) {
                        foreach ($filter in $filters) {
                            # Double-check: Verify filter-name matches HSTS filter names
                            $filterNameNode = $null
                            $nameXpaths = @("filter-name", ".//filter-name", ".//*[local-name()='filter-name']")
                            foreach ($nameXpath in $nameXpaths) {
                                try {
                                    $filterNameNode = $filter.SelectSingleNode($nameXpath)
                                    if ($filterNameNode) { break }
                                }
                                catch { }
                            }
                        
                            # Only remove if filter-name is confirmed to be HSTS-related
                            if ($filterNameNode -and ($filterNameNode.InnerText -eq "HstsHeaderFilter" -or $filterNameNode.InnerText -eq "HttpHeaderSecurityFilter")) {
                                if ($filter.ParentNode) {
                                    $filter.ParentNode.RemoveChild($filter) | Out-Null
                                    Write-LogMessage "Removed HSTS filter: $($filterNameNode.InnerText)"
                                }
                            }
                            else {
                                Write-LogMessage "SAFETY: Skipping filter removal - filter-name does not match HSTS filter names"
                            }
                        }
                    }
                
                    # Try XPath with and without namespace handling for filter-mappings
                    $mappings = $null
                    $mappingXpaths = @(
                        "//filter-mapping[filter-name[text()='HstsHeaderFilter' or text()='HttpHeaderSecurityFilter']]",
                        "//*[local-name()='filter-mapping'][*[local-name()='filter-name'][text()='HstsHeaderFilter' or text()='HttpHeaderSecurityFilter']]"
                    )
                
                    foreach ($xpath in $mappingXpaths) {
                        try {
                            $mappings = $WebXml.SelectNodes($xpath)
                            if ($mappings -and $mappings.Count -gt 0) {
                                break
                            }
                        }
                        catch {
                            # Continue to next XPath
                        }
                    }
                
                    # SAFETY: Verify each mapping is actually an HSTS mapping before removal
                    if ($mappings) {
                        foreach ($mapping in $mappings) {
                            # Double-check: Verify filter-name in mapping matches HSTS filter names
                            $mappingFilterNameNode = $null
                            $nameXpaths = @("filter-name", ".//filter-name", ".//*[local-name()='filter-name']")
                            foreach ($nameXpath in $nameXpaths) {
                                try {
                                    $mappingFilterNameNode = $mapping.SelectSingleNode($nameXpath)
                                    if ($mappingFilterNameNode) { break }
                                }
                                catch { }
                            }
                        
                            # Only remove if filter-name is confirmed to be HSTS-related
                            if ($mappingFilterNameNode -and ($mappingFilterNameNode.InnerText -eq "HstsHeaderFilter" -or $mappingFilterNameNode.InnerText -eq "HttpHeaderSecurityFilter")) {
                                if ($mapping.ParentNode) {
                                    $mapping.ParentNode.RemoveChild($mapping) | Out-Null
                                    Write-LogMessage "Removed HSTS filter-mapping: $($mappingFilterNameNode.InnerText)"
                                }
                            }
                            else {
                                Write-LogMessage "SAFETY: Skipping mapping removal - filter-name does not match HSTS filter names"
                            }
                        }
                    }
                }
            
                function Invoke-HstsCompliantPatch {
                    param(
                        [xml]$WebXml
                    )
                
                    # SAFETY: Remove only HSTS-related configurations first
                    Remove-AllHstsConfigs -WebXml $WebXml
                
                    # Try to find web-app or Context element, handling namespaces
                    $webApp = $null
                    $nsManager = $null
                
                    # Check if namespace manager exists (from Import-WebXml)
                    if ($WebXml.NamespaceManager) {
                        $nsManager = $WebXml.NamespaceManager
                    }
                    else {
                        # Create namespace manager if not present
                        $nsManager = New-Object System.Xml.XmlNamespaceManager($WebXml.NameTable)
                        $nsManager.AddNamespace("ns", "http://xmlns.jcp.org/xml/ns/javaee")
                        $nsManager.AddNamespace("javaee", "http://xmlns.jcp.org/xml/ns/javaee")
                        $nsManager.AddNamespace("jakartaee", "https://jakarta.ee/xml/ns/jakartaee")
                    }
                
                    # Try various XPath queries to find web-app element (with and without namespaces)
                    $xpaths = @(
                        "//web-app",
                        "//ns:web-app",
                        "//javaee:web-app",
                        "//jakartaee:web-app",
                        "//*[local-name()='web-app']",
                        "//Context",
                        "//*[local-name()='Context']"
                    )
                
                    foreach ($xpath in $xpaths) {
                        try {
                            if ($xpath -match "^(//ns:|//javaee:|//jakartaee:)") {
                                $webApp = $WebXml.SelectSingleNode($xpath, $nsManager)
                            }
                            else {
                                $webApp = $WebXml.SelectSingleNode($xpath)
                            }
                            if ($webApp) {
                                break
                            }
                        }
                        catch {
                            # Continue to next XPath
                        }
                    }
                
                    if (-not $webApp) {
                        throw "Neither web-app nor Context element found in XML file. The file may use an unsupported XML namespace or structure."
                    }
                    
                    # Capture the namespace of the root element to ensure new elements match
                    $rootNamespace = $webApp.NamespaceURI
                    if (-not $rootNamespace) { $rootNamespace = "" }
                
                    # SAFETY: Define exact required values - these are the ONLY values that will be set
                    $requiredFilterName = "HstsHeaderFilter"
                    $requiredFilterClass = "org.apache.catalina.filters.HttpHeaderSecurityFilter"
                    $requiredMaxAgeParam = "hstsMaxAgeSeconds"
                    $requiredMaxAgeValue = $MinMaxAge.ToString()
                    $requiredIncludeSubDomainsParam = "hstsIncludeSubDomains"
                    $requiredUrlPattern = "/*"
                
                    # Create filter element with SAFETY: Only set the exact required values
                    # Use the same namespace as the root element to prevent xmlns="" attributes and verification failures
                    $filter = $WebXml.CreateElement("filter", $rootNamespace)
                    
                    $filterName = $WebXml.CreateElement("filter-name", $rootNamespace)
                    $filterName.InnerText = $requiredFilterName
                    $filter.AppendChild($filterName) | Out-Null
                
                    $filterClass = $WebXml.CreateElement("filter-class", $rootNamespace)
                    $filterClass.InnerText = $requiredFilterClass
                    $filter.AppendChild($filterClass) | Out-Null
                
                    # max-age param
                    $maxAgeParam = $WebXml.CreateElement("init-param", $rootNamespace)
                    $pName = $WebXml.CreateElement("param-name", $rootNamespace)
                    $pName.InnerText = $requiredMaxAgeParam
                    $maxAgeParam.AppendChild($pName) | Out-Null
                    
                    $pValue = $WebXml.CreateElement("param-value", $rootNamespace)
                    $pValue.InnerText = $requiredMaxAgeValue
                    $maxAgeParam.AppendChild($pValue) | Out-Null
                    
                    $filter.AppendChild($maxAgeParam) | Out-Null
                    
                    # includeSubDomains param
                    if ($RequireSubDomains) {
                        $subDomainsParam = $WebXml.CreateElement("init-param", $rootNamespace)
                        $sdName = $WebXml.CreateElement("param-name", $rootNamespace)
                        $sdName.InnerText = $requiredIncludeSubDomainsParam
                        $subDomainsParam.AppendChild($sdName) | Out-Null
                        
                        $sdValue = $WebXml.CreateElement("param-value", $rootNamespace)
                        $sdValue.InnerText = "true"
                        $subDomainsParam.AppendChild($sdValue) | Out-Null
                        
                        $filter.AppendChild($subDomainsParam) | Out-Null
                    }
                    
                    # preload param
                    if ($RequirePreload) {
                        $preloadParam = $WebXml.CreateElement("init-param", $rootNamespace)
                        $plName = $WebXml.CreateElement("param-name", $rootNamespace)
                        $plName.InnerText = "hstsPreload"
                        $preloadParam.AppendChild($plName) | Out-Null
                        
                        $plValue = $WebXml.CreateElement("param-value", $rootNamespace)
                        $plValue.InnerText = "true"
                        $preloadParam.AppendChild($plValue) | Out-Null
                        
                        $filter.AppendChild($preloadParam) | Out-Null
                    }
                
                    # Create filter-mapping with SAFETY: Only set the exact required values
                    $filterMapping = $WebXml.CreateElement("filter-mapping", $rootNamespace)
                    
                    $mappingFilterName = $WebXml.CreateElement("filter-name", $rootNamespace)
                    $mappingFilterName.InnerText = $requiredFilterName
                    $filterMapping.AppendChild($mappingFilterName) | Out-Null
                
                    $urlPattern = $WebXml.CreateElement("url-pattern", $rootNamespace)
                    $urlPattern.InnerText = $requiredUrlPattern
                    $filterMapping.AppendChild($urlPattern) | Out-Null
                
                    # Insert elements into web-app
                    $webApp.InsertBefore($filter, $webApp.LastChild) | Out-Null
                    $webApp.InsertBefore($filterMapping, $webApp.LastChild) | Out-Null
                
                    Write-LogMessage "Applied compliant HSTS configuration ($SecurityLevel): max-age=$MinMaxAge, includeSubDomains=$RequireSubDomains, preload=$RequirePreload"
                }
            
                # SAFETY: Verification function to ensure only expected HSTS configuration exists
                function Test-HstsConfiguration {
                    param(
                        [xml]$WebXml
                    )
                
                    # Verify exactly one HSTS filter exists
                    $filters = $null
                    $xpaths = @(
                        "//filter[filter-name[text()='HstsHeaderFilter' or text()='HttpHeaderSecurityFilter']]",
                        "//*[local-name()='filter'][*[local-name()='filter-name'][text()='HstsHeaderFilter' or text()='HttpHeaderSecurityFilter']]"
                    )
                
                    foreach ($xpath in $xpaths) {
                        try {
                            $filters = $WebXml.SelectNodes($xpath)
                            if ($filters -and $filters.Count -gt 0) {
                                break
                            }
                        }
                        catch {
                            # Continue to next XPath
                        }
                    }
                
                    if (-not $filters -or $filters.Count -ne 1) {
                        throw "SAFETY CHECK FAILED: Expected exactly one HSTS filter, found $($filters.Count)"
                    }
                
                    $result = Test-FilterCompliant -Filter $filters[0]

                    if (-not $result.IsCompliant) {
                        throw "SAFETY CHECK FAILED: HSTS filter does not have compliant values (Target: $RecommendedHsts)"
                    }
                
                    # Verify exactly one filter-mapping exists
                    $mappings = $null
                    $mappingXpaths = @(
                        "//filter-mapping[filter-name[text()='HstsHeaderFilter' or text()='HttpHeaderSecurityFilter']]",
                        "//*[local-name()='filter-mapping'][*[local-name()='filter-name'][text()='HstsHeaderFilter' or text()='HttpHeaderSecurityFilter']]"
                    )
                
                    foreach ($xpath in $mappingXpaths) {
                        try {
                            $mappings = $WebXml.SelectNodes($xpath)
                            if ($mappings -and $mappings.Count -gt 0) {
                                break
                            }
                        }
                        catch {
                            # Continue to next XPath
                        }
                    }
                
                    if (-not $mappings -or $mappings.Count -ne 1) {
                        throw "SAFETY CHECK FAILED: Expected exactly one HSTS filter-mapping, found $($mappings.Count)"
                    }
                
                    Write-LogMessage "SAFETY VERIFICATION PASSED: HSTS configuration is correct and compliant"
                    return $true
                }
            
                function New-ConfigBackup {
                    param(
                        [string]$ConfigPath
                    )
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
            
                function Invoke-WebXmlPatch {
                    param(
                        [string]$WebXmlPath,
                        [string]$Mode,
                        [ref]$FileStatusRef
                    )
                    
                    # Only show verbose processing headers if not in Quiet mode
                    if (-not $Quiet) {
                        Write-LogMessage "" -Color Gray
                        Write-LogMessage "Processing: $WebXmlPath" -Color Gray
                    }
                    
                    try {
                        $webXml = Import-WebXml -WebXmlPath $WebXmlPath
                        if ($Mode -eq "audit") {
                            $auditResult = Test-HstsHeaders -WebXml $webXml
                            
                            # Determine status for concise output
                            $status = "NOT_CONFIGURED"
                            $details = ""
                            
                            if ($auditResult.IsCorrect) {
                                $status = "COMPLIANT"
                                $details = "Security Level: $SecurityLevel"
                                $FileStatusRef.Value = $status
                                
                                if (-not $Quiet) {
                                    Write-ComplianceStatus -FilePath $WebXmlPath -Status $status -Details $details
                                }
                                return 0
                            }
                            elseif ($auditResult.HeaderCount -eq 0) {
                                $status = "NOT_CONFIGURED"
                                $details = "No HSTS filters found"
                            }
                            elseif ($auditResult.NonCompliantCount -gt 0) {
                                if ($auditResult.HeaderCount -gt 1) {
                                    $status = "NON_COMPLIANT"
                                    $details = "Multiple HSTS filters found ($($auditResult.HeaderCount))"
                                }
                                else {
                                    $status = "NON_COMPLIANT"
                                    $details = "Weak or incorrect configuration"
                                    
                                    # Extract current HSTS values for non-compliant files
                                    $filters = $null
                                    $xpaths = @(
                                        "//filter[filter-name[text()='HstsHeaderFilter' or text()='HttpHeaderSecurityFilter']]",
                                        "//*[local-name()='filter'][*[local-name()='filter-name'][text()='HstsHeaderFilter' or text()='HttpHeaderSecurityFilter']]"
                                    )
                                    
                                    foreach ($xpath in $xpaths) {
                                        try {
                                            $filters = $webXml.SelectNodes($xpath)
                                            if ($filters -and $filters.Count -gt 0) {
                                                break
                                            }
                                        }
                                        catch { }
                                    }
                                    
                                    if ($filters -and $filters.Count -gt 0) {
                                        $filter = $filters[0]
                                        $result = Test-FilterCompliant -Filter $filter
                                        
                                        $maxAge = if ($null -ne $result.MaxAge) { $result.MaxAge } else { 'not set' }
                                        $includeSub = if ($null -ne $result.IncludeSubDomains) { $result.IncludeSubDomains } else { 'not set' }
                                        $preload = if ($null -ne $result.Preload) { $result.Preload } else { 'not set' }
                                        
                                        $details = "Current: max-age=$maxAge, includeSubDomains=$includeSub, preload=$preload"
                                    }
                                }
                            }
                            
                            $FileStatusRef.Value = $status
                            
                            if (-not $Quiet) {
                                Write-ComplianceStatus -FilePath $WebXmlPath -Status $status -Details $details
                                
                                # Show full path and detailed info for non-compliant files
                                if ($status -ne "COMPLIANT") {
                                    Write-Host "    Path: $WebXmlPath" -ForegroundColor DarkGray
                                    
                                    if ($status -eq "NON_COMPLIANT" -and $details -match "max-age") {
                                        Write-Host "    Target: max-age=$MinMaxAge" -ForegroundColor DarkGray -NoNewline
                                        if ($RequireSubDomains) { Write-Host ", includeSubDomains=True" -ForegroundColor DarkGray -NoNewline }
                                        if ($RequirePreload) { Write-Host ", preload=True" -ForegroundColor DarkGray -NoNewline }
                                        Write-Host ""
                                    }
                                }
                            }
                            
                            return 1
                        }
                        elseif ($Mode -eq "configure") {
                            if ($DryRun) {
                                Write-LogMessage "DRY RUN mode: No changes will be made"
                            }
                            $auditResult = Test-HstsHeaders -WebXml $webXml
                            Write-LogMessage "Current state: $($auditResult.Details)"
                            if ($auditResult.CompliantCount -eq 1 -and $auditResult.NonCompliantCount -eq 0 -and $auditResult.HeaderCount -eq 1) {
                                Write-LogMessage "SUCCESS: HSTS is already correctly configured"
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
                        
                            # SAFETY: Create backup before making any changes
                            $backupPath = New-ConfigBackup -ConfigPath $WebXmlPath
                        
                            # Apply compliant HSTS configuration (only modifies HSTS-related elements)
                            $null = Invoke-HstsCompliantPatch -WebXml $webXml
                        
                            if (-not $DryRun) {
                                # SAFETY: Save to temporary file first, then validate
                                $tempXmlPath = [System.IO.Path]::GetTempFileName()
                                $webXml.Save($tempXmlPath)
                            
                                # SAFETY: Validate XML structure before applying
                                if (-not (Test-ValidXml -XmlFilePath $tempXmlPath)) {
                                    throw "SAFETY CHECK FAILED: Generated XML failed validation. Original file preserved at: $backupPath"
                                }
                            
                                # SAFETY: Reload and verify the configuration is correct before applying
                                [xml]$tempXml = Get-Content -Path $tempXmlPath -Raw
                                $null = Test-HstsConfiguration -WebXml $tempXml
                            
                                # SAFETY: Only apply if all checks pass
                                Copy-Item -Path $tempXmlPath -Destination $WebXmlPath -Force -ErrorAction Stop
                                Remove-Item -Path $tempXmlPath -Force -ErrorAction SilentlyContinue
                            
                                # SAFETY: Final verification on the saved file
                                [xml]$finalXml = Get-Content -Path $WebXmlPath -Raw
                                $null = Test-HstsConfiguration -WebXml $finalXml
                            
                                Write-LogMessage "SUCCESS: Compliant HSTS configuration applied successfully with all safety checks passed"
                                Write-LogMessage "Backup available at: $backupPath"
                            }
                            else {
                                Write-LogMessage "DRY RUN: Would apply compliant HSTS configuration"
                                # In dry run, still verify the configuration would be correct
                                try {
                                    $null = Test-HstsConfiguration -WebXml $webXml
                                    Write-LogMessage "DRY RUN: Configuration verification passed"
                                }
                                catch {
                                    Write-LogMessage "DRY RUN: Configuration verification would fail: $_"
                                }
                            }
                            return 0
                        }
                    }
                    catch {
                        Write-LogError "Error processing $WebXmlPath : $_"
                        return 1
                    }
                }
            
                # Main execution
                $confPaths = Get-TomcatConfigPaths -CustomPath $TomcatConfPath -CustomPathsArray $CustomPathsArray -CustomPathsFile $CustomPathsFile
                if ($confPaths.Count -eq 0) {
                    Write-LogError "Could not locate Tomcat configuration directory."
                    Write-LogError "  - Ensure Tomcat is installed on this Windows Server"
                    Write-LogError "  - Or specify a custom path: -TomcatConfPath 'C:\path\to\tomcat\conf'"
                    Write-LogError "  - Or specify multiple paths: -CustomPaths @('C:\path1\conf', 'C:\path2\conf')"
                    Write-LogError "  - Or specify a paths file: -CustomPathsFile 'C:\paths.txt' (one path per line)"
                    return @{ Success = $false; Message = "Tomcat not found" }
                }
            
                # Collect all web.xml files from all configuration directories
                $webXmlFiles = @()
                foreach ($confPath in $confPaths) {
                    # Detect and log Tomcat version
                    $tomcatVer = Get-TomcatVersion -ConfPath $confPath
                    Write-LogMessage "Tomcat Configuration Directory: $confPath (Version: $tomcatVer)"
                
                    if (-not (Test-HstsSupport -Version $tomcatVer)) {
                        Write-LogMessage "WARNING: Detected Tomcat version $tomcatVer may not natively support HttpHeaderSecurityFilter."
                        Write-LogMessage "         Compatibility starts at: 7.0.69+, 8.0.35+, 8.5.1+, 9.0.0.M6+"
                    }
                
                    $files = Find-WebXmlFiles -ConfPath $confPath
                    foreach ($file in $files) {
                        if ($webXmlFiles -notcontains $file) {
                            $webXmlFiles += $file
                        }
                    }
                }
            
                if ($webXmlFiles.Count -eq 0) {
                    Write-LogError "No web.xml files found to process"
                    return @{ Success = $false; Message = "No web.xml files found" }
                }
            
                $overallSuccess = 0
                $processedCount = 0
                $successCount = 0
                $failureCount = 0
                $failedPaths = @()
                $compliantCount = 0
                $notConfiguredCount = 0
                $nonCompliantCount = 0
                
                # Show header for audit mode
                if ($Mode -eq "audit" -and -not $Quiet) {
                    Write-Host ""
                    Write-Host "Scanning files for HSTS compliance..." -ForegroundColor Cyan
                    Write-Host ""
                }
            
                foreach ($webXml in $webXmlFiles) {
                    $fileStatus = "UNKNOWN"
                    $result = Invoke-WebXmlPatch -WebXmlPath $webXml -Mode $Mode -FileStatusRef ([ref]$fileStatus)
                    $processedCount++
                    
                    # Track compliance status
                    switch ($fileStatus) {
                        "COMPLIANT" { $compliantCount++ }
                        "NOT_CONFIGURED" { $notConfiguredCount++ }
                        "NON_COMPLIANT" { $nonCompliantCount++ }
                    }
                    
                    if ($result -eq 0) {
                        $successCount++
                    }
                    else {
                        $failureCount++
                        $overallSuccess = 1
                        $failedPaths += $webXml
                    }
                }
            
                # Summary - Beautiful formatted output
                if (-not $Quiet) {
                    Write-Host ""
                    Write-Host "+------------------------------------------------------+" -ForegroundColor Cyan
                    Write-Host "|            HSTS COMPLIANCE SUMMARY                   |" -ForegroundColor Cyan
                    Write-Host "+------------------------------------------------------+" -ForegroundColor Cyan
                    
                    Write-Host "| Files Scanned:  " -ForegroundColor Cyan -NoNewline
                    Write-Host ("$processedCount".PadLeft(37)) -ForegroundColor White -NoNewline
                    Write-Host "|" -ForegroundColor Cyan
                    
                    if ($Mode -eq "audit") {
                        # Calculate percentages
                        $compliantPct = if ($processedCount -gt 0) { [math]::Round(($compliantCount / $processedCount) * 100) } else { 0 }
                        $notConfiguredPct = if ($processedCount -gt 0) { [math]::Round(($notConfiguredCount / $processedCount) * 100) } else { 0 }
                        $nonCompliantPct = if ($processedCount -gt 0) { [math]::Round(($nonCompliantCount / $processedCount) * 100) } else { 0 }
                        
                        Write-Host "| " -ForegroundColor Cyan -NoNewline
                        Write-Host "[PASS]" -ForegroundColor Green -NoNewline
                        Write-Host " Compliant:  " -ForegroundColor Cyan -NoNewline
                        Write-Host ("$compliantCount".PadLeft(8)) -ForegroundColor Green -NoNewline
                        Write-Host " ($compliantPct%)" -ForegroundColor Gray -NoNewline
                        Write-Host (" ".PadLeft(19 - ("($compliantPct%)").Length)) -NoNewline
                        Write-Host "|" -ForegroundColor Cyan
                        
                        Write-Host "| " -ForegroundColor Cyan -NoNewline
                        Write-Host "[FAIL]" -ForegroundColor Red -NoNewline
                        Write-Host " Not Configured:  " -ForegroundColor Cyan -NoNewline
                        Write-Host ("$notConfiguredCount".PadLeft(4)) -ForegroundColor Red -NoNewline
                        Write-Host " ($notConfiguredPct%)" -ForegroundColor Gray -NoNewline
                        Write-Host (" ".PadLeft(19 - ("($notConfiguredPct%)").Length)) -NoNewline
                        Write-Host "|" -ForegroundColor Cyan
                        
                        Write-Host "| " -ForegroundColor Cyan -NoNewline
                        Write-Host "[WARN]" -ForegroundColor Yellow -NoNewline
                        Write-Host " Non-Compliant:  " -ForegroundColor Cyan -NoNewline
                        Write-Host ("$nonCompliantCount".PadLeft(5)) -ForegroundColor Yellow -NoNewline
                        Write-Host " ($nonCompliantPct%)" -ForegroundColor Gray -NoNewline
                        Write-Host (" ".PadLeft(19 - ("($nonCompliantPct%)").Length)) -NoNewline
                        Write-Host "|" -ForegroundColor Cyan
                    }
                    else {
                        Write-Host "| " -ForegroundColor Cyan -NoNewline
                        Write-Host "[PASS]" -ForegroundColor Green -NoNewline
                        Write-Host " Successful:  "  -ForegroundColor Cyan -NoNewline
                        Write-Host ("$successCount".PadLeft(33)) -ForegroundColor Green -NoNewline
                        Write-Host "|" -ForegroundColor Cyan
                        
                        Write-Host "| " -ForegroundColor Cyan -NoNewline
                        Write-Host "[FAIL]" -ForegroundColor Red -NoNewline
                        Write-Host " Failed:  " -ForegroundColor Cyan -NoNewline
                        Write-Host ("$failureCount".PadLeft(37)) -ForegroundColor Red -NoNewline
                        Write-Host "|" -ForegroundColor Cyan
                    }
                    
                    Write-Host "+------------------------------------------------------+" -ForegroundColor Cyan
                    Write-Host ""
                }

                if ($failedPaths.Count -gt 0 -and $Mode -eq "audit" -and -not $Quiet) {
                    Write-Host ""
                    Write-Host "+------------------------------------------------------+" -ForegroundColor Yellow
                    Write-Host "|        QUICK FIX - Configure All Non-Compliant       |" -ForegroundColor Yellow
                    Write-Host "+------------------------------------------------------+" -ForegroundColor Yellow
                    Write-Host ""
                    Write-Host "Choose a security level and run ONE command:\" -ForegroundColor Cyan
                    Write-Host ""
                    Write-Host "  [1] BASIC (1 year):\" -ForegroundColor White
                    Write-Host "      .\\Remote_UpdateTomcatHstsWin.ps1 -ServerName $env:COMPUTERNAME -Mode configure -SecurityLevel 1\" -ForegroundColor Gray
                    Write-Host ""
                    Write-Host "  [2] HIGH - OWASP Recommended (1 year + subdomains):\" -ForegroundColor White
                    Write-Host "      .\\Remote_UpdateTomcatHstsWin.ps1 -ServerName $env:COMPUTERNAME -Mode configure -SecurityLevel 2\" -ForegroundColor Gray
                    Write-Host ""
                    Write-Host "  [3] VERY HIGH (1 year + subdomains + preload):\" -ForegroundColor White
                    Write-Host "      .\\Remote_UpdateTomcatHstsWin.ps1 -ServerName $env:COMPUTERNAME -Mode configure -SecurityLevel 3\" -ForegroundColor Gray
                    Write-Host ""
                    Write-Host "  [4] MAXIMUM (2 years + subdomains + preload):\" -ForegroundColor White
                    Write-Host "      .\\Remote_UpdateTomcatHstsWin.ps1 -ServerName $env:COMPUTERNAME -Mode configure -SecurityLevel 4\" -ForegroundColor Gray
                    Write-Host ""
                    Write-Host "TIP: Add -DryRun to preview changes without applying\" -ForegroundColor Cyan
                    Write-Host ""
                }
            
                # Return results
            
                return @{
                    Success        = ($overallSuccess -eq 0)
                    ProcessedCount = $processedCount
                    SuccessCount   = $successCount
                    FailureCount   = $failureCount
                    LogFile        = $LogFile
                }
            }
            ArgumentList = @($Mode, $TomcatConfPath, $CustomPaths, $CustomPathsFile, $DryRun.IsPresent, $Force.IsPresent, $SecurityLevel)
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

