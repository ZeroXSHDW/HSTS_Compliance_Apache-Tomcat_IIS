# UpdateTomcatHstsWin.ps1
# Audit and Configure HSTS (HTTP Strict Transport Security) in Apache Tomcat
# For Windows Server environments only
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("audit", "configure")]
    [string]$Mode = "configure",
    
    [Parameter(Mandatory=$false)]
    [string]$TomcatConfPath = $null,
    
    [Parameter(Mandatory=$false)]
    [string[]]$CustomPaths = @(),
    
    [Parameter(Mandatory=$false)]
    [string]$CustomPathsFile = $null,
    
    [Parameter(Mandatory=$false)]
    [string]$LogFile = "$env:LOCALAPPDATA\Temp\TomcatHsts.log",
    
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
    $LogFile = "$env:LOCALAPPDATA\Temp\TomcatHsts.log"
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
Log-Message "Tomcat HSTS Configuration Tool"
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

# Auto-detect Tomcat configuration directory
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
            Log-Message "Found Tomcat configuration at custom path: $customPath"
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
        "E:\Tomcat\conf"
    )
    
    $tomcatRoot = "C:\Program Files\Apache Software Foundation\Tomcat"
    if (Test-Path $tomcatRoot) {
        $subDirs = Get-ChildItem -Path $tomcatRoot -Directory -ErrorAction SilentlyContinue
        foreach ($dir in $subDirs) {
            $confPath = Join-Path $dir.FullName "conf"
            if (Test-Path (Join-Path $confPath "server.xml")) {
                $possiblePaths += $confPath
            }
        }
    }
    
    # Check all possible paths and return all found
    $foundPaths = @()
    foreach ($path in $possiblePaths) {
        if (Test-Path $path) {
            $serverXml = Join-Path $path "server.xml"
            if (Test-Path $serverXml) {
                Log-Message "Found Tomcat configuration at: $path"
                $foundPaths += $path
            }
        }
    }
    
    return $foundPaths
}

# Find web.xml files
function Find-WebXmlFiles {
    param([string]$ConfPath)
    
    $webXmlFiles = @()
    $tomcatHome = Split-Path $ConfPath
    
    $globalWebXml = Join-Path $ConfPath "web.xml"
    if (Test-Path $globalWebXml) {
        $webXmlFiles += $globalWebXml
        Log-Message "Found: $globalWebXml (global configuration)"
    }
    
    $contextXml = Join-Path $ConfPath "context.xml"
    if (Test-Path $contextXml) {
        $webXmlFiles += $contextXml
        Log-Message "Found: $contextXml (context configuration)"
    }
    
    $webappsPath = Join-Path $tomcatHome "webapps"
    if (Test-Path $webappsPath) {
        $appWebXmls = Get-ChildItem -Path $webappsPath -Recurse -Filter "web.xml" -ErrorAction SilentlyContinue | 
            Where-Object { $_.FullName -like "*\WEB-INF\web.xml" }
        foreach ($webxml in $appWebXmls) {
            $webXmlFiles += $webxml.FullName
            Log-Message "Found: $($webxml.FullName) (application-specific)"
        }
    }
    
    Log-Message "Found $($webXmlFiles.Count) web.xml file(s) to process"
    return $webXmlFiles
}

# Function: Validate XML file
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

# Function: Load web.xml file
function Load-WebXml {
    param([string]$WebXmlPath)
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

# Function: Test if a single filter is compliant
function Test-FilterCompliant {
    param([System.Xml.XmlElement]$Filter)
    $hasMaxAge = $false
    $hasIncludeSubDomains = $false
    
    # Try to find init-param elements (with and without namespace)
    $initParams = $null
    $xpaths = @("init-param", ".//init-param", ".//*[local-name()='init-param']")
    
    foreach ($xpath in $xpaths) {
        try {
            $initParams = $Filter.SelectNodes($xpath)
            if ($initParams -and $initParams.Count -gt 0) {
                break
            }
        } catch {
            # Continue to next XPath
        }
    }
    
    if (-not $initParams) {
        return $false
    }
    
    foreach ($param in $initParams) {
        # Try to find param-name and param-value (with and without namespace)
        $name = $null
        $value = $null
        
        $nameXpaths = @("param-name", ".//param-name", ".//*[local-name()='param-name']")
        $valueXpaths = @("param-value", ".//param-value", ".//*[local-name()='param-value']")
        
        foreach ($xpath in $nameXpaths) {
            try {
                $name = $param.SelectSingleNode($xpath)
                if ($name) { break }
            } catch { }
        }
        
        foreach ($xpath in $valueXpaths) {
            try {
                $value = $param.SelectSingleNode($xpath)
                if ($value) { break }
            } catch { }
        }
        
        if ($name -and $value) {
            if ($name.InnerText -eq "hstsMaxAgeSeconds" -and $value.InnerText -eq "31536000") {
                $hasMaxAge = $true
            }
            if ($name.InnerText -eq "hstsIncludeSubDomains" -and $value.InnerText -eq "true") {
                $hasIncludeSubDomains = $true
            }
        }
    }
    return ($hasMaxAge -and $hasIncludeSubDomains)
}

# Function: Test if HSTS configuration is compliant (checks entire document)
function Test-CompliantHsts {
    param([xml]$WebXml)
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
        } catch {
            # Continue to next XPath
        }
    }
    
    if ($filters) {
        foreach ($filter in $filters) {
            if (Test-FilterCompliant -Filter $filter) {
                return $true
            }
        }
    }
    return $false
}

# Function: Audit HSTS headers
function Audit-HstsHeaders {
    param([xml]$WebXml)
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
        } catch {
            # Continue to next XPath
        }
    }
    
    if (-not $filters) {
        $filters = @()
    }
    $headerCount = $filters.Count
    if ($headerCount -eq 0) {
        $details = "No HSTS header definitions found in configuration"
        return @{
            IsCorrect = $false
            Details = $details
            HeaderCount = 0
            CompliantCount = 0
            NonCompliantCount = 0
        }
    }
    Log-Message "Found $headerCount HSTS filter definition(s)"
    foreach ($filter in $filters) {
        if (Test-FilterCompliant -Filter $filter) {
            $compliantCount++
        } else {
            $nonCompliantCount++
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
    } else {
        $details = "HSTS configuration issue detected"
        $isCorrect = $false
    }
    return @{
        IsCorrect = $isCorrect
        Details = $details
        HeaderCount = $headerCount
        CompliantCount = $compliantCount
        NonCompliantCount = $nonCompliantCount
    }
}

# Function: Remove all HSTS configurations
function Remove-AllHstsConfigs {
    param([xml]$WebXml)
    
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
        } catch {
            # Continue to next XPath
        }
    }
    
    if ($filters) {
        foreach ($filter in $filters) {
            if ($filter.ParentNode) {
                $filter.ParentNode.RemoveChild($filter) | Out-Null
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
        } catch {
            # Continue to next XPath
        }
    }
    
    if ($mappings) {
        foreach ($mapping in $mappings) {
            if ($mapping.ParentNode) {
                $mapping.ParentNode.RemoveChild($mapping) | Out-Null
            }
        }
    }
}

# Function: Apply compliant HSTS configuration
function Apply-CompliantHsts {
    param([xml]$WebXml)
    Remove-AllHstsConfigs -WebXml $WebXml
    
    # Try to find web-app or Context element, handling namespaces
    $webApp = $null
    $nsManager = $null
    
    # Check if namespace manager exists (from Load-WebXml)
    if ($WebXml.NamespaceManager) {
        $nsManager = $WebXml.NamespaceManager
    } else {
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
            } else {
                $webApp = $WebXml.SelectSingleNode($xpath)
            }
            if ($webApp) {
                break
            }
        } catch {
            # Continue to next XPath
        }
    }
    
    if (-not $webApp) {
        throw "Neither web-app nor Context element found in XML file. The file may use an unsupported XML namespace or structure."
    }
    $filter = $WebXml.CreateElement("filter")
    $filterName = $WebXml.CreateElement("filter-name")
    $filterName.InnerText = "HstsHeaderFilter"
    $filter.AppendChild($filterName) | Out-Null
    $filterClass = $WebXml.CreateElement("filter-class")
    $filterClass.InnerText = "org.apache.catalina.filters.HttpHeaderSecurityFilter"
    $filter.AppendChild($filterClass) | Out-Null
    $initParam1 = $WebXml.CreateElement("init-param")
    $paramName1 = $WebXml.CreateElement("param-name")
    $paramName1.InnerText = "hstsMaxAgeSeconds"
    $paramValue1 = $WebXml.CreateElement("param-value")
    $paramValue1.InnerText = "31536000"
    $initParam1.AppendChild($paramName1) | Out-Null
    $initParam1.AppendChild($paramValue1) | Out-Null
    $filter.AppendChild($initParam1) | Out-Null
    $initParam2 = $WebXml.CreateElement("init-param")
    $paramName2 = $WebXml.CreateElement("param-name")
    $paramName2.InnerText = "hstsIncludeSubDomains"
    $paramValue2 = $WebXml.CreateElement("param-value")
    $paramValue2.InnerText = "true"
    $initParam2.AppendChild($paramName2) | Out-Null
    $initParam2.AppendChild($paramValue2) | Out-Null
    $filter.AppendChild($initParam2) | Out-Null
    $filterMapping = $WebXml.CreateElement("filter-mapping")
    $mappingFilterName = $WebXml.CreateElement("filter-name")
    $mappingFilterName.InnerText = "HstsHeaderFilter"
    $filterMapping.AppendChild($mappingFilterName) | Out-Null
    $urlPattern = $WebXml.CreateElement("url-pattern")
    $urlPattern.InnerText = "/*"
    $filterMapping.AppendChild($urlPattern) | Out-Null
    $webApp.InsertBefore($filter, $webApp.LastChild) | Out-Null
    $webApp.InsertBefore($filterMapping, $webApp.LastChild) | Out-Null
}

# Function: Create backup
function Backup-Config {
    param([string]$ConfigPath)
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupPath = "$ConfigPath.backup.$timestamp"
    try {
        Copy-Item -Path $ConfigPath -Destination $backupPath -Force -ErrorAction Stop
        Log-Message "Backup created: $backupPath"
        return $backupPath
    } catch {
        Log-Error "Failed to create backup: $_"
        throw
    }
}

# Function: Process a single web.xml file
function Process-WebXml {
    param([string]$WebXmlPath, [string]$Mode)
    Log-Message ""
    Log-Message "========================================="
    Log-Message "Processing: $WebXmlPath"
    Log-Message "========================================="
    try {
        $webXml = Load-WebXml -WebXmlPath $WebXmlPath
        if ($Mode -eq "audit") {
            $auditResult = Audit-HstsHeaders -WebXml $webXml
            if ($auditResult.IsCorrect) {
                Log-Message "SUCCESS: $($auditResult.Details)"
                Log-Message "HSTS configuration is compliant."
                return 0
            } else {
                Log-Message "FAILURE: $($auditResult.Details)"
                Log-Message "HSTS configuration needs to be updated."
                if ($auditResult.HeaderCount -gt 1) {
                    Log-Message "ACTION REQUIRED: Remove duplicate HSTS definitions. Only one compliant configuration should exist."
                }
                return 1
            }
        } elseif ($Mode -eq "configure") {
            if ($DryRun) {
                Log-Message "DRY RUN mode: No changes will be made"
            }
            $auditResult = Audit-HstsHeaders -WebXml $webXml
            Log-Message "Current state: $($auditResult.Details)"
            if ($auditResult.CompliantCount -eq 1 -and $auditResult.NonCompliantCount -eq 0 -and $auditResult.HeaderCount -eq 1) {
                Log-Message "SUCCESS: HSTS is already correctly configured with exactly one compliant definition"
                return 0
            }
            Log-Message "Configuration required: Ensuring exactly one compliant HSTS definition exists"
            
            if (-not $DryRun) {
                if (-not $Force) {
                    Write-Host ""
                    Write-Host "WARNING: This will modify: $WebXmlPath"
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
            
            $backupPath = Backup-Config -ConfigPath $WebXmlPath
            Apply-CompliantHsts -WebXml $webXml
            if (-not $DryRun) {
                $tempXmlPath = [System.IO.Path]::GetTempFileName()
                $webXml.Save($tempXmlPath)
                if (-not (Test-ValidXml -XmlFilePath $tempXmlPath)) {
                    throw "Generated XML failed validation"
                }
                Copy-Item -Path $tempXmlPath -Destination $WebXmlPath -Force -ErrorAction Stop
                Remove-Item -Path $tempXmlPath -Force -ErrorAction SilentlyContinue
                Log-Message "SUCCESS: Compliant HSTS configuration applied successfully. All duplicate/non-compliant headers removed."
                Log-Message "Backup available at: $backupPath"
            } else {
                Log-Message "DRY RUN: Would apply compliant HSTS configuration"
            }
            return 0
        }
    } catch {
        Log-Error "Error processing $WebXmlPath : $_"
        return 1
    }
}

# Main execution
try {
    # Auto-detect or use provided paths
    $confPaths = Get-TomcatConfigPaths -CustomPath $TomcatConfPath -CustomPathsArray $CustomPaths -CustomPathsFile $CustomPathsFile
    if ($confPaths.Count -eq 0) {
        Log-Error "Could not locate Tomcat configuration directory."
        Log-Error "  - Ensure Tomcat is installed on this Windows Server"
        Log-Error "  - Or specify a custom path: -TomcatConfPath 'C:\path\to\tomcat\conf'"
        Log-Error "  - Or specify multiple paths: -CustomPaths @('C:\path1\conf', 'C:\path2\conf')"
        Log-Error "  - Or specify a paths file: -CustomPathsFile 'C:\paths.txt' (one path per line)"
        exit 1
    }
    
    # Collect all web.xml files from all configuration directories
    $webXmlFiles = @()
    foreach ($confPath in $confPaths) {
        Log-Message "Tomcat Configuration Directory: $confPath"
        $files = Find-WebXmlFiles -ConfPath $confPath
        foreach ($file in $files) {
            if ($webXmlFiles -notcontains $file) {
                $webXmlFiles += $file
            }
        }
    }
    
    if ($webXmlFiles.Count -eq 0) {
        Log-Error "No web.xml files found to process"
        exit 1
    }
    
    # Process each web.xml file
    $overallSuccess = 0
    $processedCount = 0
    $successCount = 0
    $failureCount = 0
    
    foreach ($webXml in $webXmlFiles) {
        $result = Process-WebXml -WebXmlPath $webXml -Mode $Mode
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

