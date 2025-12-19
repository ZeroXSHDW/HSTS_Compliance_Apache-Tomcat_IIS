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
    [switch]$DryRun = $false
)

$ErrorActionPreference = "Stop"
$RecommendedHsts = "max-age=31536000; includeSubDomains"
$LogFile = "$env:LOCALAPPDATA\Temp\TomcatHsts.log"
$Hostname = $env:COMPUTERNAME
$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Function: Log message
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

# Initialize log file
try {
    $null = New-Item -Path $LogFile -ItemType File -Force -ErrorAction Stop
} catch {
    Log-Error "Cannot create log file: $LogFile"
}

Log-Message "========================================="
Log-Message "Tomcat HSTS Configuration Tool"
Log-Message "Hostname: $Hostname"
Log-Message "Execution Time: $Timestamp"
Log-Message "Mode: $Mode"
Log-Message "========================================="

# Function: Auto-detect Tomcat configuration directory
function Get-TomcatConfigPath {
    param([string]$CustomPath)
    
    if ($CustomPath -and (Test-Path $CustomPath)) {
        $serverXml = Join-Path $CustomPath "server.xml"
        if (Test-Path $serverXml) {
            Log-Message "Found Tomcat configuration at custom path: $CustomPath"
            return $CustomPath
        }
    }
    
    $possiblePaths = @(
        "C:\Program Files\Apache Software Foundation\Tomcat 7.0\conf",
        "C:\Program Files\Apache Software Foundation\Tomcat 8.0\conf",
        "C:\Program Files\Apache Software Foundation\Tomcat 8.5\conf",
        "C:\Program Files\Apache Software Foundation\Tomcat 9.0\conf",
        "C:\Program Files\Apache Software Foundation\Tomcat 10.0\conf",
        "C:\Program Files\Apache Software Foundation\Tomcat 10.1\conf",
        "C:\Program Files (x86)\Apache Software Foundation\Tomcat 7.0\conf",
        "C:\Program Files (x86)\Apache Software Foundation\Tomcat 8.0\conf",
        "C:\Program Files (x86)\Apache Software Foundation\Tomcat 8.5\conf",
        "C:\Program Files (x86)\Apache Software Foundation\Tomcat 9.0\conf",
        "C:\Program Files (x86)\Apache Software Foundation\Tomcat 10.0\conf",
        "C:\Program Files (x86)\Apache Software Foundation\Tomcat 10.1\conf",
        "C:\Tomcat\conf",
        "C:\Tomcat7\conf",
        "C:\Tomcat8\conf",
        "C:\Tomcat9\conf",
        "C:\Tomcat10\conf",
        "C:\Apache\Tomcat\conf",
        "C:\Apache\Tomcat7\conf",
        "C:\Apache\Tomcat8\conf",
        "C:\Apache\Tomcat9\conf",
        "C:\Apache\Tomcat10\conf",
        "D:\Program Files\Apache Software Foundation\Tomcat 7.0\conf",
        "D:\Program Files\Apache Software Foundation\Tomcat 8.5\conf",
        "D:\Program Files\Apache Software Foundation\Tomcat 9.0\conf",
        "D:\Program Files\Apache Software Foundation\Tomcat 10.0\conf",
        "D:\Program Files\Apache Software Foundation\Tomcat 10.1\conf",
        "D:\Tomcat\conf",
        "E:\Program Files\Apache Software Foundation\Tomcat 7.0\conf",
        "E:\Program Files\Apache Software Foundation\Tomcat 8.5\conf",
        "E:\Program Files\Apache Software Foundation\Tomcat 9.0\conf",
        "E:\Program Files\Apache Software Foundation\Tomcat 10.0\conf",
        "E:\Program Files\Apache Software Foundation\Tomcat 10.1\conf",
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
    
    foreach ($path in $possiblePaths) {
        if (Test-Path $path) {
            $serverXml = Join-Path $path "server.xml"
            if (Test-Path $serverXml) {
                Log-Message "Found Tomcat configuration at: $path"
                return $path
            }
        }
    }
    
    return $null
}

# Function: Find web.xml files
function Find-WebXmlFiles {
    param([string]$ConfPath)
    
    $webXmlFiles = @()
    $tomcatHome = Split-Path $ConfPath
    
    # Check global web.xml
    $globalWebXml = Join-Path $ConfPath "web.xml"
    if (Test-Path $globalWebXml) {
        $webXmlFiles += $globalWebXml
        Log-Message "Found: $globalWebXml (global configuration)"
    }
    
    # Check context.xml
    $contextXml = Join-Path $ConfPath "context.xml"
    if (Test-Path $contextXml) {
        $webXmlFiles += $contextXml
        Log-Message "Found: $contextXml (context configuration)"
    }
    
    # Search webapps for application-specific web.xml
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

# Function: Validate XML
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

# Function: Load web.xml
function Load-WebXml {
    param([string]$WebXmlPath)
    
    if (-not (Test-Path $WebXmlPath)) {
        throw "File not found: $WebXmlPath"
    }
    
    if (-not (Test-ValidXml -XmlFilePath $WebXmlPath)) {
        throw "Invalid XML: $WebXmlPath"
    }
    
    [xml]$xml = Get-Content -Path $WebXmlPath -Raw
    return $xml
}

# Function: Check if HSTS is compliant
function Test-CompliantHsts {
    param([xml]$WebXml)
    
    $hasMaxAge = $false
    $hasIncludeSubDomains = $false
    $maxAgeValue = $null
    
    # Check for filter-based HSTS configuration
    $filters = $WebXml.SelectNodes("//filter[filter-name[text()='HstsHeaderFilter' or text()='HttpHeaderSecurityFilter']]")
    foreach ($filter in $filters) {
        $initParams = $filter.SelectNodes("init-param")
        foreach ($param in $initParams) {
            $name = $param.SelectSingleNode("param-name")
            $value = $param.SelectSingleNode("param-value")
            if ($name -and $value) {
                if ($name.InnerText -eq "hstsMaxAgeSeconds" -and $value.InnerText -eq "31536000") {
                    $hasMaxAge = $true
                    $maxAgeValue = $value.InnerText
                }
                if ($name.InnerText -eq "hstsIncludeSubDomains" -and $value.InnerText -eq "true") {
                    $hasIncludeSubDomains = $true
                }
            }
        }
    }
    
    return ($hasMaxAge -and $hasIncludeSubDomains)
}

# Function: Audit HSTS configuration
function Audit-HstsHeaders {
    param([xml]$WebXml)
    
    $headerCount = 0
    $compliantCount = 0
    $nonCompliantCount = 0
    $details = ""
    $isCorrect = $false
    
    # Check for filter-based HSTS
    $filters = $WebXml.SelectNodes("//filter[filter-name[text()='HstsHeaderFilter' or text()='HttpHeaderSecurityFilter']]")
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
        if (Test-CompliantHsts -WebXml $WebXml) {
            $compliantCount++
        } else {
            $nonCompliantCount++
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
    
    # Remove filter blocks
    $filters = $WebXml.SelectNodes("//filter[filter-name[text()='HstsHeaderFilter' or text()='HttpHeaderSecurityFilter']]")
    foreach ($filter in $filters) {
        $filter.ParentNode.RemoveChild($filter) | Out-Null
    }
    
    # Remove filter-mapping blocks
    $mappings = $WebXml.SelectNodes("//filter-mapping[filter-name[text()='HstsHeaderFilter' or text()='HttpHeaderSecurityFilter']]")
    foreach ($mapping in $mappings) {
        $mapping.ParentNode.RemoveChild($mapping) | Out-Null
    }
}

# Function: Apply compliant HSTS configuration
function Apply-CompliantHsts {
    param([xml]$WebXml)
    
    # Remove existing HSTS configs
    Remove-AllHstsConfigs -WebXml $WebXml
    
    # Find web-app element
    $webApp = $WebXml.SelectSingleNode("//web-app")
    if (-not $webApp) {
        throw "web-app element not found in web.xml"
    }
    
    # Create filter element
    $filter = $WebXml.CreateElement("filter")
    $filterName = $WebXml.CreateElement("filter-name")
    $filterName.InnerText = "HstsHeaderFilter"
    $filter.AppendChild($filterName) | Out-Null
    
    $filterClass = $WebXml.CreateElement("filter-class")
    $filterClass.InnerText = "org.apache.catalina.filters.HttpHeaderSecurityFilter"
    $filter.AppendChild($filterClass) | Out-Null
    
    # Add init-param for max-age
    $initParam1 = $WebXml.CreateElement("init-param")
    $paramName1 = $WebXml.CreateElement("param-name")
    $paramName1.InnerText = "hstsMaxAgeSeconds"
    $paramValue1 = $WebXml.CreateElement("param-value")
    $paramValue1.InnerText = "31536000"
    $initParam1.AppendChild($paramName1) | Out-Null
    $initParam1.AppendChild($paramValue1) | Out-Null
    $filter.AppendChild($initParam1) | Out-Null
    
    # Add init-param for includeSubDomains
    $initParam2 = $WebXml.CreateElement("init-param")
    $paramName2 = $WebXml.CreateElement("param-name")
    $paramName2.InnerText = "hstsIncludeSubDomains"
    $paramValue2 = $WebXml.CreateElement("param-value")
    $paramValue2.InnerText = "true"
    $initParam2.AppendChild($paramName2) | Out-Null
    $initParam2.AppendChild($paramValue2) | Out-Null
    $filter.AppendChild($initParam2) | Out-Null
    
    # Create filter-mapping
    $filterMapping = $WebXml.CreateElement("filter-mapping")
    $mappingFilterName = $WebXml.CreateElement("filter-name")
    $mappingFilterName.InnerText = "HstsHeaderFilter"
    $filterMapping.AppendChild($mappingFilterName) | Out-Null
    
    $urlPattern = $WebXml.CreateElement("url-pattern")
    $urlPattern.InnerText = "/*"
    $filterMapping.AppendChild($urlPattern) | Out-Null
    
    # Insert before closing web-app tag
    $webApp.InsertBefore($filter, $webApp.LastChild) | Out-Null
    $webApp.InsertBefore($filterMapping, $webApp.LastChild) | Out-Null
}

# Function: Backup configuration
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
    param(
        [string]$WebXmlPath,
        [string]$Mode
    )
    
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
                return 1
            }
            
        } elseif ($Mode -eq "configure") {
            if ($DryRun) {
                Log-Message "DRY RUN mode: No changes will be made"
            }
            
            # Audit current state
            $auditResult = Audit-HstsHeaders -WebXml $webXml
            Log-Message "Current state: $($auditResult.Details)"
            
            # Check if already compliant
            if ($auditResult.CompliantCount -eq 1 -and $auditResult.NonCompliantCount -eq 0 -and $auditResult.HeaderCount -eq 1) {
                Log-Message "SUCCESS: HSTS is already correctly configured"
                return 0
            }
            
            Log-Message "Configuration required: Ensuring exactly one compliant HSTS definition exists"
            
            # Confirm before configuring
            if (-not $DryRun) {
                Write-Host ""
                Write-Host "WARNING: This will modify: $WebXmlPath"
                Write-Host "A backup will be created before making changes."
                $response = Read-Host "Do you want to continue? (yes/no)"
                if ($response -notmatch "^(yes|y)$") {
                    Log-Message "Configuration operation cancelled by user"
                    return 2
                }
            }
            
            # Create backup
            $backupPath = Backup-Config -ConfigPath $WebXmlPath
            
            # Apply configuration
            Apply-CompliantHsts -WebXml $webXml
            
            if (-not $DryRun) {
                # Validate XML before saving
                $tempXmlPath = [System.IO.Path]::GetTempFileName()
                $webXml.Save($tempXmlPath)
                
                if (-not (Test-ValidXml -XmlFilePath $tempXmlPath)) {
                    throw "Generated XML failed validation"
                }
                
                Copy-Item -Path $tempXmlPath -Destination $WebXmlPath -Force -ErrorAction Stop
                Remove-Item -Path $tempXmlPath -Force -ErrorAction SilentlyContinue
                
                Log-Message "SUCCESS: Compliant HSTS configuration applied successfully"
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
    # Auto-detect Tomcat configuration directory
    $confPath = Get-TomcatConfigPath -CustomPath $TomcatConfPath
    
    if (-not $confPath) {
        Log-Error "Could not locate Tomcat configuration directory."
        Log-Error "  - Ensure Tomcat is installed on this Windows Server"
        Log-Error "  - Or specify a custom path: -TomcatConfPath 'C:\path\to\conf'"
        exit 2
    }
    
    Log-Message "Tomcat Configuration Directory: $confPath"
    
    # Find all web.xml files
    $webXmlFiles = Find-WebXmlFiles -ConfPath $confPath
    
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
            $overallSuccess = 1
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
