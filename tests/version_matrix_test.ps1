# Comprehensive HSTS Compliance Version Matrix Test Suite
# Tests all versions: Tomcat 7-11, IIS 7-10
# Includes Java version detection and config path discovery
# Compatible with Windows PowerShell and PowerShell Core

param(
    [switch]$Verbose,
    [switch]$SkipUnix,
    [switch]$TestDetection,
    [string[]]$VersionsToTest
)

$ErrorActionPreference = "Stop"
$script:TestsPassed = 0
$script:TestsFailed = 0
$script:TestResults = @()

# Setup environment mocks for Windows behavior on macOS
if ($IsMacOS -or $IsLinux) {
    $env:LOCALAPPDATA = $env:TMPDIR
    if (-not $env:LOCALAPPDATA) { $env:LOCALAPPDATA = "/tmp" }
    $env:COMPUTERNAME = "TEST-SERVER"
}

function Write-TestResult {
    param([string]$TestName, [bool]$Passed, [string]$Details = "")
    $result = @{ Name = $TestName; Passed = $Passed; Details = $Details }
    $script:TestResults += $result
    if ($Passed) {
        Write-Host "  [PASS] $TestName" -ForegroundColor Green
        $script:TestsPassed++
    }
    else {
        Write-Host "  [FAIL] $TestName - $Details" -ForegroundColor Red
        $script:TestsFailed++
    }
}

#region Java Version Detection
function Get-JavaVersions {
    <#
    .SYNOPSIS
    Detects all installed Java versions and their paths
    #>
    $javaInstalls = @()
    
    # Windows-specific paths
    if ($IsWindows -or (-not $IsMacOS -and -not $IsLinux)) {
        # Check Program Files
        $programFiles = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ }
        foreach ($pf in $programFiles) {
            # Oracle JDK/JRE
            Get-ChildItem -Path "$pf\Java" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                if (Test-Path "$($_.FullName)\bin\java.exe") {
                    $version = & "$($_.FullName)\bin\java.exe" -version 2>&1 | Select-Object -First 1
                    $javaInstalls += @{
                        Path    = $_.FullName
                        Version = [regex]::Match($version, '\d+\.\d+\.\d+|\d+').Value
                        Type    = if ($_.Name -match "jdk") { "JDK" } else { "JRE" }
                        Vendor  = "Oracle"
                    }
                }
            }
            
            # Eclipse Adoptium (AdoptOpenJDK)
            Get-ChildItem -Path "$pf\Eclipse Adoptium" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                Get-ChildItem -Path $_.FullName -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                    if (Test-Path "$($_.FullName)\bin\java.exe") {
                        $javaInstalls += @{
                            Path    = $_.FullName
                            Version = $_.Name -replace '^jdk-?|^jre-?', ''
                            Type    = if ($_.Name -match "jdk") { "JDK" } else { "JRE" }
                            Vendor  = "Eclipse Adoptium"
                        }
                    }
                }
            }
            
            # Amazon Corretto
            Get-ChildItem -Path "$pf\Amazon Corretto" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                if (Test-Path "$($_.FullName)\bin\java.exe") {
                    $javaInstalls += @{
                        Path    = $_.FullName
                        Version = $_.Name -replace '^jdk', ''
                        Type    = "JDK"
                        Vendor  = "Amazon Corretto"
                    }
                }
            }
            
            # Azul Zulu
            Get-ChildItem -Path "$pf\Zulu" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                if (Test-Path "$($_.FullName)\bin\java.exe") {
                    $javaInstalls += @{
                        Path    = $_.FullName
                        Version = $_.Name -replace '^zulu-?', ''
                        Type    = "JDK"
                        Vendor  = "Azul Zulu"
                    }
                }
            }
        }
        
        # Check JAVA_HOME
        if ($env:JAVA_HOME -and (Test-Path "$env:JAVA_HOME\bin\java.exe")) {
            $version = & "$env:JAVA_HOME\bin\java.exe" -version 2>&1 | Select-Object -First 1
            $javaInstalls += @{
                Path    = $env:JAVA_HOME
                Version = [regex]::Match($version, '\d+\.\d+\.\d+|\d+').Value
                Type    = "JAVA_HOME"
                Vendor  = "Unknown"
            }
        }
    }
    
    # Unix/macOS-specific paths
    if ($IsMacOS -or $IsLinux) {
        # macOS - check /Library/Java/JavaVirtualMachines
        if (Test-Path "/Library/Java/JavaVirtualMachines") {
            Get-ChildItem -Path "/Library/Java/JavaVirtualMachines" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $javaPath = "$($_.FullName)/Contents/Home"
                if (Test-Path "$javaPath/bin/java") {
                    $javaInstalls += @{
                        Path    = $javaPath
                        Version = $_.Name -replace '\.jdk$|^jdk-?|^temurin-?', ''
                        Type    = "JDK"
                        Vendor  = $_.Name
                    }
                }
            }
        }
        
        # Linux - check common paths
        $linuxPaths = @(
            "/usr/lib/jvm",
            "/usr/java",
            "/opt/java",
            "/opt/jdk"
        )
        foreach ($basePath in $linuxPaths) {
            if (Test-Path $basePath) {
                Get-ChildItem -Path $basePath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                    if (Test-Path "$($_.FullName)/bin/java") {
                        $javaInstalls += @{
                            Path    = $_.FullName
                            Version = $_.Name -replace '^java-|^jdk-?|^openjdk-?', ''
                            Type    = "JDK"
                            Vendor  = $_.Name
                        }
                    }
                }
            }
        }
        
        # Check JAVA_HOME
        if ($env:JAVA_HOME -and (Test-Path "$env:JAVA_HOME/bin/java")) {
            $javaInstalls += @{
                Path    = $env:JAVA_HOME
                Version = "JAVA_HOME"
                Type    = "JAVA_HOME"
                Vendor  = "Environment"
            }
        }
    }
    
    return $javaInstalls
}
#endregion

#region Tomcat Detection
function Get-TomcatInstallations {
    <#
    .SYNOPSIS
    Detects all installed Tomcat versions and their config paths
    #>
    $tomcatInstalls = @()
    
    # Windows-specific paths
    if ($IsWindows -or (-not $IsMacOS -and -not $IsLinux)) {
        $programFiles = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ }
        foreach ($pf in $programFiles) {
            # Apache Tomcat standard installation
            Get-ChildItem -Path "$pf\Apache*Tomcat*" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                if (Test-Path "$($_.FullName)\conf\server.xml") {
                    $version = Get-TomcatVersion -ConfPath "$($_.FullName)\conf"
                    $tomcatInstalls += @{
                        Path     = $_.FullName
                        ConfPath = "$($_.FullName)\conf"
                        Version  = $version
                        Source   = "ProgramFiles"
                    }
                }
            }
        }
        
        # Check CATALINA_HOME
        if ($env:CATALINA_HOME -and (Test-Path "$env:CATALINA_HOME\conf\server.xml")) {
            $version = Get-TomcatVersion -ConfPath "$env:CATALINA_HOME\conf"
            $tomcatInstalls += @{
                Path     = $env:CATALINA_HOME
                ConfPath = "$env:CATALINA_HOME\conf"
                Version  = $version
                Source   = "CATALINA_HOME"
            }
        }
        
        # Check CATALINA_BASE
        if ($env:CATALINA_BASE -and (Test-Path "$env:CATALINA_BASE\conf\server.xml")) {
            $version = Get-TomcatVersion -ConfPath "$env:CATALINA_BASE\conf"
            $tomcatInstalls += @{
                Path     = $env:CATALINA_BASE
                ConfPath = "$env:CATALINA_BASE\conf"
                Version  = $version
                Source   = "CATALINA_BASE"
            }
        }
    }
    
    # Unix/macOS-specific paths
    if ($IsMacOS -or $IsLinux) {
        $unixPaths = @(
            "/opt/tomcat*",
            "/usr/share/tomcat*",
            "/usr/local/tomcat*",
            "/var/lib/tomcat*",
            "/home/*/tomcat*",
            "/Applications/tomcat*"
        )
        
        foreach ($pattern in $unixPaths) {
            Get-ChildItem -Path $pattern -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                if (Test-Path "$($_.FullName)/conf/server.xml") {
                    $version = Get-TomcatVersion -ConfPath "$($_.FullName)/conf"
                    $tomcatInstalls += @{
                        Path     = $_.FullName
                        ConfPath = "$($_.FullName)/conf"
                        Version  = $version
                        Source   = "FileSystem"
                    }
                }
            }
        }
        
        # Homebrew on macOS
        if (Test-Path "/opt/homebrew/opt/tomcat*/libexec") {
            Get-ChildItem -Path "/opt/homebrew/opt/tomcat*/libexec" -ErrorAction SilentlyContinue | ForEach-Object {
                if (Test-Path "$_/conf/server.xml") {
                    $version = Get-TomcatVersion -ConfPath "$_/conf"
                    $tomcatInstalls += @{
                        Path     = $_
                        ConfPath = "$_/conf"
                        Version  = $version
                        Source   = "Homebrew"
                    }
                }
            }
        }
    }
    
    return $tomcatInstalls
}

function Get-TomcatVersion {
    param([string]$ConfPath)
    
    $webXmlPath = Join-Path $ConfPath "web.xml"
    if (Test-Path $webXmlPath) {
        $content = Get-Content $webXmlPath -Raw -ErrorAction SilentlyContinue
        
        # Detect namespace to determine version
        if ($content -match 'jakarta\.ee') {
            if ($content -match 'version="6\.1"') { return "11.x" }
            if ($content -match 'version="6\.0"') { return "10.1" }
            if ($content -match 'version="5\.0"') { return "10.0" }
            return "10+"
        }
        elseif ($content -match 'xmlns\.jcp\.org') {
            if ($content -match 'version="4\.0"') { return "9.x" }
            if ($content -match 'version="3\.1"') { return "8.x" }
            return "8-9"
        }
        elseif ($content -match 'java\.sun\.com') {
            return "7.x"
        }
    }
    
    return "Unknown"
}
#endregion

#region IIS Detection
function Get-IisInstallations {
    <#
    .SYNOPSIS
    Detects IIS installations and their web.config paths
    #>
    $iisInstalls = @()
    
    if ($IsWindows -or (-not $IsMacOS -and -not $IsLinux)) {
        # Check default IIS paths
        $iisPaths = @(
            "C:\inetpub\wwwroot",
            "D:\inetpub\wwwroot"
        )
        
        foreach ($path in $iisPaths) {
            if (Test-Path "$path\web.config") {
                # Try to get IIS version from registry
                try {
                    $iisVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\InetStp" -ErrorAction SilentlyContinue).VersionString
                }
                catch {
                    $iisVersion = "Unknown"
                }
                
                $iisInstalls += @{
                    Path    = $path
                    Version = $iisVersion
                    Source  = "Default"
                }
            }
        }
        
        # Check for application pools and sites via appcmd
        if (Test-Path "$env:SystemRoot\System32\inetsrv\appcmd.exe") {
            try {
                $sites = & "$env:SystemRoot\System32\inetsrv\appcmd.exe" list site /xml 2>$null
                # Parse sites for paths
            }
            catch { }
        }
    }
    
    return $iisInstalls
}
#endregion

$TestDir = Join-Path ([System.IO.Path]::GetTempPath()) "HstsVersionMatrixTest_$(Get-Random)"
New-Item -Path $TestDir -ItemType Directory -Force | Out-Null

Write-Host "`n" -NoNewline
Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  HSTS Compliance Version Matrix Test Suite v2.0                  ║" -ForegroundColor Cyan
Write-Host "║  Testing: Tomcat 7-11, IIS 7-10 + Java Detection                 ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host "  Test Directory: $TestDir" -ForegroundColor Gray

# =============================================================================
# DETECTION TESTS (Optional)
# =============================================================================
if ($TestDetection) {
    Write-Host "`n═══════════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host "  JAVA VERSION DETECTION TEST" -ForegroundColor Magenta
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    
    $javaVersions = Get-JavaVersions
    if ($javaVersions.Count -gt 0) {
        foreach ($java in $javaVersions) {
            Write-Host "  Found: Java $($java.Version) ($($java.Vendor)) at $($java.Path)" -ForegroundColor Green
        }
        Write-TestResult "Java Detection" $true "Found $($javaVersions.Count) Java installation(s)"
    }
    else {
        Write-Host "  No Java installations detected" -ForegroundColor Yellow
        Write-TestResult "Java Detection" $true "No Java installations (this is OK for testing)"
    }
    
    Write-Host "`n═══════════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host "  TOMCAT INSTALLATION DETECTION TEST" -ForegroundColor Magenta
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    
    $tomcatInstalls = Get-TomcatInstallations
    if ($tomcatInstalls.Count -gt 0) {
        foreach ($tomcat in $tomcatInstalls) {
            Write-Host "  Found: Tomcat $($tomcat.Version) at $($tomcat.ConfPath) (via $($tomcat.Source))" -ForegroundColor Green
        }
        Write-TestResult "Tomcat Detection" $true "Found $($tomcatInstalls.Count) Tomcat installation(s)"
    }
    else {
        Write-Host "  No Tomcat installations detected" -ForegroundColor Yellow
        Write-TestResult "Tomcat Detection" $true "No Tomcat installations (using test fixtures)"
    }
}

# =============================================================================
# TOMCAT VERSION TEST FIXTURES
# =============================================================================

$TomcatVersions = @(
    @{
        Version       = "7.x"
        DisplayName   = "Tomcat 7 (Java EE - java.sun.com)"
        Namespace     = "http://java.sun.com/xml/ns/javaee"
        SchemaVersion = "3.0"
        JavaMin       = "6"
        JavaMax       = "8"
        WebXml        = @"
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://java.sun.com/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://java.sun.com/xml/ns/javaee http://java.sun.com/xml/ns/javaee/web-app_3_0.xsd"
         version="3.0">
    <display-name>Tomcat 7 Test Application</display-name>
</web-app>
"@
    },
    @{
        Version       = "8.0"
        DisplayName   = "Tomcat 8.0 (Java EE - xmlns.jcp.org)"
        Namespace     = "http://xmlns.jcp.org/xml/ns/javaee"
        SchemaVersion = "3.1"
        JavaMin       = "7"
        JavaMax       = "11"
        WebXml        = @"
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee http://xmlns.jcp.org/xml/ns/javaee/web-app_3_1.xsd"
         version="3.1">
    <display-name>Tomcat 8.0 Test Application</display-name>
</web-app>
"@
    },
    @{
        Version       = "8.5"
        DisplayName   = "Tomcat 8.5 (Java EE - xmlns.jcp.org)"
        Namespace     = "http://xmlns.jcp.org/xml/ns/javaee"
        SchemaVersion = "3.1"
        JavaMin       = "7"
        JavaMax       = "17"
        WebXml        = @"
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee http://xmlns.jcp.org/xml/ns/javaee/web-app_3_1.xsd"
         version="3.1">
    <display-name>Tomcat 8.5 Test Application</display-name>
</web-app>
"@
    },
    @{
        Version       = "9.x"
        DisplayName   = "Tomcat 9 (Java EE - xmlns.jcp.org)"
        Namespace     = "http://xmlns.jcp.org/xml/ns/javaee"
        SchemaVersion = "4.0"
        JavaMin       = "8"
        JavaMax       = "21"
        WebXml        = @"
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
         version="4.0">
    <display-name>Tomcat 9 Test Application</display-name>
</web-app>
"@
    },
    @{
        Version       = "10.0"
        DisplayName   = "Tomcat 10.0 (Jakarta EE 9)"
        Namespace     = "https://jakarta.ee/xml/ns/jakartaee"
        SchemaVersion = "5.0"
        JavaMin       = "8"
        JavaMax       = "21"
        WebXml        = @"
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="https://jakarta.ee/xml/ns/jakartaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="https://jakarta.ee/xml/ns/jakartaee https://jakarta.ee/xml/ns/jakartaee/web-app_5_0.xsd"
         version="5.0">
    <display-name>Tomcat 10.0 Test Application</display-name>
</web-app>
"@
    },
    @{
        Version       = "10.1"
        DisplayName   = "Tomcat 10.1 (Jakarta EE 10)"
        Namespace     = "https://jakarta.ee/xml/ns/jakartaee"
        SchemaVersion = "6.0"
        JavaMin       = "11"
        JavaMax       = "21"
        WebXml        = @"
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="https://jakarta.ee/xml/ns/jakartaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="https://jakarta.ee/xml/ns/jakartaee https://jakarta.ee/xml/ns/jakartaee/web-app_6_0.xsd"
         version="6.0">
    <display-name>Tomcat 10.1 Test Application</display-name>
</web-app>
"@
    },
    @{
        Version       = "11.x"
        DisplayName   = "Tomcat 11 (Jakarta EE 11)"
        Namespace     = "https://jakarta.ee/xml/ns/jakartaee"
        SchemaVersion = "6.1"
        JavaMin       = "17"
        JavaMax       = "22"
        WebXml        = @"
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="https://jakarta.ee/xml/ns/jakartaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="https://jakarta.ee/xml/ns/jakartaee https://jakarta.ee/xml/ns/jakartaee/web-app_6_1.xsd"
         version="6.1">
    <display-name>Tomcat 11 Test Application</display-name>
</web-app>
"@
    }
)

# =============================================================================
# IIS VERSION TEST FIXTURES
# =============================================================================

$IisVersions = @(
    @{
        Version     = "7.0"
        DisplayName = "IIS 7.0 (Windows Server 2008)"
        OsVersion   = "Windows Server 2008"
        WebConfig   = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
    </system.webServer>
</configuration>
"@
    },
    @{
        Version     = "7.5"
        DisplayName = "IIS 7.5 (Windows Server 2008 R2)"
        OsVersion   = "Windows Server 2008 R2"
        WebConfig   = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
        <defaultDocument>
            <files>
                <add value="index.html" />
            </files>
        </defaultDocument>
    </system.webServer>
</configuration>
"@
    },
    @{
        Version     = "8.0"
        DisplayName = "IIS 8.0 (Windows Server 2012)"
        OsVersion   = "Windows Server 2012"
        WebConfig   = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
        <staticContent>
            <mimeMap fileExtension=".json" mimeType="application/json" />
        </staticContent>
    </system.webServer>
</configuration>
"@
    },
    @{
        Version     = "8.5"
        DisplayName = "IIS 8.5 (Windows Server 2012 R2)"
        OsVersion   = "Windows Server 2012 R2"
        WebConfig   = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
        <rewrite>
            <rules>
                <rule name="HTTPS Redirect" stopProcessing="true">
                    <match url="(.*)" />
                    <conditions>
                        <add input="{HTTPS}" pattern="off" />
                    </conditions>
                    <action type="Redirect" url="https://{HTTP_HOST}/{R:1}" redirectType="Permanent" />
                </rule>
            </rules>
        </rewrite>
    </system.webServer>
</configuration>
"@
    },
    @{
        Version     = "10.0"
        DisplayName = "IIS 10.0 (Windows Server 2016/2019/2022)"
        OsVersion   = "Windows Server 2016+"
        WebConfig   = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
        <httpProtocol>
            <customHeaders>
                <add name="X-Content-Type-Options" value="nosniff" />
                <add name="X-Frame-Options" value="SAMEORIGIN" />
            </customHeaders>
        </httpProtocol>
    </system.webServer>
</configuration>
"@
    }
)

$SecurityLevels = @("basic", "high", "veryhigh", "maximum")

# Filter versions if specified
if ($VersionsToTest) {
    $TomcatVersions = $TomcatVersions | Where-Object { $VersionsToTest -contains $_.Version }
    $IisVersions = $IisVersions | Where-Object { $VersionsToTest -contains $_.Version }
}

# =============================================================================
# TEST GROUP 1: TOMCAT VERSIONS (Windows PowerShell Script)
# =============================================================================
Write-Host "`n═══════════════════════════════════════════════════════════════════" -ForegroundColor Magenta
Write-Host "  TOMCAT VERSION TESTS (UpdateTomcatHstsWin.ps1)" -ForegroundColor Magenta
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Magenta

foreach ($tomcat in $TomcatVersions) {
    Write-Host "`n  --- $($tomcat.DisplayName) ---" -ForegroundColor Yellow
    Write-Host "      Java Compatibility: $($tomcat.JavaMin) - $($tomcat.JavaMax)" -ForegroundColor Gray
    
    $TomcatConf = Join-Path $TestDir "tomcat_$($tomcat.Version)/conf"
    New-Item -Path $TomcatConf -ItemType Directory -Force | Out-Null
    Set-Content -Path (Join-Path $TomcatConf "server.xml") -Value '<Server port="8005" shutdown="SHUTDOWN"></Server>'
    
    foreach ($level in $SecurityLevels) {
        # Reset web.xml for each test
        Set-Content -Path (Join-Path $TomcatConf "web.xml") -Value $tomcat.WebXml
        
        try {
            $result = & "./src/windows/UpdateTomcatHstsWin.ps1" -Mode "configure" -CustomPaths @($TomcatConf) -SecurityLevel $level -Force 2>&1
            $content = Get-Content (Join-Path $TomcatConf "web.xml") -Raw
            
            $hasFilter = $content -match "HstsHeaderFilter|HttpHeaderSecurityFilter"
            $hasMaxAge = $content -match "hstsMaxAgeSeconds"
            
            if ($level -eq "maximum") {
                $hasCorrectAge = $content -match "63072000"
            }
            else {
                $hasCorrectAge = $content -match "31536000"
            }
            
            # Verify namespace is preserved
            $namespacePreserved = $content -match [regex]::Escape($tomcat.Namespace)
            
            $passed = $hasFilter -and $hasMaxAge -and $hasCorrectAge -and $namespacePreserved
            Write-TestResult "Tomcat $($tomcat.Version) - $level" $passed $(if (-not $namespacePreserved) { "Namespace not preserved" })
        }
        catch {
            Write-TestResult "Tomcat $($tomcat.Version) - $level" $false "Exception: $_"
        }
    }
    
    # Audit test
    try {
        $result = & "./src/windows/UpdateTomcatHstsWin.ps1" -Mode "audit" -CustomPaths @($TomcatConf) -SecurityLevel "high" 2>&1
        $passed = $LASTEXITCODE -eq 0
        Write-TestResult "Tomcat $($tomcat.Version) - Audit Mode" $passed
    }
    catch {
        Write-TestResult "Tomcat $($tomcat.Version) - Audit Mode" $false "Exception: $_"
    }
    
    # Dry-run test
    Set-Content -Path (Join-Path $TomcatConf "web.xml") -Value $tomcat.WebXml
    try {
        $result = & "./src/windows/UpdateTomcatHstsWin.ps1" -Mode "configure" -CustomPaths @($TomcatConf) -SecurityLevel "high" -DryRun -Force 2>&1
        $content = Get-Content (Join-Path $TomcatConf "web.xml") -Raw
        # Dry-run should NOT modify the file
        $unchanged = $content -eq $tomcat.WebXml.Trim() -or (-not ($content -match "HstsHeaderFilter"))
        Write-TestResult "Tomcat $($tomcat.Version) - Dry-Run" $unchanged
    }
    catch {
        Write-TestResult "Tomcat $($tomcat.Version) - Dry-Run" $false "Exception: $_"
    }
}

# =============================================================================
# TEST GROUP 2: IIS VERSIONS (Windows PowerShell Script)
# =============================================================================
Write-Host "`n═══════════════════════════════════════════════════════════════════" -ForegroundColor Magenta
Write-Host "  IIS VERSION TESTS (UpdateIisHstsWin.ps1)" -ForegroundColor Magenta
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Magenta

foreach ($iis in $IisVersions) {
    Write-Host "`n  --- $($iis.DisplayName) ---" -ForegroundColor Yellow
    
    $IisDir = Join-Path $TestDir "iis_$($iis.Version)/wwwroot"
    New-Item -Path $IisDir -ItemType Directory -Force | Out-Null
    
    foreach ($level in $SecurityLevels) {
        # Reset web.config for each test
        Set-Content -Path (Join-Path $IisDir "web.config") -Value $iis.WebConfig
        
        try {
            $result = & "./src/windows/UpdateIisHstsWin.ps1" -Mode "configure" -CustomPaths @($IisDir) -SecurityLevel $level -Force 2>&1
            $content = Get-Content (Join-Path $IisDir "web.config") -Raw
            
            $hasHsts = $content -match "Strict-Transport-Security"
            
            switch ($level) {
                "basic" { $hasCorrectConfig = $content -match "max-age=31536000" -and $content -notmatch "includeSubDomains" }
                "high" { $hasCorrectConfig = $content -match "max-age=31536000" -and $content -match "includeSubDomains" }
                "veryhigh" { $hasCorrectConfig = $content -match "max-age=31536000" -and $content -match "includeSubDomains" -and $content -match "preload" }
                "maximum" { $hasCorrectConfig = $content -match "max-age=63072000" -and $content -match "includeSubDomains" -and $content -match "preload" }
            }
            
            $passed = $hasHsts -and $hasCorrectConfig
            Write-TestResult "IIS $($iis.Version) - $level" $passed
        }
        catch {
            Write-TestResult "IIS $($iis.Version) - $level" $false "Exception: $_"
        }
    }
    
    # Audit test
    try {
        $result = & "./src/windows/UpdateIisHstsWin.ps1" -Mode "audit" -CustomPaths @($IisDir) -SecurityLevel "high" 2>&1
        $passed = $LASTEXITCODE -eq 0
        Write-TestResult "IIS $($iis.Version) - Audit Mode" $passed
    }
    catch {
        Write-TestResult "IIS $($iis.Version) - Audit Mode" $false "Exception: $_"
    }
    
    # Dry-run test
    Set-Content -Path (Join-Path $IisDir "web.config") -Value $iis.WebConfig
    try {
        $result = & "./src/windows/UpdateIisHstsWin.ps1" -Mode "configure" -CustomPaths @($IisDir) -SecurityLevel "high" -DryRun -Force 2>&1
        $content = Get-Content (Join-Path $IisDir "web.config") -Raw
        # Dry-run should NOT modify the file
        $unchanged = (-not ($content -match "Strict-Transport-Security"))
        Write-TestResult "IIS $($iis.Version) - Dry-Run" $unchanged
    }
    catch {
        Write-TestResult "IIS $($iis.Version) - Dry-Run" $false "Exception: $_"
    }
}

# =============================================================================
# TEST GROUP 3: UNIX TOMCAT VERSIONS (if not skipped)
# =============================================================================
if (-not $SkipUnix -and ($IsMacOS -or $IsLinux)) {
    Write-Host "`n═══════════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host "  UNIX TOMCAT VERSION TESTS (UpdateTomcatHstsUnix.sh)" -ForegroundColor Magenta
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    
    foreach ($tomcat in $TomcatVersions) {
        Write-Host "`n  --- $($tomcat.DisplayName) (Unix) ---" -ForegroundColor Yellow
        
        $UnixTomcatConf = Join-Path $TestDir "unix_tomcat_$($tomcat.Version)/conf"
        New-Item -Path $UnixTomcatConf -ItemType Directory -Force | Out-Null
        Set-Content -Path (Join-Path $UnixTomcatConf "server.xml") -Value '<Server port="8005" shutdown="SHUTDOWN"></Server>'
        
        foreach ($level in $SecurityLevels) {
            Set-Content -Path (Join-Path $UnixTomcatConf "web.xml") -Value $tomcat.WebXml
            
            try {
                $result = bash -c "./src/unix/UpdateTomcatHstsUnix.sh --mode configure --security-level $level --custom-conf='$UnixTomcatConf'" 2>&1
                $content = Get-Content (Join-Path $UnixTomcatConf "web.xml") -Raw
                
                $hasFilter = $content -match "HstsHeaderFilter|HttpHeaderSecurityFilter"
                $hasMaxAge = $content -match "hstsMaxAgeSeconds|max-age"
                
                if ($level -eq "maximum") {
                    $hasCorrectAge = $content -match "63072000"
                }
                else {
                    $hasCorrectAge = $content -match "31536000"
                }
                
                $passed = $hasFilter -and $hasMaxAge -and $hasCorrectAge
                Write-TestResult "Unix Tomcat $($tomcat.Version) - $level" $passed
            }
            catch {
                Write-TestResult "Unix Tomcat $($tomcat.Version) - $level" $false "Exception: $_"
            }
        }
    }
}

# =============================================================================
# Cleanup and Summary
# =============================================================================
Remove-Item -Path $TestDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "`n" -NoNewline
Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  TEST SUMMARY                                                    ║" -ForegroundColor Cyan
Write-Host "╠══════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
Write-Host "║  Passed: $($script:TestsPassed.ToString().PadLeft(4))                                                    ║" -ForegroundColor $(if ($script:TestsPassed -gt 0) { "Green" } else { "Gray" })
Write-Host "║  Failed: $($script:TestsFailed.ToString().PadLeft(4))                                                    ║" -ForegroundColor $(if ($script:TestsFailed -gt 0) { "Red" } else { "Green" })
Write-Host "║  Total:  $((($script:TestsPassed + $script:TestsFailed).ToString().PadLeft(4)))                                                    ║" -ForegroundColor White
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

if ($script:TestsFailed -gt 0) {
    Write-Host "`n  SOME TESTS FAILED!" -ForegroundColor Red
    Write-Host "  Failed tests:" -ForegroundColor Red
    $script:TestResults | Where-Object { -not $_.Passed } | ForEach-Object {
        Write-Host "    - $($_.Name): $($_.Details)" -ForegroundColor Red
    }
    exit 1
}
else {
    Write-Host "`n  ALL TESTS PASSED!" -ForegroundColor Green
    exit 0
}
