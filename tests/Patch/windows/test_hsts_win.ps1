# test_hsts_win.ps1
# Tests HSTS patching scripts for Tomcat and IIS on Windows
# Tests UpdateTomcatHstsWin.ps1 and UpdateIisHstsWin.ps1

#Requires -Version 5.1
#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$LOG_FILE = "$env:TEMP\TestHstsWin.log"
$TEST_DIR = "$env:TEMP\HstsTest"
$BACKUP_DIR = "$env:TEMP\HstsTestBackup"

# Function to write log messages
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Level - $Message"
    Add-Content -Path $LOG_FILE -Value $logMessage
    Write-Host $logMessage
}

Write-Log "Starting HSTS patching tests for Windows..."

# Create test directories
if (Test-Path $TEST_DIR) {
    Remove-Item -Path $TEST_DIR -Recurse -Force
}
New-Item -ItemType Directory -Path $TEST_DIR -Force | Out-Null
New-Item -ItemType Directory -Path $BACKUP_DIR -Force | Out-Null

# Test scenarios
$testScenarios = @(
    @{
        Name = "No_HSTS_Header"
        Description = "Configuration with no HSTS header"
        WebXml = @"
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
         http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
         version="4.0">
    <display-name>Test Application</display-name>
</web-app>
"@
        WebConfig = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
            </customHeaders>
        </httpProtocol>
    </system.webServer>
</configuration>
"@
        ExpectedResult = "Should add compliant HSTS header"
    },
    @{
        Name = "Non_Compliant_HSTS_Short_MaxAge"
        Description = "HSTS with max-age less than 31536000"
        WebXml = @"
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
         http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
         version="4.0">
    <filter>
        <filter-name>HstsHeaderFilter</filter-name>
        <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>
        <init-param>
            <param-name>hstsMaxAgeSeconds</param-name>
            <param-value>86400</param-value>
        </init-param>
        <init-param>
            <param-name>hstsIncludeSubDomains</param-name>
            <param-value>true</param-value>
        </init-param>
    </filter>
    <filter-mapping>
        <filter-name>HstsHeaderFilter</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>
</web-app>
"@
        WebConfig = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="Strict-Transport-Security" value="max-age=86400; includeSubDomains" />
            </customHeaders>
        </httpProtocol>
    </system.webServer>
</configuration>
"@
        ExpectedResult = "Should replace with compliant HSTS header (max-age=31536000)"
    },
    @{
        Name = "Non_Compliant_HSTS_No_IncludeSubDomains"
        Description = "HSTS with max-age correct but missing includeSubDomains"
        WebXml = @"
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
         http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
         version="4.0">
    <filter>
        <filter-name>HstsHeaderFilter</filter-name>
        <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>
        <init-param>
            <param-name>hstsMaxAgeSeconds</param-name>
            <param-value>31536000</param-value>
        </init-param>
        <init-param>
            <param-name>hstsIncludeSubDomains</param-name>
            <param-value>false</param-value>
        </init-param>
    </filter>
    <filter-mapping>
        <filter-name>HstsHeaderFilter</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>
</web-app>
"@
        WebConfig = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="Strict-Transport-Security" value="max-age=31536000" />
            </customHeaders>
        </httpProtocol>
    </system.webServer>
</configuration>
"@
        ExpectedResult = "Should add includeSubDomains"
    },
    @{
        Name = "Compliant_HSTS"
        Description = "Already compliant HSTS configuration"
        WebXml = @"
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
         http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
         version="4.0">
    <filter>
        <filter-name>HstsHeaderFilter</filter-name>
        <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>
        <init-param>
            <param-name>hstsMaxAgeSeconds</param-name>
            <param-value>31536000</param-value>
        </init-param>
        <init-param>
            <param-name>hstsIncludeSubDomains</param-name>
            <param-value>true</param-value>
        </init-param>
    </filter>
    <filter-mapping>
        <filter-name>HstsHeaderFilter</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>
</web-app>
"@
        WebConfig = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains" />
            </customHeaders>
        </httpProtocol>
    </system.webServer>
</configuration>
"@
        ExpectedResult = "Should remain unchanged (already compliant)"
    },
    @{
        Name = "Multiple_HSTS_Headers"
        Description = "Multiple HSTS header definitions (should be consolidated)"
        WebXml = @"
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
         http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
         version="4.0">
    <filter>
        <filter-name>HstsHeaderFilter1</filter-name>
        <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>
        <init-param>
            <param-name>hstsMaxAgeSeconds</param-name>
            <param-value>31536000</param-value>
        </init-param>
        <init-param>
            <param-name>hstsIncludeSubDomains</param-name>
            <param-value>true</param-value>
        </init-param>
    </filter>
    <filter>
        <filter-name>HstsHeaderFilter2</filter-name>
        <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>
        <init-param>
            <param-name>hstsMaxAgeSeconds</param-name>
            <param-value>86400</param-value>
        </init-param>
    </filter>
    <filter-mapping>
        <filter-name>HstsHeaderFilter1</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>
    <filter-mapping>
        <filter-name>HstsHeaderFilter2</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>
</web-app>
"@
        WebConfig = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains" />
                <add name="Strict-Transport-Security" value="max-age=86400" />
            </customHeaders>
        </httpProtocol>
    </system.webServer>
</configuration>
"@
        ExpectedResult = "Should remove duplicates and keep one compliant header"
    }
)

# Test Tomcat HSTS patching
Write-Log "=== Testing Tomcat HSTS Patching ==="
$tomcatTestDir = Join-Path $TEST_DIR "tomcat"
New-Item -ItemType Directory -Path $tomcatTestDir -Force | Out-Null
New-Item -ItemType Directory -Path "$tomcatTestDir\conf" -Force | Out-Null

$scriptPath = Join-Path $PSScriptRoot "..\..\..\src\windows\Patch\powershell\UpdateTomcatHstsWin.ps1"
if (-not (Test-Path $scriptPath)) {
    Write-Log "ERROR: UpdateTomcatHstsWin.ps1 not found at $scriptPath" "ERROR"
    exit 1
}

foreach ($scenario in $testScenarios) {
    Write-Log "Testing scenario: $($scenario.Name) - $($scenario.Description)"
    
    # Create test web.xml
    $webXmlPath = Join-Path "$tomcatTestDir\conf" "web.xml"
    Set-Content -Path $webXmlPath -Value $scenario.WebXml -Encoding UTF8
    
    # Backup original
    Copy-Item $webXmlPath "$BACKUP_DIR\web.xml.$($scenario.Name)" -Force
    
    # Run audit mode
    Write-Log "Running audit mode..."
    try {
        $auditResult = & $scriptPath -Mode audit -CustomPaths @("$tomcatTestDir\conf") 2>&1
        Write-Log "Audit output: $auditResult"
    } catch {
        Write-Log "Audit error: $_" "ERROR"
    }
    
    # Run configure mode (dry run first)
    Write-Log "Running configure mode (dry run)..."
    try {
        $dryRunResult = & $scriptPath -Mode configure -CustomPaths @("$tomcatTestDir\conf") -DryRun 2>&1
        Write-Log "Dry run output: $dryRunResult"
    } catch {
        Write-Log "Dry run error: $_" "ERROR"
    }
    
    # Restore for next test
    Copy-Item "$BACKUP_DIR\web.xml.$($scenario.Name)" $webXmlPath -Force
}

# Test IIS HSTS patching
Write-Log "=== Testing IIS HSTS Patching ==="
$iisTestDir = Join-Path $TEST_DIR "iis"
New-Item -ItemType Directory -Path $iisTestDir -Force | Out-Null

$iisScriptPath = Join-Path $PSScriptRoot "..\..\..\src\windows\Patch\powershell\UpdateIisHstsWin.ps1"
if (-not (Test-Path $iisScriptPath)) {
    Write-Log "ERROR: UpdateIisHstsWin.ps1 not found at $iisScriptPath" "ERROR"
    exit 1
}

foreach ($scenario in $testScenarios) {
    Write-Log "Testing scenario: $($scenario.Name) - $($scenario.Description)"
    
    # Create test web.config
    $webConfigPath = Join-Path $iisTestDir "web.config"
    Set-Content -Path $webConfigPath -Value $scenario.WebConfig -Encoding UTF8
    
    # Backup original
    Copy-Item $webConfigPath "$BACKUP_DIR\web.config.$($scenario.Name)" -Force
    
    # Run audit mode
    Write-Log "Running audit mode..."
    try {
        $auditResult = & $iisScriptPath -Mode audit -ConfigPath $webConfigPath 2>&1
        Write-Log "Audit output: $auditResult"
    } catch {
        Write-Log "Audit error: $_" "ERROR"
    }
    
    # Run configure mode (dry run first)
    Write-Log "Running configure mode (dry run)..."
    try {
        $dryRunResult = & $iisScriptPath -Mode configure -ConfigPath $webConfigPath -DryRun 2>&1
        Write-Log "Dry run output: $dryRunResult"
    } catch {
        Write-Log "Dry run error: $_" "ERROR"
    }
    
    # Restore for next test
    Copy-Item "$BACKUP_DIR\web.config.$($scenario.Name)" $webConfigPath -Force
}

Write-Log "=== All HSTS tests completed ==="
Write-Log "Test log saved to: $LOG_FILE"
Write-Log "Test files saved to: $TEST_DIR"
Write-Log "Backups saved to: $BACKUP_DIR"

