# verify_enhanced_audit_win.ps1
# Verifies the enhanced audit output in UpdateTomcatHstsWin.ps1 and UpdateIisHstsWin.ps1

$ErrorActionPreference = "Stop"
$TestDir = New-Item -Path ".\tests\EnhancedAuditTestWin" -ItemType Directory -Force
$TomcatScript = ".\src\windows\UpdateTomcatHstsWin.ps1"
$IisScript = ".\src\windows\UpdateIisHstsWin.ps1"

function Write-Log {
    param($Message)
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
}

function Run-TomcatAudit {
    param($Name, $WebXml)
    $TargetDir = New-Item -Path "$TestDir\Tomcat_$Name\conf" -ItemType Directory -Force
    $WebXmlPath = "$TargetDir\web.xml"
    $WebXml | Out-File -FilePath $WebXmlPath -Encoding utf8
    # Mock server.xml and RELEASE-NOTES for detection
    " " | Out-File -FilePath "$TargetDir\server.xml" -Encoding utf8
    "Apache Tomcat Version 9.0.0" | Out-File -FilePath (Join-Path $TargetDir "..\RELEASE-NOTES") -Encoding utf8
    
    $LogPath = "$TestDir\Tomcat_$Name`_audit.log"
    & $TomcatScript -Mode audit -TomcatConfPath "$TargetDir" -LogFile "$LogPath" | Out-Null
    return $LogPath
}

function Run-IisAudit {
    param($Name, $WebConfig)
    $TargetDir = New-Item -Path "$TestDir\Iis_$Name" -ItemType Directory -Force
    $WebConfigPath = "$TargetDir\web.config"
    # Use ascii/utf8 without BOM to avoid parsing issues if any
    [System.IO.File]::WriteAllText($WebConfigPath, $WebConfig)
    
    $LogPath = "$TestDir\Iis_$Name`_audit.log"
    & $IisScript -Mode audit -ConfigPath "$WebConfigPath" -LogFile "$LogPath" | Out-Null
    return $LogPath
}

# --- Tomcat Verifications ---
Write-Log "Verifying Windows Tomcat enhanced audit..."

# Scenario 1: No HSTS
$WebXml = '<?xml version="1.0" encoding="UTF-8"?><web-app><filter><filter-name>SomeOtherFilter</filter-name></filter></web-app>'
$log = Run-TomcatAudit -Name "NoHsts" -WebXml $WebXml
$content = Get-Content $log
if ($content -match "=== AUDIT: No HSTS Configuration Found ===" -and $content -match "SomeOtherFilter") {
    Write-Log "SUCCESS: Tomcat No HSTS verified"
}
else {
    Write-Log "FAILURE: Tomcat No HSTS mismatch"
}

# Scenario 2: Non-Compliant
$WebXml = '<?xml version="1.0" encoding="UTF-8"?>
<web-app>
    <filter>
        <filter-name>HstsHeaderFilter</filter-name>
        <init-param><param-name>hstsMaxAgeSeconds</param-name><param-value>42</param-value></init-param>
    </filter>
</web-app>'
$log = Run-TomcatAudit -Name "NonCompliant" -WebXml $WebXml
$content = Get-Content $log
if ($content -match "=== Audit Result Breakdown ===" -and $content -match "\[FAIL\] Filter: HstsHeaderFilter \(max-age=42") {
    Write-Log "SUCCESS: Tomcat Non-compliant verified"
}
else {
    Write-Log "FAILURE: Tomcat Non-compliant mismatch"
}

# --- IIS Verifications ---
Write-Log "Verifying Windows IIS enhanced audit..."

# Scenario 1: No HSTS
$WebConfig = '<?xml version="1.0" encoding="UTF-8"?><configuration><system.webServer><httpProtocol><customHeaders><add name="X-Other" value="test"/></customHeaders></httpProtocol></system.webServer></configuration>'
$log = Run-IisAudit -Name "NoHsts" -WebConfig $WebConfig
$content = Get-Content $log
if ($content -match "=== AUDIT: No HSTS Configuration Found ===" -and $content -match "X-Other: test") {
    Write-Log "SUCCESS: IIS No HSTS verified"
}
else {
    Write-Log "FAILURE: IIS No HSTS mismatch"
}

# Scenario 2: Non-Compliant Breakdown
$WebConfig = '<?xml version="1.0" encoding="UTF-8"?><configuration><system.webServer><httpProtocol><customHeaders><add name="Strict-Transport-Security" value="max-age=60"/></customHeaders></httpProtocol></system.webServer></configuration>'
$log = Run-IisAudit -Name "NonCompliant" -WebConfig $WebConfig
$content = Get-Content $log
if ($content -match "=== Audit Result Breakdown ===" -and $content -match "\[FAIL\] Source: CustomHeader \(max-age=60\)") {
    Write-Log "SUCCESS: IIS Non-compliant verified"
}
else {
    Write-Log "FAILURE: IIS Non-compliant mismatch"
}

Write-Log "=== Windows Verification Complete ==="
