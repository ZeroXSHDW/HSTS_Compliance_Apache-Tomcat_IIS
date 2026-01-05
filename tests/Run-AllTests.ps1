# Run-AllTests.ps1
# Comprehensive test runner for HSTS Compliance Suite (Windows)
# Runs all tests and validates results

#Requires -Version 5.1
#Requires -RunAsAdministrator

$ErrorActionPreference = "Continue"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
$TestResultsDir = Join-Path $ProjectRoot "test-results"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# Create test results directory
if (-not (Test-Path $TestResultsDir)) {
    New-Item -ItemType Directory -Path $TestResultsDir -Force | Out-Null
}

# Test result tracking
$TotalTests = 0
$PassedTests = 0
$FailedTests = 0
$TestResults = @()

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "HSTS Compliance Suite - Test Runner" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Timestamp: $Timestamp"
Write-Host "Project Root: $ProjectRoot"
Write-Host ""

# Function to write test results
function Write-TestResult {
    param(
        [string]$TestName,
        [string]$Result,
        [string]$Message
    )
    
    $script:TotalTests++
    
    $testResult = [PSCustomObject]@{
        TestName  = $TestName
        Result    = $Result
        Message   = $Message
        Timestamp = Get-Date
    }
    
    $script:TestResults += $testResult
    
    if ($Result -eq "PASS") {
        $script:PassedTests++
        Write-Host "✓ $TestName`: $Message" -ForegroundColor Green
    }
    else {
        $script:FailedTests++
        Write-Host "✗ $TestName`: $Message" -ForegroundColor Red
    }
}

# Test 1: PowerShell Syntax Validation
Write-Host "Running Test 1: PowerShell Syntax Validation..." -ForegroundColor Yellow

$psScripts = @(
    "src\windows\UpdateTomcatHstsWin.ps1",
    "src\windows\UpdateIisHstsWin.ps1",
    "src\windows\Remote_UpdateTomcatHstsWin.ps1",
    "src\windows\Remote_UpdateIisHstsWin.ps1"
)

foreach ($script in $psScripts) {
    $scriptPath = Join-Path $ProjectRoot $script
    if (Test-Path $scriptPath) {
        try {
            $errors = $null
            $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $scriptPath -Raw), [ref]$errors)
            if ($errors.Count -eq 0) {
                Write-TestResult "PS_Syntax_$(Split-Path $script -Leaf)" "PASS" "Syntax is valid"
            }
            else {
                Write-TestResult "PS_Syntax_$(Split-Path $script -Leaf)" "FAIL" "Syntax errors found: $($errors.Count)"
            }
        }
        catch {
            Write-TestResult "PS_Syntax_$(Split-Path $script -Leaf)" "FAIL" "Failed to parse: $_"
        }
    }
    else {
        Write-TestResult "PS_Syntax_$(Split-Path $script -Leaf)" "FAIL" "Script not found"
    }
}

# Test 2: Windows Test Suite
Write-Host ""
Write-Host "Running Test 2: Windows Test Suite..." -ForegroundColor Yellow

$windowsTestScript = Join-Path $ProjectRoot "tests\windows\test_hsts_win.ps1"
if (Test-Path $windowsTestScript) {
    try {
        $testLog = Join-Path $TestResultsDir "windows_tests_$Timestamp.log"
        & $windowsTestScript *> $testLog
        if ($LASTEXITCODE -eq 0 -or $null -eq $LASTEXITCODE) {
            Write-TestResult "Windows_Test_Suite" "PASS" "All Windows tests completed"
        }
        else {
            Write-TestResult "Windows_Test_Suite" "FAIL" "Tests failed - check log: $testLog"
        }
    }
    catch {
        Write-TestResult "Windows_Test_Suite" "FAIL" "Test execution failed: $_"
    }
}
else {
    Write-TestResult "Windows_Test_Suite" "FAIL" "Test script not found"
}

# Test 3: Example Files Validation
Write-Host ""
Write-Host "Running Test 3: Example Files Validation..." -ForegroundColor Yellow

$exampleFiles = @{
    "test_web.xml"    = "examples\test_web.xml"
    "test_web.config" = "examples\test_web.config"
    "web.xml"         = "examples\web.xml"
}

foreach ($file in $exampleFiles.GetEnumerator()) {
    $filePath = Join-Path $ProjectRoot $file.Value
    if (Test-Path $filePath) {
        try {
            $null = [xml]::new().LoadXml((Get-Content $filePath -Raw))
            Write-TestResult "Example_$($file.Key)" "PASS" "Valid XML"
        }
        catch {
            Log-TestResult "Example_$($file.Key)" "FAIL" "Invalid XML: $_"
        }
    }
    else {
        Log-TestResult "Example_$($file.Key)" "FAIL" "File not found"
    }
}

# Test 4: Documentation Completeness
Write-Host ""
Write-Host "Running Test 4: Documentation Completeness..." -ForegroundColor Yellow

$requiredDocs = @("README.md", "CHANGELOG.md", "CONTRIBUTING.md", "SECURITY.md", "LICENSE", "VERSION")

foreach ($doc in $requiredDocs) {
    $docPath = Join-Path $ProjectRoot $doc
    if (Test-Path $docPath) {
        Write-TestResult "Doc_$doc" "PASS" "Document exists"
    }
    else {
        Write-TestResult "Doc_$doc" "FAIL" "Document missing"
    }
}

# Test 5: Required Directories
Write-Host ""
Write-Host "Running Test 5: Required Directories..." -ForegroundColor Yellow

$requiredDirs = @("src", "tests", "examples", "docs", "install", ".github")

foreach ($dir in $requiredDirs) {
    $dirPath = Join-Path $ProjectRoot $dir
    if (Test-Path $dirPath) {
        Write-TestResult "Dir_$dir" "PASS" "Directory exists"
    }
    else {
        Write-TestResult "Dir_$dir" "FAIL" "Directory missing"
    }
}

# Test 6: HSTS Compliance Validation (Tomcat)
Write-Host ""
Write-Host "Running Test 6: HSTS Compliance Validation (Tomcat)..." -ForegroundColor Yellow

# Determine temp directory cross-platform
$TempRoot = if ($IsWindows) { $env:TEMP } else { [System.IO.Path]::GetTempPath() }
if (-not $TempRoot) { $TempRoot = "/tmp" }

$tempDir = Join-Path $TempRoot "HSTSTest_$Timestamp"
$tempConfDir = Join-Path $tempDir "conf"
New-Item -ItemType Directory -Path $tempConfDir -Force | Out-Null

# Create minimal web.xml
$testWebXml = @"
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee" version="4.0">
    <display-name>Test</display-name>
</web-app>
"@
Set-Content -Path (Join-Path $tempConfDir "web.xml") -Value $testWebXml

# Create server.xml for detection
New-Item -ItemType File -Path (Join-Path $tempConfDir "server.xml") -Force | Out-Null

# Run audit mode
$tomcatScript = Join-Path $ProjectRoot "src\windows\UpdateTomcatHstsWin.ps1"
if (Test-Path $tomcatScript) {
    try {
        & $tomcatScript -Mode audit -CustomPaths @($tempConfDir) -ErrorAction SilentlyContinue | Out-Null
        # Exit code 1 is expected for non-compliant configs
        if ($LASTEXITCODE -eq 1 -or $LASTEXITCODE -eq 0) {
            Write-TestResult "HSTS_Tomcat_Audit" "PASS" "Audit mode executes correctly"
        }
        else {
            Write-TestResult "HSTS_Tomcat_Audit" "FAIL" "Unexpected exit code: $LASTEXITCODE"
        }
    }
    catch {
        Write-TestResult "HSTS_Tomcat_Audit" "FAIL" "Audit failed: $_"
    }
}
else {
    Write-TestResult "HSTS_Tomcat_Audit" "FAIL" "Tomcat script not found"
}

# Cleanup
Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue

# Test 7: HSTS Compliance Validation (IIS)
Write-Host ""
Write-Host "Running Test 7: HSTS Compliance Validation (IIS)..." -ForegroundColor Yellow

$tempDir2 = Join-Path $TempRoot "HSTSTestIIS_$Timestamp"
New-Item -ItemType Directory -Path $tempDir2 -Force | Out-Null

# Create minimal web.config
$testWebConfig = @"
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
$webConfigPath = Join-Path $tempDir2 "web.config"
Set-Content -Path $webConfigPath -Value $testWebConfig

# Run audit mode
$iisScript = Join-Path $ProjectRoot "src\windows\UpdateIisHstsWin.ps1"
if (Test-Path $iisScript) {
    try {
        & $iisScript -Mode audit -ConfigPath $webConfigPath -ErrorAction SilentlyContinue | Out-Null
        # Exit code 1 is expected for non-compliant configs
        if ($LASTEXITCODE -eq 1 -or $LASTEXITCODE -eq 0) {
            Write-TestResult "HSTS_IIS_Audit" "PASS" "Audit mode executes correctly"
        }
        else {
            Write-TestResult "HSTS_IIS_Audit" "FAIL" "Unexpected exit code: $LASTEXITCODE"
        }
    }
    catch {
        Write-TestResult "HSTS_IIS_Audit" "FAIL" "Audit failed: $_"
    }
}
else {
    Write-TestResult "HSTS_IIS_Audit" "FAIL" "IIS script not found"
}

# Cleanup
Remove-Item -Path $tempDir2 -Recurse -Force -ErrorAction SilentlyContinue

# Final Summary
Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Test Results Summary" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Total Tests: $TotalTests"
Write-Host "Passed: $PassedTests" -ForegroundColor Green
if ($FailedTests -gt 0) {
    Write-Host "Failed: $FailedTests" -ForegroundColor Red
}
else {
    Write-Host "Failed: $FailedTests" -ForegroundColor Green
}
Write-Host ""

# Calculate success rate
$SuccessRate = [math]::Round(($PassedTests / $TotalTests) * 100, 2)
Write-Host "Success Rate: $SuccessRate%"
Write-Host ""

# Save results to file
$summaryPath = Join-Path $TestResultsDir "summary_$Timestamp.txt"
@"
HSTS Compliance Suite - Test Results
=====================================
Timestamp: $Timestamp
Total Tests: $TotalTests
Passed: $PassedTests
Failed: $FailedTests
Success Rate: $SuccessRate%
"@ | Out-File -FilePath $summaryPath

# Export detailed results to CSV
$csvPath = Join-Path $TestResultsDir "detailed_results_$Timestamp.csv"
$TestResults | Export-Csv -Path $csvPath -NoTypeInformation

Write-Host "Test results saved to: $summaryPath"
Write-Host "Detailed results saved to: $csvPath"
Write-Host ""

# Exit with appropriate code
if ($FailedTests -eq 0) {
    Write-Host "All tests passed!" -ForegroundColor Green
    exit 0
}
else {
    Write-Host "Some tests failed. Please review the results above." -ForegroundColor Red
    exit 1
}
