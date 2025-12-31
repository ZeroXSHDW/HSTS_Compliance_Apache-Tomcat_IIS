# HSTS Patching Tests

This directory contains test scripts for validating HSTS (HTTP Strict Transport Security) patching functionality across different platforms and web servers.

## Test Structure

```
tests/
├── README.md                    # This file
└── 
    ├── windows/
    │   └── test_hsts_win.ps1   # Windows tests for Tomcat and IIS
    └── unix/
        └── test_hsts_unix.sh   # Unix/Linux tests for Tomcat
```

## Test Scenarios

All test scripts validate the following scenarios:

1. **No HSTS Header** - Configuration with no HSTS header
   - Expected: Script should add compliant HSTS header

2. **Non-Compliant HSTS (Short MaxAge)** - HSTS with max-age less than 31536000
   - Expected: Script should replace with compliant HSTS header (max-age=31536000)

3. **Non-Compliant HSTS (No IncludeSubDomains)** - HSTS with correct max-age but missing includeSubDomains
   - Expected: Script should add includeSubDomains

4. **Compliant HSTS** - Already compliant HSTS configuration
   - Expected: Script should remain unchanged (already compliant)

5. **Multiple HSTS Headers** - Multiple HSTS header definitions (Windows only)
   - Expected: Script should remove duplicates and keep one compliant header

## Running Tests

### Windows Tests

**Prerequisites:**
- PowerShell 5.1 or later
- Administrator privileges
- HSTS patching scripts in `src/windows/powershell/`

**Run Tests:**
```powershell
# Run as Administrator
cd tests\windows
.\test_hsts_win.ps1
```

**Test Output:**
- Log file: `$env:TEMP\TestHstsWin.log`
- Test files: `$env:TEMP\HstsTest\`
- Backups: `$env:TEMP\HstsTestBackup\`

### Unix/Linux Tests

**Prerequisites:**
- Bash shell (version 4.0+)
- Sudo/root access
- HSTS patching script in `src/unix/`

**Run Tests:**
```bash
# Run as root or with sudo
cd tests/unix
sudo ./test_hsts_unix.sh
```

**Test Output:**
- Log file: `~/TestHstsUnix.log`
- Test files: `~/HstsTest/`
- Backups: `~/HstsTestBackup/`

## What Tests Validate

Each test scenario:

1. **Creates test configuration files** with specific HSTS states
2. **Runs audit mode** to check current compliance status
3. **Runs configure mode (dry run)** to preview changes without applying
4. **Validates expected behavior** based on the scenario

## Test Safety

- Tests use temporary directories and files
- Original configurations are backed up before modification
- Dry-run mode is used to preview changes without applying
- Test files are isolated from production configurations

## Troubleshooting

### Windows Tests Fail

- Ensure you're running PowerShell as Administrator
- Verify HSTS patching scripts exist in `src/windows/powershell/`
- Check log file for detailed error messages: `$env:TEMP\TestHstsWin.log`

### Unix Tests Fail

- Ensure you have sudo/root access
- Verify HSTS patching script exists and is executable: `src/unix/UpdateTomcatHstsUnix.sh`
- Check log file for detailed error messages: `~/TestHstsUnix.log`

### Permission Errors

- Windows: Run PowerShell as Administrator
- Unix: Run with `sudo` or as root

## Integration with CI/CD

These tests can be integrated into CI/CD pipelines:

**Windows (PowerShell):**
```powershell
$testResult = & .\tests\windows\test_hsts_win.ps1
if ($LASTEXITCODE -ne 0) { exit 1 }
```

**Unix (Bash):**
```bash
sudo ./tests/unix/test_hsts_unix.sh
if [ $? -ne 0 ]; then exit 1; fi
```

## Notes

- Tests are designed for **test environments only**
- Do not run tests on production systems
- Tests modify configuration files (though in isolated test directories)
- Always review test output and logs before deploying to production

