# Testing Guide

## Overview

The HSTS Compliance Suite includes comprehensive automated testing to ensure 100% functionality across all platforms and scenarios.

## Test Structure

```
tests/
├── run_all_tests.sh          # Unix/Linux comprehensive test runner
├── Run-AllTests.ps1           # Windows comprehensive test runner
├── unix/
│   └── test_hsts_unix.sh     # Unix-specific HSTS tests
├── windows/
│   └── test_hsts_win.ps1     # Windows-specific HSTS tests
└── test-results/              # Generated test results (created automatically)
```

## Quick Start

### Run All Tests (Unix/Linux)

```bash
cd tests
sudo ./run_all_tests.sh
```

### Run All Tests (Windows)

```powershell
# Run as Administrator
cd tests
.\Run-AllTests.ps1
```

## What Gets Tested

### Automated Validation

1. **Syntax Validation**
   - All Bash scripts checked with `bash -n`
   - All PowerShell scripts parsed for syntax errors

2. **Functional Tests**
   - Audit mode execution
   - Configure mode execution
   - Dry-run mode
   - XML validation
   - Backup creation
   - Rollback functionality

3. **HSTS Compliance**
   - No HSTS header → Add compliant header
   - Non-compliant max-age → Fix to 31536000
   - Missing includeSubDomains → Add directive
   - Multiple headers → Consolidate to one
   - Already compliant → No changes

4. **Platform Support**
   - Tomcat (7.0, 8.5, 9.0, 10.0, 10.1, 11.0)
   - IIS (7.0+)
   - Jakarta EE namespace (Tomcat 11)
   - IIS Native HSTS (IIS 10+)

5. **Documentation**
   - All required docs present
   - Example files valid XML
   - Directory structure correct

## Test Results

### Output Locations

**Unix/Linux:**
- Summary: `test-results/summary_TIMESTAMP.txt`
- Detailed logs: `test-results/unix_tests_TIMESTAMP.log`

**Windows:**
- Summary: `test-results/summary_TIMESTAMP.txt`
- Detailed CSV: `test-results/detailed_results_TIMESTAMP.csv`
- Logs: `test-results/windows_tests_TIMESTAMP.log`

### Success Criteria

- ✅ All syntax validation passes
- ✅ All functional tests execute without errors
- ✅ HSTS compliance correctly detected and fixed
- ✅ XML files remain valid after modifications
- ✅ Backups created before changes
- ✅ Success rate: 100%

## CI/CD Integration

Tests run automatically on:
- Every push to `main` or `develop` branches
- Every pull request
- Manual workflow dispatch

### GitHub Actions Workflow

```yaml
- name: Run comprehensive Unix test suite
  run: |
    chmod +x tests/run_all_tests.sh
    cd tests
    ./run_all_tests.sh

- name: Run comprehensive Windows test suite
  shell: pwsh
  run: |
    Set-Location tests
    ./Run-AllTests.ps1
```

## Manual Testing

### Test Individual Scripts

**Unix - Tomcat:**
```bash
cd tests/unix
sudo ./test_hsts_unix.sh
```

**Windows - Tomcat:**
```powershell
cd tests\windows
.\test_hsts_win.ps1
```

### Test Specific Scenarios

Edit the test scripts to run only specific scenarios:

```bash
# In test_hsts_unix.sh, comment out scenarios you don't want to run
# test_scenario "No_HSTS_Header" ...
```

## Troubleshooting

### Tests Fail on Unix

1. **Permission Error:**
   ```bash
   sudo chmod +x tests/run_all_tests.sh
   sudo ./run_all_tests.sh
   ```

2. **xmllint Not Found:**
   ```bash
   # Ubuntu/Debian
   sudo apt-get install libxml2-utils
   
   # RHEL/CentOS
   sudo yum install libxml2
   ```

### Tests Fail on Windows

1. **Not Administrator:**
   - Right-click PowerShell → "Run as Administrator"

2. **Execution Policy:**
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
   ```

3. **Script Not Found:**
   ```powershell
   # Ensure you're in the tests directory
   cd path\to\HSTS_Compliance_Apache-Tomcat_IIS\tests
   ```

## Test Coverage

### Scenarios Covered

| Scenario | Tomcat (Unix) | Tomcat (Windows) | IIS (Windows) |
|----------|---------------|------------------|---------------|
| No HSTS | ✅ | ✅ | ✅ |
| Short max-age | ✅ | ✅ | ✅ |
| Missing includeSubDomains | ✅ | ✅ | ✅ |
| Already compliant | ✅ | ✅ | ✅ |
| Multiple headers | ✅ | ✅ | ✅ |
| Tomcat 11 Jakarta | ✅ | ✅ | N/A |
| IIS Native HSTS | N/A | N/A | ✅ |
| JSON output | ✅ | ✅ | ✅ |

### Exit Codes

- `0` - All tests passed
- `1` - Some tests failed (check logs)
- `2` - Script error (check syntax)

## Best Practices

1. **Run tests before committing** code changes
2. **Review test logs** for any warnings
3. **Update tests** when adding new features
4. **Keep test data** in `examples/` directory
5. **Document** any new test scenarios

## Performance

Expected test execution times:
- Unix comprehensive tests: ~30 seconds
- Windows comprehensive tests: ~45 seconds
- Individual scenario: ~2-5 seconds

## Support

For test failures or questions:
1. Check test logs in `test-results/`
2. Review [tests/README.md](README.md)
3. Open an issue on GitHub
