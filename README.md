<div align="center">

<img src="assets/images/banner.png" alt="HSTS Compliance Suite Banner" width="100%" />

# HSTS Compliance Suite

## Enterprise-Grade Security Automation for Apache Tomcat & Microsoft IIS

</div>

---

## ⚡ HSTS Compliance Matrix

The complete reference for auditing and configuring HSTS across your infrastructure.

| Component | Standard (OWASP High) | Indicators | Quick Command (Audit/Configure) |
| :--- | :--- | :--- | :--- |
| **Windows IIS** | `max-age=31536000;` | `[PASS]` Compliant | **Audit:** `.\src\windows\UpdateIisHstsWin.ps1 -Mode audit` |
| (Local/Remote) | `includeSubDomains` | `[WARN]` Weak | **Configure:** `.\src\windows\UpdateIisHstsWin.ps1 -Mode configure -All` |
|  |  | `[FAIL]` Non-Compliant | **Remote:** `.\src\windows\Remote_UpdateIisHstsWin.ps1 -ServerName "Web01" -Mode audit` |
| **Windows Tomcat** | `max-age=31536000;` | `[PASS]` / `[FAIL]` | **Audit:** `.\src\windows\UpdateTomcatHstsWin.ps1 -Mode audit` |
| (Local/Remote) | `includeSubDomains` | Standard Indicators | **Configure:** `.\src\windows\UpdateTomcatHstsWin.ps1 -Mode configure -SecurityLevel high` |
|  |  |  | **Remote:** `.\src\windows\Remote_UpdateTomcatHstsWin.ps1 -ServerName "App01" -Mode audit` |
| **Linux Tomcat** | `max-age=31536000;` | `[PASS]` / `[FAIL]` | **Audit:** `sudo ./src/unix/UpdateTomcatHstsUnix.sh --mode audit` |
| (Local Only) | `includeSubDomains` | Standard Indicators | **Configure:** `sudo ./src/unix/UpdateTomcatHstsUnix.sh --mode configure --security-level high` |

---

### 🛡️ Security Levels

* **Basic**: `max-age=1 Year`
* **High**: `max-age=1 Year` + `includeSubDomains` **(Recommended)**
* **Very High**: `max-age=1 Year` + `includeSubDomains` + `preload`
* **Maximum**: `max-age=2 Years` + `includeSubDomains` + `preload`

**Configuration Examples:**

```powershell
# Windows - Configure IIS with High security (recommended)
.\src\windows\UpdateIisHstsWin.ps1 -Mode configure -SecurityLevel high -All

# Windows - Configure Tomcat with Maximum security
.\src\windows\UpdateTomcatHstsWin.ps1 -Mode configure -SecurityLevel maximum

# Linux - Configure Tomcat with Very High security (preload ready)
sudo ./src/unix/UpdateTomcatHstsUnix.sh --mode configure --security-level veryhigh

# Dry-run mode (preview changes without applying)
.\src\windows\UpdateIisHstsWin.ps1 -Mode configure -SecurityLevel high -All -DryRun
sudo ./src/unix/UpdateTomcatHstsUnix.sh --mode configure --security-level high --dry-run
```

---

### 🧪 Testing & Validation

#### Automated Test Suites

**Linux/Unix Testing:**

```bash
# Run complete Unix test suite (audit, configure, dry-run, JSON reporting)
cd tests/unix
bash test_hsts_unix.sh

# Run enhanced audit verification
bash verify_enhanced_audit_unix.sh
```

**Windows Testing (PowerShell):**

```powershell
# Run complete Windows test suite (requires PowerShell 5.1+)
cd tests
.\Run-AllTests.ps1

# Run enhanced audit verification
.\windows\verify_enhanced_audit_win.ps1

# Run version matrix tests (Tomcat 7-11, IIS 7-10)
.\version_matrix_test.ps1
```

#### Manual Validation Examples

**IIS Audit:**

```powershell
# Audit all IIS sites
.\src\windows\UpdateIisHstsWin.ps1 -Mode audit

# Expected output:
# [PASS] site1\web.config [COMPLIANT] - max-age=31536000, includeSubDomains=true
# [FAIL] site2\web.config [NOT CONFIGURED] - No HSTS headers found
```

**Tomcat Audit:**

```bash
# Linux - Audit Tomcat installation
sudo ./src/unix/UpdateTomcatHstsUnix.sh --mode audit

# Expected output:
# [PASS] web.xml [COMPLIANT] - max-age=31536000, includeSubDomains=true
# [WARN] web.xml [WEAK] - max-age=31536000 (missing includeSubDomains)
# [FAIL] web.xml [NON-COMPLIANT] - max-age=86400 (too short)
```

**Example Output - Apache Tomcat Audit (Linux/Unix):**

```text
Checking Tomcat HSTS Configuration...
############################server-hostname############################
Execution Time: 2026-01-05 15:06:54
HOSTNAME: server-hostname
===========================

HSTS Compliance Results:
File                                     | Status          | Details
-----------------------------------------+-----------------+-----------------------------------------
web.xml                                  | Not Configured  | No HSTS filters found

===========================
Overall Status: Non-Compliant (0 Compliant, 0 Non-Compliant, 1 Not Configured)
Audit completed. Log: /var/log/tomcat-hsts-20260105_150654.log
```

**Example Output - Apache Tomcat Configure (Linux/Unix):**

```text
Checking Tomcat HSTS Configuration...
############################server-hostname############################
Execution Time: 2026-01-05 15:07:20
HOSTNAME: server-hostname
===========================

Found Tomcat Configuration: /opt/tomcat/conf (Version: 9.0.50)
Searching for web.xml files...
  Found: /opt/tomcat/conf/web.xml (global configuration)
Found 1 web.xml file(s) to process

=========================================
Processing: /opt/tomcat/conf/web.xml
=========================================
Found 1 HSTS header definition(s)
=== Current Filter-Based HSTS Configuration ===
  hstsMaxAgeSeconds: 86400
  hstsIncludeSubDomains: false
===============================================
=== Audit Result Breakdown ===
  [FAIL] Filter-based HSTS (Target Level: high): max-age=86400; includeSubDomains=false; preload=false
==============================
Current state: Non-compliant HSTS configuration found: 1 failed issues.
Configuration required: Ensuring exactly one compliant HSTS definition exists
Running pre-flight checks...
Pre-flight checks passed
Backup created: /opt/tomcat/conf/web.xml.backup.20260105_150720
Compliant HSTS configuration applied successfully. All duplicate/non-compliant headers removed.

=========================================
Summary
=========================================
Total files processed: 1
Successful: 1
Failed: 0
Overall Status: SUCCESS
Log file: /var/log/tomcat-hsts-20260105_150720.log
```

**Configuration with Verification:**

```powershell
# Step 1: Audit current state
.\src\windows\UpdateIisHstsWin.ps1 -Mode audit

# Step 2: Preview changes (dry-run)
.\src\windows\UpdateIisHstsWin.ps1 -Mode configure -SecurityLevel high -All -DryRun

# Step 3: Apply configuration
.\src\windows\UpdateIisHstsWin.ps1 -Mode configure -SecurityLevel high -All

# Step 4: Verify configuration was applied
.\src\windows\UpdateIisHstsWin.ps1 -Mode audit
```

---

### 🔑 Remote Fleet Management

For managing multiple servers, ensure WinRM is configured and target hosts are trusted:

```powershell
# 1. Add servers to TrustedHosts (Required for non-domain environments)
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "Web01,App02,Web03" -Force

# 2. Audit remote IIS fleet
$creds = Get-Credential
.\src\windows\Remote_UpdateIisHstsWin.ps1 -ServerName "Web01" -Mode audit -Credential $creds

# 3. Configure remote Tomcat fleet
.\src\windows\Remote_UpdateTomcatHstsWin.ps1 -ServerName "App01" -Mode configure -SecurityLevel high -Credential $creds

# 4. Batch processing with server list file
# Create servers.txt with one server name per line
.\src\windows\Remote_UpdateIisHstsWin.ps1 -ServerListFile "servers.txt" -Mode audit -Credential $creds
```

**Example Output - Remote Tomcat Audit:**

```text
Executing on remote server: App01
========================================

Tomcat Configuration Directory: C:\Program Files\Apache Software Foundation\Tomcat 9.0\conf (Version: 9.0.50)
Found 1 web.xml file(s) to process

Scanning files for HSTS compliance...

  [PASS] web.xml [COMPLIANT] - max-age=31536000, includeSubDomains=true

+------------------------------------------------------+
|            HSTS COMPLIANCE SUMMARY                   |
+------------------------------------------------------+
| Files Scanned:                                     1 |
| [PASS] Compliant:        1 (100%)                    |
| [FAIL] Not Configured:   0 (0%)                      |
| [WARN] Non-Compliant:    0 (0%)                      |
+------------------------------------------------------+

Remote execution completed successfully
```

**Example Output - Remote Tomcat Configure:**

```text
Executing on remote server: App01
========================================

Tomcat Configuration Directory: C:\Program Files\Apache Software Foundation\Tomcat 9.0\conf (Version: 9.0.50)
Found 1 web.xml file(s) to process

Processing: C:\Program Files\Apache Software Foundation\Tomcat 9.0\conf\web.xml
Current state: Non-compliant HSTS configuration found: 1 failed issues.
Configuration required: Ensuring exactly one compliant HSTS definition exists
Backup created: C:\Program Files\Apache Software Foundation\Tomcat 9.0\conf\web.xml.backup.20260105_150245
Compliant HSTS configuration applied successfully. All duplicate/non-compliant headers removed.

+------------------------------------------------------+
|            HSTS COMPLIANCE SUMMARY                   |
+------------------------------------------------------+
| Files Scanned:                                     1 |
| [+] Successful:                                    1 |
| [-] Failed:                                        0 |
+------------------------------------------------------+

[PASS] Overall Status: SUCCESS
Remote execution completed successfully
```

**Example Output - Remote IIS Audit:**

```text
Executing on remote server: Web01
========================================

IIS Version: 10.0
Found 3 IIS site(s) to process

Scanning files for HSTS compliance...

  [PASS] Default Web Site\web.config [COMPLIANT] - max-age=31536000, includeSubDomains=true
  [FAIL] App1\web.config [NOT CONFIGURED] - No HSTS headers found
  [WARN] App2\web.config [WEAK] - max-age=31536000 (missing includeSubDomains)

+------------------------------------------------------+
|            HSTS COMPLIANCE SUMMARY                   |
+------------------------------------------------------+
| Files Scanned:                                     3 |
| [PASS] Compliant:        1 (33%)                     |
| [FAIL] Not Configured:   1 (33%)                     |
| [WARN] Non-Compliant:    1 (33%)                     |
+------------------------------------------------------+

Remote execution completed successfully
```

**Example Output - Remote IIS Configure:**

```text
Executing on remote server: Web01
========================================

IIS Version: 10.0
Found 3 IIS site(s) to process

Processing: C:\inetpub\wwwroot\web.config
Current state: HSTS is correctly configured with exactly one compliant definition.
SUCCESS: HSTS is already correctly configured

Processing: C:\inetpub\App1\web.config
Current state: No HSTS header definitions found in configuration
Backup created: C:\inetpub\App1\web.config.backup.20260105_150430
Compliant HSTS configuration applied successfully

Processing: C:\inetpub\App2\web.config
Current state: Non-compliant HSTS configuration found: 1 failed issues.
Backup created: C:\inetpub\App2\web.config.backup.20260105_150431
Compliant HSTS configuration applied successfully

+------------------------------------------------------+
|            HSTS COMPLIANCE SUMMARY                   |
+------------------------------------------------------+
| Files Scanned:                                     3 |
| [+] Successful:                                    3 |
| [-] Failed:                                        0 |
+------------------------------------------------------+

[PASS] Overall Status: SUCCESS
Remote execution completed successfully
```

---

### ✅ Pre-Publication Validation Checklist

Before deploying to production, validate all functionality:

* [ ] **Unix/Linux Tests**: Run `bash tests/unix/test_hsts_unix.sh` - all tests pass
* [ ] **Unix Audit Verification**: Run `bash tests/unix/verify_enhanced_audit_unix.sh` - all scenarios pass
* [ ] **Windows Tests**: Run `.\tests\Run-AllTests.ps1` - all tests pass (requires Windows Server)
* [ ] **Manual IIS Audit**: Verify audit mode detects HSTS configurations correctly
* [ ] **Manual Tomcat Audit**: Verify audit mode detects HSTS configurations correctly
* [ ] **Dry-Run Mode**: Verify dry-run shows changes without applying them
* [ ] **Configuration Mode**: Verify configure mode applies HSTS correctly
* [ ] **Rollback Testing**: Verify automatic rollback on validation failure
* [ ] **Remote Execution**: Verify remote scripts work with WinRM
* [ ] **JSON Reporting**: Verify `--json` flag produces valid JSON output

**Quick Validation Commands:**

```bash
# Linux - Full validation
cd tests/unix && bash test_hsts_unix.sh && bash verify_enhanced_audit_unix.sh

# Windows - Full validation (PowerShell)
cd tests; .\Run-AllTests.ps1; .\windows\verify_enhanced_audit_win.ps1
```

---

<p align="center">
  © 2025 HSTS Compliance Suite • <a href="LICENSE">MIT License</a>
</p>
