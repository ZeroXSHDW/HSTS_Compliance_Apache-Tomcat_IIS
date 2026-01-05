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

```powershell
# Windows - Audit Tomcat installation
.\src\windows\UpdateTomcatHstsWin.ps1 -Mode audit

# Linux - Audit Tomcat installation
sudo ./src/unix/UpdateTomcatHstsUnix.sh --mode audit

# Expected output:
# [PASS] web.xml [COMPLIANT] - max-age=31536000, includeSubDomains=true
# [WARN] web.xml [WEAK] - max-age=31536000 (missing includeSubDomains)
# [FAIL] web.xml [NON-COMPLIANT] - max-age=86400 (too short)
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
