<div align="center">

<img src="assets/images/banner.png" alt="HSTS Compliance Suite Banner" width="100%" />

# HSTS Compliance Suite
### Enterprise-Grade Security Automation for Apache Tomcat & Microsoft IIS

[![License](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey.svg?style=for-the-badge)](docs/INSTALLATION.md)
[![Status](https://img.shields.io/badge/Status-Production%20%7C%20Enterprise-success.svg?style=for-the-badge)](docs/PROJECT_STATUS.md)
[![Security Rating](https://img.shields.io/badge/Security-A%2B-green.svg?style=for-the-badge)](docs/SECURITY.md)

</div>

<p align="center">
  <b>🛡️ Automate. Secure. Comply.</b><br>
  The professional solution for auditing and enforcing OWASP HSTS compliance across mixed enterprise server fleets.
</p>

---

## 🛡️ Security Levels (OWASP Compliance)

This suite enforces HSTS based on 4 standardized security tiers. **High** is the recommended default.

| Level | `max-age` | `includeSubDomains` | `preload` | Description |
|-------|-----------|--------------------|-----------|-------------|
| `basic` | 1 Year | No | No | Minimum standard. |
| **`high`** | **1 Year** | **✅ Yes** | **No** | **Recommended Standard (OWASP Compliant).** |
| `veryhigh` | 1 Year | ✅ Yes | ✅ Yes | High security with preloading enabled. |
| `maximum` | 2 Years | ✅ Yes | ✅ Yes | Maximum possible security. |

---

## 🚀 Quick Start (The "Golden Path")

### 1. Audit (Check Status)
Run these commands to see if your servers are compliant. No changes will be made.

**Linux / Unix (Tomcat)**
```bash
sudo ./src/unix/UpdateTomcatHstsUnix.sh --mode audit
```

**Windows (IIS & Tomcat)**
```powershell
# Audit Tomcat
.\src\windows\UpdateTomcatHstsWin.ps1 -Mode audit

# Audit IIS
.\src\windows\UpdateIisHstsWin.ps1 -Mode audit
```

### 2. Configure (Fix All)
Automatically fix all discovered installations to meet OWASP standards (Level: High).

**Linux / Unix (Tomcat)**
```bash
# Configure ALL found instances
sudo ./src/unix/UpdateTomcatHstsUnix.sh --mode configure --all
```

**Windows (IIS & Tomcat)**
```powershell
# Configure ALL found Tomcat instances
.\src\windows\UpdateTomcatHstsWin.ps1 -Mode configure -All

# Configure ALL found IIS sites
.\src\windows\UpdateIisHstsWin.ps1 -Mode configure -All
```

> **Note:** The `-All` / `--all` flag ensures that **every** configuration found is updated. Without it, you may need to specify paths manually or rely on default single-instance behavior.

---

## ⚡ Features

*   **Auto-Discovery**: Automatically finds multiple Tomcat versions and IIS sites on a single host.
*   **Idempotency**: Safely re-runs without creating duplicate headers. Guarantees exactly one compliant definition.
*   **Self-Healing**: Detects and fixes broken or partial configurations ("Compliance Drift").
*   **Safety First**: Creates timestamped backups before every change. Supports Dry Run previews.
*   **Enterprise Reporting**: Outputs JSON/CSV for SIEM integration or compliance audits.
*   **Remote Execution**: Push HSTS configurations to hundreds of Windows servers via WinRM.

---

## 📋 Platform Support

| Platform | Server Type | Supported | Script Location |
|----------|-------------|-----------|-----------------|
| **Windows** | IIS | ✅ | `src/windows/UpdateIisHstsWin.ps1` |
| **Windows** | Apache Tomcat | ✅ | `src/windows/UpdateTomcatHstsWin.ps1` |
| **Linux/Unix** | Apache Tomcat | ✅ | `src/unix/UpdateTomcatHstsUnix.sh` |

---

## 🔧 Advanced Usage

### Remote Execution (Windows)
Audit or configure a fleet of servers using PowerShell Remoting.

```powershell
# Audit multiple servers
$cred = Get-Credential
.\src\windows\Remote_UpdateTomcatHstsWin.ps1 -ServerName "Server01","Server02" -Mode audit -Credential $cred

# Configure ALL servers (Tomcat)
.\src\windows\Remote_UpdateTomcatHstsWin.ps1 -ServerName "Server01","Server02" -Mode configure -All -Credential $cred

# Configure ALL servers (IIS)
.\src\windows\Remote_UpdateIisHstsWin.ps1 -ServerName "Web01","Web02" -Mode configure -All -Credential $cred
```

### JSON Reporting (SIEM Integration)
Generate machine-readable logs for Splunk, ELK, or other dashboards.

```bash
# Linux
sudo ./src/unix/UpdateTomcatHstsUnix.sh --mode audit --json --report-file=/var/log/hsts.json
```

```powershell
# Windows
.\src\windows\UpdateIisHstsWin.ps1 -Mode audit -OutputFormat json -ReportPath "C:\logs\hsts.json"
```

---

## 📚 Documentation
*   [Installation Guide](docs/INSTALLATION.md)
*   [Verification Guide](docs/VERIFICATION.md)
*   [Security Policy](docs/SECURITY.md)

---

<p align="center">
  2025 HSTS Compliance Suite • <a href="LICENSE">MIT License</a>
</p>
