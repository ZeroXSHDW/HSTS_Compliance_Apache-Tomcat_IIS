<div align="center">

<img src="assets/images/banner.png" alt="HSTS Compliance Suite Banner" width="100%" />

# HSTS Compliance Suite
### Enterprise-Grade Security Automation for Apache Tomcat & Microsoft IIS

</div>

---

## ⚡ HSTS Compliance Matrix

The complete reference for auditing and configuring HSTS across your infrastructure.

| Component | standard (OWASP High) | Indicators | Quick Command (Audit/Fix) |
| :--- | :--- | :--- | :--- |
| **Windows IIS** | `max-age=31536000;` | `[PASS]` Compliant | **Local:** `.\src\windows\UpdateIisHstsWin.ps1` <br> **Remote:** `.\src\windows\Remote_UpdateIisHstsWin.ps1` |
| (Local/Remote) | `includeSubDomains` | `[WARN]` Weak | *Args: `-Mode audit` or `-Mode configure -All`* |
| **Windows Tomcat** | `max-age=31536000;` | `[FAIL]` Non-Compliant | **Local:** `.\src\windows\UpdateTomcatHstsWin.ps1` <br> **Remote:** `.\src\windows\Remote_UpdateTomcatHstsWin.ps1` |
| (Local/Remote) | `includeSubDomains` | `[FAIL]` Missing / Conflict | *Args: `-Mode audit` or `-Mode configure -All`* |
| **Linux Tomcat** | `max-age=31536000;` | `[PASS]` / `[FAIL]` | **Local:** `sudo ./src/unix/UpdateTomcatHstsUnix.sh` <br> **Remote:** N/A (Local Only) |
| (Local Only) | `includeSubDomains` | Standard Indicators | *Args: `--mode audit` or `--mode configure --all`* |

---

### 🛡️ Security Levels

* **Basic**: `max-age=1 Year`
* **High**: `max-age=1 Year` + `includeSubDomains` **(Recommended)**
* **Very High**: `max-age=1 Year` + `includeSubDomains` + `preload`
* **Maximum**: `max-age=2 Years` + `includeSubDomains` + `preload`

### 🔑 Remote Prerequisites

For fleet management, ensure WinRM is configured and target hosts are trusted:

```powershell
# 1. Add servers to TrustedHosts (Required for non-domain environments)
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "Web01,App02" -Force

# 2. Audit remote fleet with credentials
$creds = Get-Credential
.\src\windows\Remote_UpdateIisHstsWin.ps1 -ServerName "Web01" -Mode audit -Credential $creds
```

---

<p align="center">
  2025 HSTS Compliance Suite • <a href="LICENSE">MIT License</a>
</p>
