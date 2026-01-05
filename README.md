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
| **Windows IIS** | `max-age=31536000;` | `[PASS]` Compliant | `.\src\windows\UpdateIisHstsWin.ps1 -Mode audit` |
| (Local/Remote) | `includeSubDomains` | `[WARN]` Weak | `.\src\windows\UpdateIisHstsWin.ps1 -Mode configure -All` |
| **Windows Tomcat** | `max-age=31536000;` | `[FAIL]` Non-Compliant | `.\src\windows\UpdateTomcatHstsWin.ps1 -Mode audit` |
| (Local/Remote) | `includeSubDomains` | `[FAIL]` Missing / Conflict | `.\src\windows\UpdateTomcatHstsWin.ps1 -Mode configure -All` |
| **Linux Tomcat** | `max-age=31536000;` | `[PASS]` / `[FAIL]` | `sudo ./src/unix/UpdateTomcatHstsUnix.sh --mode audit` |
| (Local Only) | `includeSubDomains` | Standard Indicators | `sudo ./src/unix/UpdateTomcatHstsUnix.sh --mode configure --all` |

---


### 🛡️ Security Levels

* **Basic**: `max-age=1 Year`
* **High**: `max-age=1 Year` + `includeSubDomains` **(Recommended)**
* **Very High**: `max-age=1 Year` + `includeSubDomains` + `preload`
* **Maximum**: `max-age=2 Years` + `includeSubDomains` + `preload`

### 🌐 Remote Fleet Management

Audit or configure multiple servers via WinRM:

```powershell
.\src\windows\Remote_UpdateIisHstsWin.ps1 -ServerName "Web01","Web02" -Mode audit
.\src\windows\Remote_UpdateTomcatHstsWin.ps1 -ServerName "App01","App02" -Mode configure -SecurityLevel maximum
```

---

<p align="center">
  2025 HSTS Compliance Suite • <a href="LICENSE">MIT License</a>
</p>
