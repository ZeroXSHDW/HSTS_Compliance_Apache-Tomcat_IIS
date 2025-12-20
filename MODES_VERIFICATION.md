# HSTS Scripts - Audit & Configure Modes Verification

## ✅ Verification Complete - All Modes Available

All HSTS patching scripts support both **Audit** and **Configure** modes as required.

## Windows - Apache Tomcat

**Script:** `src/windows/Patch/powershell/UpdateTomcatHstsWin.ps1`

### ✅ Audit Mode
- **Status:** Fully Implemented
- **Usage:** `-Mode audit`
- **Function:** `Audit-HstsHeaders` (line 309)
- **Implementation:** Lines 441-454
- **Exit Codes:** 0 (compliant), 1 (non-compliant), 2 (error)

### ✅ Configure Mode
- **Status:** Fully Implemented
- **Usage:** `-Mode configure`
- **Functions:** `Audit-HstsHeaders`, `Apply-CompliantHsts`, `Backup-Config`
- **Implementation:** Lines 455-494
- **Exit Codes:** 0 (success), 1 (failed), 2 (error/cancelled)

**Example:**
```powershell
# Audit
.\src\windows\Patch\powershell\UpdateTomcatHstsWin.ps1 -Mode audit

# Configure
.\src\windows\Patch\powershell\UpdateTomcatHstsWin.ps1 -Mode configure
```

## Windows - IIS

**Script:** `src/windows/Patch/powershell/UpdateIisHstsWin.ps1`

### ✅ Audit Mode
- **Status:** Fully Implemented
- **Usage:** `-Mode audit`
- **Function:** `Audit-HstsHeaders` (line 424)
- **Implementation:** Lines 809-820
- **Exit Codes:** 0 (compliant), 1 (non-compliant), 2 (error)

### ✅ Configure Mode
- **Status:** Fully Implemented
- **Usage:** `-Mode configure`
- **Functions:** `Audit-HstsHeaders`, `Apply-CompliantHsts`, `Backup-Config`
- **Implementation:** Lines 822-860
- **Exit Codes:** 0 (success), 1 (failed), 2 (error/cancelled)

**Example:**
```powershell
# Audit
.\src\windows\Patch\powershell\UpdateIisHstsWin.ps1 -Mode audit

# Configure
.\src\windows\Patch\powershell\UpdateIisHstsWin.ps1 -Mode configure
```

## Linux/Unix - Apache Tomcat

**Script:** `src/unix/Patch/bash/UpdateTomcatHstsUnix.sh`

### ✅ Audit Mode
- **Status:** Fully Implemented
- **Usage:** `--mode audit`
- **Function:** `audit_hsts_headers` (line 246)
- **Implementation:** Lines 885-895
- **Exit Codes:** 0 (compliant), 1 (non-compliant), 2 (error)

### ✅ Configure Mode
- **Status:** Fully Implemented
- **Usage:** `--mode configure`
- **Functions:** `audit_hsts_headers`, `configure_hsts_headers`, `backup_config`
- **Implementation:** Lines 897-945
- **Exit Codes:** 0 (success), 1 (failed), 2 (error/cancelled)

**Example:**
```bash
# Audit
sudo ./src/unix/Patch/bash/UpdateTomcatHstsUnix.sh --mode audit

# Configure
sudo ./src/unix/Patch/bash/UpdateTomcatHstsUnix.sh --mode configure
```

## Summary

| Platform | Server | Script | Audit Mode | Configure Mode |
|----------|--------|--------|------------|----------------|
| **Windows** | Apache Tomcat | UpdateTomcatHstsWin.ps1 | ✅ | ✅ |
| **Windows** | IIS | UpdateIisHstsWin.ps1 | ✅ | ✅ |
| **Linux/Unix** | Apache Tomcat | UpdateTomcatHstsUnix.sh | ✅ | ✅ |

## Verification Results

✅ **All Required Modes Implemented:**
- ✅ Windows Apache Tomcat - Audit Mode
- ✅ Windows Apache Tomcat - Configure Mode
- ✅ Windows IIS - Audit Mode
- ✅ Windows IIS - Configure Mode
- ✅ Linux/Unix Apache Tomcat - Audit Mode
- ✅ Linux/Unix Apache Tomcat - Configure Mode

## Quick Reference

### Windows Tomcat
```powershell
# Audit
.\src\windows\Patch\powershell\UpdateTomcatHstsWin.ps1 -Mode audit

# Configure
.\src\windows\Patch\powershell\UpdateTomcatHstsWin.ps1 -Mode configure
```

### Windows IIS
```powershell
# Audit
.\src\windows\Patch\powershell\UpdateIisHstsWin.ps1 -Mode audit

# Configure
.\src\windows\Patch\powershell\UpdateIisHstsWin.ps1 -Mode configure
```

### Linux/Unix Tomcat
```bash
# Audit
sudo ./src/unix/Patch/bash/UpdateTomcatHstsUnix.sh --mode audit

# Configure
sudo ./src/unix/Patch/bash/UpdateTomcatHstsUnix.sh --mode configure
```

## Documentation

- **Quick Start:** See [README.md](README.md#quick-start)
- **Complete Mode Reference:** See [MODE_REFERENCE.md](MODE_REFERENCE.md)
- **Command Reference:** See [README.md](README.md#command-reference)

---

**Status:** ✅ **ALL MODES VERIFIED AND OPERATIONAL**

