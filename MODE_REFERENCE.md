# HSTS Scripts - Mode Reference Guide

This document provides a quick reference for audit and configure modes across all HSTS patching scripts.

## Mode Overview

All HSTS patching scripts support two modes:

1. **Audit Mode** - Checks HSTS configuration compliance without making changes
2. **Configure Mode** - Fixes HSTS configuration to be OWASP compliant

## Windows - Apache Tomcat

**Script:** `src/windows/Patch/powershell/UpdateTomcatHstsWin.ps1`

### Audit Mode
```powershell
# Auto-detect and audit
.\src\windows\Patch\powershell\UpdateTomcatHstsWin.ps1 -Mode audit

# Audit with custom path
.\src\windows\Patch\powershell\UpdateTomcatHstsWin.ps1 -Mode audit -TomcatConfPath "C:\Tomcat\conf"

# Audit multiple paths
.\src\windows\Patch\powershell\UpdateTomcatHstsWin.ps1 -Mode audit -CustomPaths @("C:\Tomcat1\conf", "C:\Tomcat2\conf")
```

**Exit Codes:**
- `0` - HSTS is correctly configured
- `1` - HSTS is not correctly configured
- `2` - Error occurred

### Configure Mode
```powershell
# Auto-detect and configure
.\src\windows\Patch\powershell\UpdateTomcatHstsWin.ps1 -Mode configure

# Configure with custom path
.\src\windows\Patch\powershell\UpdateTomcatHstsWin.ps1 -Mode configure -TomcatConfPath "C:\Tomcat\conf"

# Preview changes (dry run)
.\src\windows\Patch\powershell\UpdateTomcatHstsWin.ps1 -Mode configure -DryRun
```

**Exit Codes:**
- `0` - Configuration applied successfully or already compliant
- `1` - Configuration failed
- `2` - Error occurred or user cancelled

## Windows - IIS

**Script:** `src/windows/Patch/powershell/UpdateIisHstsWin.ps1`

### Audit Mode
```powershell
# Auto-detect and audit
.\src\windows\Patch\powershell\UpdateIisHstsWin.ps1 -Mode audit

# Audit specific web.config
.\src\windows\Patch\powershell\UpdateIisHstsWin.ps1 -Mode audit -ConfigPath "C:\inetpub\wwwroot\web.config"

# Audit multiple paths
.\src\windows\Patch\powershell\UpdateIisHstsWin.ps1 -Mode audit -CustomPaths @("C:\App1\web.config", "C:\App2\web.config")
```

**Exit Codes:**
- `0` - HSTS is correctly configured
- `1` - HSTS is not correctly configured
- `2` - Error occurred

### Configure Mode
```powershell
# Auto-detect and configure
.\src\windows\Patch\powershell\UpdateIisHstsWin.ps1 -Mode configure

# Configure specific web.config
.\src\windows\Patch\powershell\UpdateIisHstsWin.ps1 -Mode configure -ConfigPath "C:\inetpub\wwwroot\web.config"

# Preview changes (dry run)
.\src\windows\Patch\powershell\UpdateIisHstsWin.ps1 -Mode configure -DryRun
```

**Exit Codes:**
- `0` - Configuration applied successfully or already compliant
- `1` - Configuration failed
- `2` - Error occurred or user cancelled

## Linux/Unix - Apache Tomcat

**Script:** `src/unix/Patch/bash/UpdateTomcatHstsUnix.sh`

### Audit Mode
```bash
# Auto-detect and audit
sudo ./src/unix/Patch/bash/UpdateTomcatHstsUnix.sh --mode audit

# Audit with custom path
sudo ./src/unix/Patch/bash/UpdateTomcatHstsUnix.sh --mode audit --custom-conf=/opt/tomcat/conf

# Audit multiple paths
sudo ./src/unix/Patch/bash/UpdateTomcatHstsUnix.sh --mode audit --custom-conf=/opt/tomcat1/conf --custom-conf=/opt/tomcat2/conf
```

**Exit Codes:**
- `0` - HSTS is correctly configured
- `1` - HSTS is not correctly configured
- `2` - Error occurred

### Configure Mode
```bash
# Auto-detect and configure
sudo ./src/unix/Patch/bash/UpdateTomcatHstsUnix.sh --mode configure

# Configure with custom path
sudo ./src/unix/Patch/bash/UpdateTomcatHstsUnix.sh --mode configure --custom-conf=/opt/tomcat/conf

# Preview changes (dry run)
sudo ./src/unix/Patch/bash/UpdateTomcatHstsUnix.sh --mode configure --dry-run
```

**Exit Codes:**
- `0` - Configuration applied successfully or already compliant
- `1` - Configuration failed
- `2` - Error occurred or user cancelled

## Mode Comparison

| Aspect | Audit Mode | Configure Mode |
|--------|-----------|----------------|
| **Purpose** | Check compliance | Fix compliance |
| **Makes Changes** | ❌ No | ✅ Yes (with confirmation) |
| **Backup Created** | ❌ No | ✅ Yes (automatic) |
| **Dry Run Support** | N/A | ✅ Yes |
| **User Confirmation** | ❌ No | ✅ Yes (for destructive operations) |
| **Exit Code 0** | Compliant | Success/Already Compliant |
| **Exit Code 1** | Non-Compliant | Failed |
| **Exit Code 2** | Error | Error/Cancelled |

## Recommended Workflow

1. **First, run Audit Mode** to check current state:
   ```bash
   # Linux
   sudo ./UpdateTomcatHstsUnix.sh --mode audit
   ```
   ```powershell
   # Windows Tomcat
   .\UpdateTomcatHstsWin.ps1 -Mode audit
   ```
   ```powershell
   # Windows IIS
   .\UpdateIisHstsWin.ps1 -Mode audit
   ```

2. **If non-compliant, preview changes with Dry Run**:
   ```bash
   # Linux
   sudo ./UpdateTomcatHstsUnix.sh --mode configure --dry-run
   ```
   ```powershell
   # Windows
   .\UpdateTomcatHstsWin.ps1 -Mode configure -DryRun
   ```

3. **Apply configuration**:
   ```bash
   # Linux
   sudo ./UpdateTomcatHstsUnix.sh --mode configure
   ```
   ```powershell
   # Windows
   .\UpdateTomcatHstsWin.ps1 -Mode configure
   ```

4. **Verify with Audit Mode again**:
   ```bash
   # Linux
   sudo ./UpdateTomcatHstsUnix.sh --mode audit
   ```

## Notes

- **Audit Mode** is read-only and safe to run anytime
- **Configure Mode** creates automatic backups before making changes
- **Dry Run** is only available in Configure Mode
- All scripts support auto-detection of installations
- Custom paths can override auto-detection
- Multiple paths can be specified for batch processing

For detailed documentation, see [README.md](README.md).

