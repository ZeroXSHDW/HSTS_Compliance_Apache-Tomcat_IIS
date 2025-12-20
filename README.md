# HSTS Compliance Tools - Apache Tomcat & IIS

A comprehensive set of tools for auditing and configuring HTTP Strict Transport Security (HSTS) headers in Apache Tomcat and Microsoft IIS web servers. This project focuses exclusively on HSTS compliance and patching across Linux and Windows platforms.

## Table of Contents

- [Overview](#overview)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation Instructions](#installation-instructions)
- [Quick Start](#quick-start)
- [Usage Examples](#usage-examples-with-output)
- [Auto-Detection](#auto-detection)
- [Command Reference](#command-reference)
- [Exit Codes](#exit-codes)
- [Security Notes](#security-notes)
- [Troubleshooting](#troubleshooting)
- [Best Practices](#best-practices)
- [Testing](#testing)
- [Advanced Usage](#advanced-usage)
- [Code Review Summary](#code-review-summary)
- [License](#license)
- [Contributing](#contributing)

## Overview

This project provides scripts to audit and configure HSTS headers for compliance with security best practices as defined in the **OWASP HSTS Cheat Sheet** (RFC 6797).

**OWASP Recommended Configuration:**
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

**Reference:** [OWASP HSTS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)

### Compliance Requirements

This implementation follows OWASP recommendations:
- ✅ **Required**: `max-age=31536000` (1 year = 365 days × 24 hours × 60 minutes × 60 seconds)
- ✅ **Required**: `includeSubDomains` (prevents cookie-related attacks from subdomains)
- ℹ️ **Optional**: `preload` directive (allowed but not configured by default - see [Preload Considerations](#preload-considerations) below)

**Key Features:**

**Core Functionality:**
- ✅ **Auto-Detection**: Automatically finds Tomcat and IIS installations across common paths
- ✅ **Audit Mode**: Check if HSTS is correctly configured without making changes
- ✅ **Configure Mode**: Automatically fix HSTS configuration to be OWASP compliant
- ✅ **Backup Support**: Automatically creates timestamped backups before making changes
- ✅ **Dry Run**: Preview changes without applying them (configure mode only)
- ✅ **XML Validation**: Validates XML structure before and after modifications
- ✅ **Idempotency**: Ensures exactly one compliant HSTS definition (removes duplicates)

**Flexibility & Control:**
- ✅ **Custom Paths**: Specify single or multiple custom configuration paths
- ✅ **Paths File Support**: Load multiple paths from a file (one per line, comments supported)
- ✅ **Multiple File Processing**: Automatically processes all web.xml/web.config files in detected installations
- ✅ **Selective Processing**: Target specific files or directories as needed
- ✅ **Environment Variable Support**: Unix scripts check CATALINA_BASE and CATALINA_HOME

**Remote & Enterprise Features:**
- ✅ **Remote Execution**: Windows scripts support remote execution via PowerShell Remoting (WinRM)
- ✅ **Server List Files**: Execute on multiple servers using server list files (comments supported)
- ✅ **Batch Operations**: Process multiple servers simultaneously with credential management
- ✅ **Parallel Processing**: Remote scripts can process multiple servers in sequence

**Platform & Compatibility:**
- ✅ **Cross-Platform**: Bash scripts for Unix/Linux servers, PowerShell for Windows Server
- ✅ **Version Support**: Works with all versions of Tomcat (7.0+) and IIS (7.0+)
- ✅ **Installation Scripts**: Automated Tomcat installation for Windows and Unix/Linux (versions 7.0, 8.5, 9.0, 10.0, 10.1)
- ✅ **Java Auto-Installation**: Installation scripts automatically install required Java versions

**Quality & Safety:**
- ✅ **Test Suite**: Comprehensive test scripts for validating HSTS patching functionality (5 scenarios Windows, 4 scenarios Unix)
- ✅ **Logging**: Detailed logging to files and console with timestamps and hostname
- ✅ **Error Handling**: Comprehensive error handling with clear exit codes (0=success, 1=failure, 2=error)
- ✅ **Security Validations**: Path traversal protection, null byte detection, symlink/junction detection, permission checks
- ✅ **User Confirmation**: Interactive prompts for destructive operations
- ✅ **Example Files**: Provided example configuration files for testing

## Project Structure

```
.
├── README.md                    # Main documentation (this file)
├── INSTALLATION.md              # Installation guide for Tomcat, IIS, and PowerShell Remoting
├── LICENSE                      # MIT License
├── CONTRIBUTING.md              # Contribution guidelines
├── .gitignore                   # Git ignore patterns
├── assets/                      # Project assets
│   └── images/
│       └── banner.jpg          # Project banner image
├── install/                     # Installation scripts for Tomcat
│   ├── README.md               # Installation script documentation
│   ├── windows/
│   │   └── TomcatManager.ps1   # Windows Tomcat installation script (supports 7.0, 8.5, 9.0, 10.0, 10.1)
│   └── unix/
│       └── tomcat_manager.sh   # Unix/Linux Tomcat installation script (supports 7.0, 8.5, 9.0, 10.0, 10.1)
├── src/                         # HSTS patching scripts
│   ├── unix/
│   │   └── Patch/
│   │       └── bash/
│   │           └── UpdateTomcatHstsUnix.sh    # Unix/Linux Tomcat HSTS script (auto-detect, custom paths)
│   └── windows/
│       └── Patch/
│           └── powershell/
│               ├── UpdateTomcatHstsWin.ps1           # Windows Tomcat HSTS script (local execution)
│               ├── Remote_UpdateTomcatHstsWin.ps1    # Windows Tomcat HSTS script (remote execution)
│               ├── UpdateIisHstsWin.ps1              # Windows IIS HSTS script (local execution)
│               └── Remote_UpdateIisHstsWin.ps1       # Windows IIS HSTS script (remote execution)
├── tests/                       # Test scripts for HSTS patching
│   ├── README.md               # Test documentation and usage guide
│   └── Patch/
│       ├── windows/
│       │   └── test_hsts_win.ps1   # Windows HSTS tests (Tomcat and IIS, 5 scenarios)
│       └── unix/
│           └── test_hsts_unix.sh   # Unix/Linux HSTS tests (Tomcat, 4 scenarios)
└── examples/                    # Example configuration files for testing
    ├── README.md               # Examples usage guide
    ├── test_web.xml            # Example Tomcat web.xml (minimal configuration)
    ├── test_web.config         # Example IIS web.config (minimal configuration)
    └── web.xml                 # Additional Tomcat web.xml example
```

## Prerequisites

### For Tomcat (Unix/Linux Servers)
- Bash shell (version 4.0+)
- Apache Tomcat installed (version 7.0 or later)
- Root or sudo access for configuration changes
- Optional: `xmllint` for XML validation, `diff` for dry-run preview
- **Note:** Scripts are designed for Linux/Unix server environments only (not macOS)

### For Tomcat (Windows Server)
- PowerShell 5.1 or later
- Apache Tomcat installed (version 7.0 or later)
- Administrator privileges
- For remote execution: PowerShell Remoting (WinRM) enabled and configured

### For IIS (Windows Server)
- PowerShell 5.1 or later
- IIS installed (version 7.0 or later)
- Administrator privileges
- For remote execution: PowerShell Remoting (WinRM) enabled and configured

## Installation Instructions

### Automated Tomcat Installation

For automated installation of Apache Tomcat on Windows or Unix/Linux systems, use the installation scripts provided in the `install/` directory. These scripts handle download, extraction, Java setup, secure user configuration, and service management.

**Windows:**
```powershell
# Run as Administrator
cd install\windows
.\TomcatManager.ps1 -Action install -TomcatVersion 10.1
```

**Unix/Linux:**
```bash
# Run as root or with sudo
cd install/unix
sudo ./tomcat_manager.sh -v 10.1
```

See [install/README.md](install/README.md) for full installation script documentation and usage examples.

### Manual Installation

For detailed manual installation instructions for Apache Tomcat, IIS, and PowerShell Remoting configuration, please see the **[INSTALLATION.md](INSTALLATION.md)** file.

**Quick Summary:**
- **Apache Tomcat**: Download Windows Service Installer from https://tomcat.apache.org or use the installation scripts
- **IIS**: Install via PowerShell: `Install-WindowsFeature -Name Web-Server -IncludeManagementTools`
- **PowerShell Remoting**: Enable on target servers: `Enable-PSRemoting -Force` and configure firewall rules

See [INSTALLATION.md](INSTALLATION.md) for complete step-by-step instructions, troubleshooting guides, and verification checklists.
    
## Quick Start

### Apache Tomcat (Unix/Linux)

**Auto-detect and Audit:**
```bash
sudo ./src/unix/Patch/bash/UpdateTomcatHstsUnix.sh --mode audit
```

**Auto-detect and Configure:**
```bash
sudo ./src/unix/Patch/bash/UpdateTomcatHstsUnix.sh --mode configure
```

**With Custom Path:**
```bash
sudo ./src/unix/Patch/bash/UpdateTomcatHstsUnix.sh --mode configure --custom-conf=/opt/tomcat/conf
```

**With Multiple Custom Paths:**
```bash
sudo ./src/unix/Patch/bash/UpdateTomcatHstsUnix.sh --mode configure \
  --custom-conf=/opt/tomcat1/conf \
  --custom-conf=/opt/tomcat2/conf
```

**With Custom Paths File:**
```bash
# Create paths file: /etc/tomcat-paths.txt
# /opt/tomcat1/conf
# /opt/tomcat2/conf
# /opt/tomcat3/conf

sudo ./src/unix/Patch/bash/UpdateTomcatHstsUnix.sh --mode configure \
  --custom-paths-file=/etc/tomcat-paths.txt
```

### Apache Tomcat (Windows)

**Local - Auto-detect and Configure:**
```powershell
.\src\windows\Patch\powershell\UpdateTomcatHstsWin.ps1 -Mode configure
```

**Local - With Custom Paths:**
```powershell
.\src\windows\Patch\powershell\UpdateTomcatHstsWin.ps1 -Mode configure `
  -CustomPaths @("C:\Tomcat1\conf", "C:\Tomcat2\conf")
```

**Local - With Custom Paths File:**
```powershell
# Create paths file: C:\tomcat-paths.txt
# C:\Tomcat1\conf
# C:\Tomcat2\conf

.\src\windows\Patch\powershell\UpdateTomcatHstsWin.ps1 -Mode configure `
  -CustomPathsFile "C:\tomcat-paths.txt"
```

**Remote - Multiple Servers (Command Line):**
```powershell
# Ensure PowerShell Remoting is configured (see INSTALLATION.md)
$cred = Get-Credential
.\src\windows\Patch\powershell\Remote_UpdateTomcatHstsWin.ps1 `
  -ServerName @("server1", "server2", "server3") `
  -Mode configure -Credential $cred
```

**Remote - Multiple Servers (Server List File):**
```powershell
# Create server list file: C:\servers.txt
# server1.example.com
# server2.example.com
# server3.example.com

$cred = Get-Credential
.\src\windows\Patch\powershell\Remote_UpdateTomcatHstsWin.ps1 `
  -ServerListFile "C:\servers.txt" `
  -Mode configure -Credential $cred
```

**Remote - With Custom Paths:**
```powershell
$cred = Get-Credential
.\src\windows\Patch\powershell\Remote_UpdateTomcatHstsWin.ps1 `
  -ServerName @("server1", "server2") `
  -CustomPaths @("C:\Tomcat\conf", "D:\Apache\Tomcat\conf") `
  -Mode configure -Credential $cred
```

### Microsoft IIS (Windows)

**Local - Auto-detect and Configure:**
```powershell
.\src\windows\Patch\powershell\UpdateIisHstsWin.ps1 -Mode configure
```

**Local - With Custom Paths:**
```powershell
.\src\windows\Patch\powershell\UpdateIisHstsWin.ps1 -Mode configure `
  -CustomPaths @("C:\inetpub\wwwroot\web.config", "C:\MyApp\web.config")
```

**Local - With Custom Paths File:**
```powershell
# Create paths file: C:\iis-paths.txt
# C:\inetpub\wwwroot\web.config
# C:\MyApp\web.config
# C:\AnotherApp

.\src\windows\Patch\powershell\UpdateIisHstsWin.ps1 -Mode configure `
  -CustomPathsFile "C:\iis-paths.txt"
```

**Remote - Multiple Servers (Command Line):**
```powershell
# Ensure PowerShell Remoting is configured (see INSTALLATION.md)
$cred = Get-Credential
.\src\windows\Patch\powershell\Remote_UpdateIisHstsWin.ps1 `
  -ServerName @("server1", "server2", "server3") `
  -Mode configure -Credential $cred
```

**Remote - Multiple Servers (Server List File):**
```powershell
# Create server list file: C:\servers.txt
# server1.example.com
# server2.example.com
# server3.example.com

$cred = Get-Credential
.\src\windows\Patch\powershell\Remote_UpdateIisHstsWin.ps1 `
  -ServerListFile "C:\servers.txt" `
  -Mode configure -Credential $cred
```

**Remote - With Custom Paths:**
```powershell
$cred = Get-Credential
.\src\windows\Patch\powershell\Remote_UpdateIisHstsWin.ps1 `
  -ServerName @("server1", "server2") `
  -CustomPaths @("C:\inetpub\wwwroot\web.config", "C:\MyApp\web.config") `
  -Mode configure -Credential $cred
```

## Usage Examples with Output

### Example 1: Audit Tomcat Configuration (Compliant) - Auto-detect

**Command:**
```bash
sudo ./src/unix/Patch/bash/UpdateTomcatHstsUnix.sh --mode audit
```

**Output:**
```
[2025-01-15 10:30:45] Starting HSTS audit for Tomcat configuration: /opt/tomcat/conf/web.xml
[2025-01-15 10:30:45] Found 1 HSTS header definition(s)
[2025-01-15 10:30:45] Compliant headers found:
[2025-01-15 10:30:45]   - Filter-based HSTS configuration
[2025-01-15 10:30:45] SUCCESS: HSTS is correctly configured with exactly one compliant definition: max-age=31536000; includeSubDomains
[2025-01-15 10:30:45] HSTS configuration is compliant.
```

**Exit Code:** `0` (Success - Compliant)

---

### Example 2: Audit Tomcat Configuration (Non-Compliant) - Auto-detect

**Command:**
```bash
sudo ./src/unix/Patch/bash/UpdateTomcatHstsUnix.sh --mode audit
```

**Output:**
```
[2025-01-15 10:30:45] Starting HSTS audit for Tomcat configuration: /opt/tomcat/conf/web.xml
[2025-01-15 10:30:45] Found 1 HSTS header definition(s)
[2025-01-15 10:30:45] Non-compliant headers found:
[2025-01-15 10:30:45]   - Filter-based HSTS: max-age correct but includeSubDomains missing or false
[2025-01-15 10:30:45] FAILURE: HSTS header(s) found but none are compliant. Found 1 non-compliant definition(s).
[2025-01-15 10:30:45] HSTS configuration needs to be updated.
```

**Exit Code:** `1` (Failure - Non-Compliant)

---

### Example 3: Audit Tomcat Configuration (No HSTS Found) - Auto-detect

**Command:**
```bash
sudo ./src/unix/Patch/bash/UpdateTomcatHstsUnix.sh --mode audit
```

**Output:**
```
[2025-01-15 10:30:45] Starting HSTS audit for Tomcat configuration: /opt/tomcat/conf/web.xml
[2025-01-15 10:30:45] FAILURE: No HSTS header definitions found in configuration
[2025-01-15 10:30:45] HSTS configuration needs to be updated.
```

**Exit Code:** `1` (Failure - No HSTS Configuration)

---

### Example 4: Configure Tomcat HSTS (First Time) - Auto-detect

**Command:**
```bash
sudo ./src/unix/Patch/bash/UpdateTomcatHstsUnix.sh --mode configure
```

**Output:**
```
[2025-01-15 10:30:45] Starting HSTS configure for Tomcat configuration: /opt/tomcat/conf/web.xml
[2025-01-15 10:30:45] Current state: No HSTS header definitions found in configuration
[2025-01-15 10:30:45] Configuration required: Ensuring exactly one compliant HSTS definition exists

WARNING: This will modify the configuration file: /opt/tomcat/conf/web.xml
All existing HSTS configurations will be removed and replaced with one compliant version.
A backup will be created before making changes.

Do you want to continue? (yes/no): yes
[2025-01-15 10:30:46] Backup created: /opt/tomcat/conf/web.xml.backup.20250115_103046
[2025-01-15 10:30:46] SUCCESS: Compliant HSTS configuration applied successfully. All duplicate/non-compliant headers removed.
[2025-01-15 10:30:46] Backup available at: /opt/tomcat/conf/web.xml.backup.20250115_103046
```

**Exit Code:** `0` (Success - Configuration Applied)

---

### Example 5: Configure Tomcat HSTS (Dry Run)

**Command:**
```bash
sudo ./src/unix/Patch/bash/UpdateTomcatHstsUnix.sh --mode configure --dry-run
```

**Output:**
```
[2025-01-15 10:30:45] Starting HSTS configure for Tomcat configuration: /opt/tomcat/conf/web.xml
[2025-01-15 10:30:45] DRY RUN mode: No changes will be made
[2025-01-15 10:30:45] Current state: No HSTS header definitions found in configuration
[2025-01-15 10:30:45] Configuration required: Ensuring exactly one compliant HSTS definition exists
[2025-01-15 10:30:45] DRY RUN: Would apply compliant HSTS configuration (see diff below)
--- /opt/tomcat/conf/web.xml	2025-01-15 10:30:45.000000000 +0000
+++ /tmp/tmp.XXXXXX	2025-01-15 10:30:45.000000000 +0000
@@ -10,6 +10,25 @@
     </description>
 </web-app>
+    <filter>
+        <filter-name>HstsHeaderFilter</filter-name>
+        <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>
+        <init-param>
+            <param-name>hstsMaxAgeSeconds</param-name>
+            <param-value>31536000</param-value>
+        </init-param>
+        <init-param>
+            <param-name>hstsIncludeSubDomains</param-name>
+            <param-value>true</param-value>
+        </init-param>
+    </filter>
+    <filter-mapping>
+        <filter-name>HstsHeaderFilter</filter-name>
+        <url-pattern>/*</url-pattern>
+    </filter-mapping>
 </web-app>
```

**Exit Code:** `0` (Success - Preview Only)

---

### Example 6: Configure Tomcat HSTS (Already Compliant)

**Command:**
```bash
sudo ./src/unix/Patch/bash/UpdateTomcatHstsUnix.sh --mode configure
```

**Output:**
```
[2025-01-15 10:30:45] Starting HSTS configure for Tomcat configuration: /opt/tomcat/conf/web.xml
[2025-01-15 10:30:45] Found 1 HSTS header definition(s)
[2025-01-15 10:30:45] Compliant headers found:
[2025-01-15 10:30:45]   - Filter-based HSTS configuration
[2025-01-15 10:30:45] Current state: HSTS is correctly configured with exactly one compliant definition: max-age=31536000; includeSubDomains
[2025-01-15 10:30:45] SUCCESS: HSTS is already correctly configured with exactly one compliant definition
```

**Exit Code:** `0` (Success - No Changes Needed)

---

### Example 7: Audit IIS Configuration (Compliant)

**Command:**
```powershell
.\src\windows\Patch\powershell\UpdateIisHstsWin.ps1 -Mode audit
```

**Output:**
```
[2025-01-15 10:30:45] Starting HSTS audit for IIS configuration: C:\inetpub\wwwroot\web.config
[2025-01-15 10:30:45] Found 1 HSTS header definition(s)
[2025-01-15 10:30:45] Compliant headers found:
[2025-01-15 10:30:45]   - Compliant: max-age=31536000; includeSubDomains
[2025-01-15 10:30:45] SUCCESS: HSTS is correctly configured with exactly one compliant definition: max-age=31536000; includeSubDomains
[2025-01-15 10:30:45] HSTS configuration is compliant.
```

**Exit Code:** `0` (Success - Compliant)

---

### Example 8: Audit IIS Configuration (Multiple Headers)

**Command:**
```powershell
.\src\windows\Patch\powershell\UpdateIisHstsWin.ps1 -Mode audit
```

**Output:**
```
[2025-01-15 10:30:45] Starting HSTS audit for IIS configuration: C:\inetpub\wwwroot\web.config
[2025-01-15 10:30:45] Found 2 HSTS header definition(s)
[2025-01-15 10:30:45] Compliant headers found:
[2025-01-15 10:30:45]   - Compliant: max-age=31536000; includeSubDomains
[2025-01-15 10:30:45] Non-compliant headers found:
[2025-01-15 10:30:45]   - Non-compliant: max-age=31536000
[2025-01-15 10:30:45] FAILURE: Multiple HSTS header definitions found (2 total). Only one compliant configuration should exist.
[2025-01-15 10:30:45] HSTS configuration needs to be updated.
[2025-01-15 10:30:45] ACTION REQUIRED: Remove duplicate HSTS definitions. Only one compliant configuration should exist.
```

**Exit Code:** `1` (Failure - Multiple Headers)

---

### Example 9: Configure IIS HSTS (First Time)

**Command:**
```powershell
.\src\windows\Patch\powershell\UpdateIisHstsWin.ps1 -Mode configure
```

**Output:**
```
[2025-01-15 10:30:45] Starting HSTS configure for IIS configuration: C:\inetpub\wwwroot\web.config
[2025-01-15 10:30:45] Current state: No HSTS header definitions found in configuration
[2025-01-15 10:30:45] Configuration required: Ensuring exactly one compliant HSTS definition exists

WARNING: This will modify the configuration file: C:\inetpub\wwwroot\web.config
All existing HSTS configurations will be removed and replaced with one compliant version.
A backup will be created before making changes.

Do you want to continue? (yes/no): yes
[2025-01-15 10:30:46] Backup created: C:\inetpub\wwwroot\web.config.backup.20250115_103046
[2025-01-15 10:30:46] SUCCESS: Compliant HSTS configuration applied successfully. All duplicate/non-compliant headers removed.
[2025-01-15 10:30:46] Backup available at: C:\inetpub\wwwroot\web.config.backup.20250115_103046
```

**Exit Code:** `0` (Success - Configuration Applied)

---

### Example 10: Configure IIS HSTS (Dry Run)

**Command:**
```powershell
.\src\windows\Patch\powershell\UpdateIisHstsWin.ps1 -Mode configure -DryRun
```

**Output:**
```
[2025-01-15 10:30:45] Starting HSTS configure for IIS configuration: C:\inetpub\wwwroot\web.config
[2025-01-15 10:30:45] DRY RUN mode: No changes will be made
[2025-01-15 10:30:45] Current state: No HSTS header definitions found in configuration
[2025-01-15 10:30:45] Configuration required: Ensuring exactly one compliant HSTS definition exists
[2025-01-15 10:30:45] DRY RUN: Would apply compliant HSTS configuration
[2025-01-15 10:30:45] Modified configuration would be:
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains" />
            </customHeaders>
        </httpProtocol>
    </system.webServer>
</configuration>
```

**Exit Code:** `0` (Success - Preview Only)

---

### Example 11: Configure IIS HSTS (Replace Non-Compliant)

**Command:**
```powershell
.\src\windows\Patch\powershell\UpdateIisHstsWin.ps1 -Mode configure
```

**Output:**
```
[2025-01-15 10:30:45] Starting HSTS configure for IIS configuration: C:\inetpub\wwwroot\web.config
[2025-01-15 10:30:45] Found 1 HSTS header definition(s)
[2025-01-15 10:30:45] Non-compliant headers found:
[2025-01-15 10:30:45]   - Non-compliant: max-age=86400
[2025-01-15 10:30:45] Current state: HSTS header(s) found but none are compliant. Found 1 non-compliant definition(s).
[2025-01-15 10:30:45] Configuration required: Ensuring exactly one compliant HSTS definition exists

WARNING: This will modify the configuration file: C:\inetpub\wwwroot\web.config
All existing HSTS configurations will be removed and replaced with one compliant version.
A backup will be created before making changes.

Do you want to continue? (yes/no): yes
[2025-01-15 10:30:46] Backup created: C:\inetpub\wwwroot\web.config.backup.20250115_103046
[2025-01-15 10:30:46] SUCCESS: Compliant HSTS configuration applied successfully. All duplicate/non-compliant headers removed.
[2025-01-15 10:30:46] Backup available at: C:\inetpub\wwwroot\web.config.backup.20250115_103046
```

**Exit Code:** `0` (Success - Configuration Applied)

---

### Example 12: Error - File Not Found

**Command:**
```bash
sudo ./src/unix/Patch/bash/UpdateTomcatHstsUnix.sh --mode audit --custom-conf=/nonexistent/path
```

**Output:**
```
[2025-01-15 10:30:45] ERROR: Configuration file not found: /opt/tomcat/conf/nonexistent.xml
[2025-01-15 10:30:45] ERROR: Failed to load configuration file
```

**Exit Code:** `2` (Error)

---

### Example 13: Error - Permission Denied

**Command:**
```bash
./src/unix/Patch/bash/UpdateTomcatHstsUnix.sh --mode configure
```

**Output:**
```
[2025-01-15 10:30:45] Starting HSTS configure for Tomcat configuration: /opt/tomcat/conf/web.xml
[2025-01-15 10:30:45] ERROR: Permission denied: Cannot read configuration file: /opt/tomcat/conf/web.xml
[2025-01-15 10:30:45] ERROR: Failed to load configuration file
```

**Exit Code:** `2` (Error)

---

## Auto-Detection

All scripts include automatic detection capabilities to simplify deployment:

### Unix/Linux Tomcat Auto-Detection
1. Checks `CATALINA_BASE` and `CATALINA_HOME` environment variables
2. Searches common Linux server paths:
   - `/opt/tomcat*/conf`
   - `/usr/local/tomcat*/conf`
   - `/var/lib/tomcat*/conf`
   - `/usr/share/tomcat*/conf`
   - `/etc/tomcat*/conf`
3. Finds all `web.xml` files:
   - Global: `conf/web.xml` and `conf/context.xml`
   - Application-specific: `webapps/*/WEB-INF/web.xml`

### Windows Tomcat Auto-Detection
1. Checks custom path parameter (if provided)
2. Searches common Windows Server paths:
   - `C:\Program Files\Apache Software Foundation\Tomcat*\conf`
   - `C:\Tomcat*\conf`
   - `C:\Apache\Tomcat*\conf`
   - `D:\` and `E:\` drives (same patterns)
3. Dynamically searches subdirectories in Apache Software Foundation folder
4. Finds all `web.xml` files (global and application-specific)

### Windows IIS Auto-Detection
1. Searches `C:\inetpub\wwwroot\web.config` (default root)
2. Finds application-specific web.config files in subdirectories
3. Uses IIS WebAdministration module to query all IIS sites and their web.config files

**Note:** Auto-detection can be overridden by providing a custom path parameter.

## Command Reference

### UpdateTomcatHstsUnix.sh

**Syntax:**
```bash
sudo ./src/unix/Patch/bash/UpdateTomcatHstsUnix.sh [--mode audit|configure] [--custom-conf=/path/to/conf] [--custom-paths-file=/path/to/file] [--dry-run]
```

**Options:**
- `--mode` (optional, default: configure): Operation mode - `audit` or `configure`
- `--custom-conf` (optional, repeatable): Custom Tomcat conf directory path (can be specified multiple times)
- `--custom-paths-file` (optional): File containing custom paths (one path per line, lines starting with # are comments)
- `--dry-run` (optional): Preview changes without applying (configure mode only)

**Auto-Detection:**
- Checks `CATALINA_BASE` and `CATALINA_HOME` environment variables
- Searches common Linux server paths: `/opt/tomcat*/conf`, `/usr/local/tomcat*/conf`, `/var/lib/tomcat*/conf`, etc.
- Finds all `web.xml` files (global and application-specific)

### UpdateTomcatHstsWin.ps1

**Syntax:**
```powershell
.\src\windows\Patch\powershell\UpdateTomcatHstsWin.ps1 [-Mode audit|configure] [-TomcatConfPath <path>] [-CustomPaths <string[]>] [-CustomPathsFile <path>] [-DryRun]
```

**Parameters:**
- `-Mode` (optional, default: configure): Operation mode - `audit` or `configure`
- `-TomcatConfPath` (optional): Single custom Tomcat conf directory path (auto-detects if not provided)
- `-CustomPaths` (optional): Array of custom Tomcat conf directory paths (e.g., `@("C:\Tomcat1\conf", "C:\Tomcat2\conf")`)
- `-CustomPathsFile` (optional): File containing custom paths (one path per line, lines starting with # are comments)
- `-DryRun` (optional): Preview changes without applying

**Auto-Detection:**
- Searches common Windows Server paths: `C:\Program Files\Apache Software Foundation\Tomcat*\conf`, `C:\Tomcat*\conf`, etc.
- Finds all `web.xml` files (global and application-specific)

### Remote_UpdateTomcatHstsWin.ps1

**Syntax:**
```powershell
.\src\windows\Patch\powershell\Remote_UpdateTomcatHstsWin.ps1 [-ServerName <string[]>] [-ServerListFile <path>] [-Mode audit|configure] [-TomcatConfPath <path>] [-CustomPaths <string[]>] [-CustomPathsFile <path>] [-DryRun] [-Credential <PSCredential>]
```

**Parameters:**
- `-ServerName` (optional): Array of server names to process (e.g., `@("server1", "server2")`)
- `-ServerListFile` (optional): File containing server names (one per line, lines starting with # are comments)
- `-Mode` (optional, default: configure): Operation mode - `audit` or `configure`
- `-TomcatConfPath` (optional): Single custom Tomcat conf directory path (auto-detects if not provided)
- `-CustomPaths` (optional): Array of custom Tomcat conf directory paths (e.g., `@("C:\Tomcat1\conf", "C:\Tomcat2\conf")`)
- `-CustomPathsFile` (optional): File containing custom paths (one path per line, lines starting with # are comments)
- `-DryRun` (optional): Preview changes without applying
- `-Credential` (optional): PSCredential object for remote authentication (use `Get-Credential`)

**Note:** Either `-ServerName` or `-ServerListFile` (or both) must be provided.

**Prerequisites:**
- PowerShell Remoting (WinRM) must be enabled on target servers
- Firewall rules must allow WinRM traffic (ports 5985/5986)
- Credentials must have administrator privileges on target servers
- See [INSTALLATION.md](INSTALLATION.md) for detailed setup instructions

**Auto-Detection:**
- Searches common Windows Server paths: `C:\Program Files\Apache Software Foundation\Tomcat*\conf`, `C:\Tomcat*\conf`, etc.
- Finds all `web.xml` files (global and application-specific)

### UpdateIisHstsWin.ps1

**Syntax:**
```powershell
.\src\windows\Patch\powershell\UpdateIisHstsWin.ps1 [-Mode audit|configure] [-ConfigPath <path>] [-CustomPaths <string[]>] [-CustomPathsFile <path>] [-DryRun]
```

**Parameters:**
- `-Mode` (optional, default: configure): Operation mode - `audit` or `configure`
- `-ConfigPath` (optional): Single path to web.config file or directory containing web.config (auto-detects if not provided)
- `-CustomPaths` (optional): Array of web.config file paths or directories (e.g., `@("C:\path1\web.config", "C:\path2")`)
- `-CustomPathsFile` (optional): File containing custom paths (one path per line, lines starting with # are comments)
- `-DryRun` (optional): Preview changes without applying

**Note:** For directories, the script will look for `web.config` files within them.

**Auto-Detection:**
- Searches `C:\inetpub\wwwroot\web.config` and application-specific web.config files
- Uses IIS WebAdministration module to find all IIS sites and their web.config files

### Remote_UpdateIisHstsWin.ps1

**Syntax:**
```powershell
.\src\windows\Patch\powershell\Remote_UpdateIisHstsWin.ps1 [-ServerName <string[]>] [-ServerListFile <path>] [-Mode audit|configure] [-ConfigPath <path>] [-CustomPaths <string[]>] [-CustomPathsFile <path>] [-DryRun] [-Credential <PSCredential>]
```

**Parameters:**
- `-ServerName` (optional): Array of server names to process (e.g., `@("server1", "server2")`)
- `-ServerListFile` (optional): File containing server names (one per line, lines starting with # are comments)
- `-Mode` (optional, default: configure): Operation mode - `audit` or `configure`
- `-ConfigPath` (optional): Single path to web.config file or directory containing web.config (auto-detects if not provided)
- `-CustomPaths` (optional): Array of web.config file paths or directories (e.g., `@("C:\path1\web.config", "C:\path2")`)
- `-CustomPathsFile` (optional): File containing custom paths (one path per line, lines starting with # are comments)
- `-DryRun` (optional): Preview changes without applying
- `-Credential` (optional): PSCredential object for remote authentication (use `Get-Credential`)

**Note:** Either `-ServerName` or `-ServerListFile` (or both) must be provided. For directories, the script will look for `web.config` files within them.

**Prerequisites:**
- PowerShell Remoting (WinRM) must be enabled on target servers
- Firewall rules must allow WinRM traffic (ports 5985/5986)
- Credentials must have administrator privileges on target servers
- See [INSTALLATION.md](INSTALLATION.md) for detailed setup instructions

**Auto-Detection:**
- Searches `C:\inetpub\wwwroot\web.config` and application-specific web.config files
- Uses IIS WebAdministration module to find all IIS sites and their web.config files

### Remote Scripts

**Remote_UpdateTomcatHstsWin.ps1** and **Remote_UpdateIisHstsWin.ps1** support remote execution across multiple servers:

```powershell
# Example: Remote Tomcat execution on multiple servers (command line)
$cred = Get-Credential
.\src\windows\Patch\powershell\Remote_UpdateTomcatHstsWin.ps1 -ServerName @("server1", "server2", "server3") -Mode configure -Credential $cred

# Example: Remote Tomcat execution using server list file
# Create C:\servers.txt:
# server1.example.com
# server2.example.com
# server3.example.com
$cred = Get-Credential
.\src\windows\Patch\powershell\Remote_UpdateTomcatHstsWin.ps1 -ServerListFile "C:\servers.txt" -Mode configure -Credential $cred

# Example: Remote IIS execution on multiple servers
$cred = Get-Credential
.\src\windows\Patch\powershell\Remote_UpdateIisHstsWin.ps1 -ServerName @("server1", "server2", "server3") -Mode configure -Credential $cred

# Example: Remote execution with custom paths
$cred = Get-Credential
.\src\windows\Patch\powershell\Remote_UpdateTomcatHstsWin.ps1 `
  -ServerListFile "C:\servers.txt" `
  -CustomPaths @("C:\Tomcat1\conf", "C:\Tomcat2\conf") `
  -Mode configure -Credential $cred

# Example: Remote audit without credentials (if using same account)
.\src\windows\Patch\powershell\Remote_UpdateTomcatHstsWin.ps1 -ServerName @("server1") -Mode audit
.\src\windows\Patch\powershell\Remote_UpdateIisHstsWin.ps1 -ServerName @("server1") -Mode audit
```

**Important:** Before using remote scripts, ensure:
1. PowerShell Remoting (WinRM) is enabled on all target servers
2. Firewall rules allow WinRM traffic (see [INSTALLATION.md](INSTALLATION.md))
3. Credentials have administrator privileges on target servers
4. Network connectivity and DNS resolution work correctly

## Exit Codes

- `0` - Success
  - Audit: HSTS is correctly configured
  - Configure: Patch applied successfully
- `1` - Failure
  - Audit: HSTS is not correctly configured
  - Configure: Patch failed to apply
- `2` - Error
  - Invalid arguments
  - File not found
  - Permission denied
  - XML parsing errors

## How It Works

### Execution Flow Summary

Both scripts follow a similar execution pattern:

1. **Parse Arguments** → Validate parameters
2. **Load Configuration** → Read and parse config file
3. **Branch by Mode**:
   - **AUDIT**: Find headers → Check compliance → Report → Exit
   - **CONFIGURE**: Check current → Confirm → Backup → Apply → Verify → Exit


### Tomcat Implementation

The script configures HSTS using the `HttpHeaderSecurityFilter` in Tomcat's web.xml or context.xml. This filter is available in all Tomcat versions 7.0 and later.

**Configuration Applied (OWASP Compliant):**
```xml
<filter>
    <filter-name>HstsHeaderFilter</filter-name>
    <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>
    <init-param>
        <param-name>hstsMaxAgeSeconds</param-name>
        <param-value>31536000</param-value>
    </init-param>
    <init-param>
        <param-name>hstsIncludeSubDomains</param-name>
        <param-value>true</param-value>
    </init-param>
</filter>
<filter-mapping>
    <filter-name>HstsHeaderFilter</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>
```

This generates the OWASP-recommended header: `Strict-Transport-Security: max-age=31536000; includeSubDomains`

**Key Functions:**
- `find_all_hsts_headers()` - Searches for HSTS patterns in config
- `is_compliant_header()` - Validates max-age and includeSubDomains (per OWASP requirements)
- `remove_all_hsts_configs()` - Removes existing HSTS configs using sed
- `apply_compliant_hsts()` - Inserts filter block before closing tag

### IIS Implementation

The script configures HSTS using custom HTTP headers in the web.config file.

**Configuration Applied (OWASP Compliant):**
```xml
<system.webServer>
    <httpProtocol>
        <customHeaders>
            <add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains" />
        </customHeaders>
    </httpProtocol>
</system.webServer>
```

This generates the OWASP-recommended header: `Strict-Transport-Security: max-age=31536000; includeSubDomains`

**Key Functions:**
- `Find-AllHstsHeaders()` - Navigates XML DOM to find headers
- `Test-CompliantHeader()` - Validates header value with regex
- `Remove-AllHstsHeaders()` - Removes headers via DOM manipulation
- `Apply-CompliantHsts()` - Creates and appends new header element


## Code Architecture Summary

### Key Design Principles

1. **Idempotency**: Configure mode ensures exactly one compliant HSTS definition
2. **Safety**: Automatic backups before modifications
3. **Validation**: XML validation before and after changes
4. **User Confirmation**: Interactive prompts for destructive operations
5. **Dry Run**: Preview changes without applying them

### Function Categories

**Utility Functions:**
- Logging (`log_message`, `Log-Message`)
- Error handling (`log_error`, `Log-Error`)
- Cleanup (`cleanup_temp_files`)

**Validation Functions:**
- Path validation (`validate_file_path`, `Test-ValidFilePath`)
- XML validation (`validate_xml`, `Test-ValidXml`)
- File loading (`load_config`, `Load-Config`)

**HSTS Functions:**
- Detection (`find_all_hsts_headers`, `Find-AllHstsHeaders`)
- Compliance checking (`is_compliant_header`, `Test-CompliantHeader`)
- Audit (`audit_hsts_headers`, `Audit-HstsHeaders`)
- Configuration (`configure_hsts_headers`, `Apply-CompliantHsts`)

### Security Features

- ✅ Path traversal protection (`..` detection)
- ✅ Null byte detection
- ✅ Symlink/junction detection
- ✅ Permission validation
- ✅ XML validation before/after changes
- ✅ Automatic backup creation
- ✅ User confirmation prompts


## Supported Versions

### Apache Tomcat
- ✅ Tomcat 7.0
- ✅ Tomcat 8.0
- ✅ Tomcat 8.5
- ✅ Tomcat 9.0
- ✅ Tomcat 10.0
- ✅ Tomcat 10.1
- ✅ Tomcat 11.0 and later

### Microsoft IIS
- ✅ IIS 7.0
- ✅ IIS 7.5
- ✅ IIS 8.0
- ✅ IIS 8.5
- ✅ IIS 10.0
- ✅ IIS 11.0 and later

## Security Notes

### OWASP HSTS Compliance

This implementation follows the **OWASP HSTS Cheat Sheet** recommendations:

1. **Required Configuration:**
   - `max-age=31536000` (1 year) - Ensures browsers remember HSTS policy for 1 year
   - `includeSubDomains` - Prevents cookie-related attacks from subdomains and ensures all subdomains use HTTPS

2. **Threats Addressed:**
   - ✅ User bookmarks or manually types `http://` - Automatically redirects to HTTPS
   - ✅ Web application inadvertently contains HTTP links - Automatically redirects to HTTPS
   - ✅ Man-in-the-middle attacker with invalid certificate - Prevents user override of certificate warnings

3. **Browser Support:**
   - Supported by all modern browsers (as of September 2019)
   - Only notable exception: Opera Mini

### Preload Considerations

The OWASP Cheat Sheet mentions an optional `preload` directive:
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

**⚠️ Important Warning:** The `preload` directive has **PERMANENT CONSEQUENCES**:
- Once included in browser preload lists, it can be difficult or impossible to remove
- Prevents users from accessing your site and subdomains if you need to switch back to HTTP
- Requires manual submission to browser preload lists (Chrome, Firefox, Safari)

**This script does NOT configure `preload` by default** due to these permanent consequences. If you need preload:
1. First ensure your site is fully HTTPS with no HTTP dependencies
2. Manually add `preload` to the configuration after careful consideration
3. Submit your domain to the HSTS preload list: https://hstspreload.org/

### General Security Best Practices

- Always test in a non-production environment first
- Backups are automatically created before configuration changes
- Use `--dry-run` (Unix) or `-DryRun` (Windows) to preview changes without applying them
- Verify HSTS is working after configuration using browser developer tools
- Monitor application logs after applying HSTS to ensure no issues

## Troubleshooting

### Tomcat: "Configuration file not found"
- Verify the path to your Tomcat configuration file
- Common locations: `/opt/tomcat/conf/web.xml`, `/usr/local/tomcat/conf/web.xml`
- Check file permissions: `ls -l /path/to/web.xml`

### Tomcat: "XML validation failed"
- The script validates XML before and after modifications
- If validation fails, check for:
  - Malformed XML in the original file
  - Missing XML declaration (`<?xml version="1.0"?>`)
  - Unclosed tags or mismatched brackets
- Use `xmllint` to manually validate: `xmllint --noout /path/to/web.xml`
- The script will attempt to fix common issues automatically

### IIS: "Failed to parse configuration file as XML"
- Ensure the web.config file is valid XML
- Check for syntax errors in the existing configuration
- Verify file encoding (should be UTF-8)
- The script validates XML before and after modifications to prevent corruption

### IIS: "Generated XML failed validation"
- The script validates XML before saving changes
- If this error occurs, the original file is preserved
- Check the backup file to restore if needed
- Verify the web.config structure is correct

### "Permission denied" errors
- Tomcat: Run with `sudo` or as root
- IIS: Run PowerShell as Administrator
- Check file and directory permissions

### "Configuration file is empty"
- Verify the file exists and has content
- Check if the file was accidentally truncated
- Restore from backup if available

### "Failed to write configured file"
- Check disk space: `df -h` (Unix) or check drive space (Windows)
- Verify write permissions on the directory
- Ensure the file is not locked by another process
- For Tomcat, ensure Tomcat is not running or the file is not in use

## Best Practices

1. **Always use dry-run first**: Test changes with `--dry-run` (Tomcat) or `-DryRun` (IIS) before applying
2. **Backup manually**: While scripts create automatic backups, maintain your own backups
3. **Test in non-production**: Always test configuration changes in a development environment first
4. **Verify after changes**: After configuring, run audit mode to verify the changes were applied correctly
5. **Monitor logs**: Check application logs after applying HSTS to ensure no issues
6. **XML validation**: Use `xmllint` (Unix) or XML validation tools to verify configuration files

## Testing

The project includes comprehensive test scripts to validate HSTS patching functionality across different scenarios.

### Running Tests

**Windows Tests:**
```powershell
# Run as Administrator
cd tests\Patch\windows
.\test_hsts_win.ps1
```

**Unix/Linux Tests:**
```bash
# Run as root or with sudo
cd tests/Patch/unix
sudo ./test_hsts_unix.sh
```

### Test Scenarios

Tests validate the following scenarios:
1. **No HSTS Header** - Configuration with no HSTS header (should add compliant header)
2. **Non-Compliant HSTS (Short MaxAge)** - HSTS with max-age < 31536000 (should fix)
3. **Non-Compliant HSTS (No IncludeSubDomains)** - Missing includeSubDomains (should add)
4. **Compliant HSTS** - Already compliant (should remain unchanged)
5. **Multiple HSTS Headers** - Duplicate headers (should consolidate to one)

For detailed test documentation, see [tests/README.md](tests/README.md).

## Advanced Usage

### Auto-Detection of Multiple Files

All scripts automatically detect and process multiple configuration files:

**Tomcat (Unix/Linux):**
- Automatically finds: `conf/web.xml`, `conf/context.xml`, and all `webapps/*/WEB-INF/web.xml` files
- Processes each file individually with a summary at the end
- Searches common paths: `/opt/tomcat*/conf`, `/usr/local/tomcat*/conf`, `/var/lib/tomcat*/conf`, etc.

**Tomcat (Windows):**
- Automatically finds all web.xml files in the detected Tomcat installation
- Processes each file individually with a summary at the end
- Searches common paths: `C:\Program Files\Apache Software Foundation\Tomcat*\conf`, `C:\Tomcat*\conf`, etc.

**IIS (Windows):**
- Automatically finds all web.config files (root and application-specific)
- Uses IIS WebAdministration module to discover all IIS sites
- Processes each file individually with a summary at the end
- Searches default path: `C:\inetpub\wwwroot\web.config` and application-specific paths

### Custom Paths Support

All scripts support flexible path specification:

**Single Custom Path:**
```bash
# Unix
sudo ./UpdateTomcatHstsUnix.sh --custom-conf=/opt/tomcat/conf
```

```powershell
# Windows
.\UpdateTomcatHstsWin.ps1 -TomcatConfPath "C:\Tomcat\conf"
.\UpdateIisHstsWin.ps1 -ConfigPath "C:\MyApp\web.config"
```

**Multiple Custom Paths:**
```bash
# Unix - specify multiple times
sudo ./UpdateTomcatHstsUnix.sh --custom-conf=/opt/tomcat1/conf --custom-conf=/opt/tomcat2/conf
```

```powershell
# Windows - use array
.\UpdateTomcatHstsWin.ps1 -CustomPaths @("C:\Tomcat1\conf", "C:\Tomcat2\conf")
.\UpdateIisHstsWin.ps1 -CustomPaths @("C:\App1\web.config", "C:\App2\web.config")
```

**Paths File (Recommended for Many Paths):**
```bash
# Unix - create paths file: /etc/tomcat-paths.txt
# /opt/tomcat1/conf
# /opt/tomcat2/conf
# /opt/tomcat3/conf

sudo ./UpdateTomcatHstsUnix.sh --custom-paths-file=/etc/tomcat-paths.txt
```

```powershell
# Windows - create paths file: C:\tomcat-paths.txt
# C:\Tomcat1\conf
# C:\Tomcat2\conf
# C:\Tomcat3\conf

.\UpdateTomcatHstsWin.ps1 -CustomPathsFile "C:\tomcat-paths.txt"
.\UpdateIisHstsWin.ps1 -CustomPathsFile "C:\iis-paths.txt"
```

**Note:** Paths files support comments (lines starting with `#` are ignored).

### Remote Execution with Server Lists

Windows remote scripts support server list files for batch operations:

```powershell
# Create server list file: C:\servers.txt
# server1.example.com
# server2.example.com
# server3.example.com
# # This is a comment

$cred = Get-Credential
.\Remote_UpdateTomcatHstsWin.ps1 -ServerListFile "C:\servers.txt" -Mode configure -Credential $cred
.\Remote_UpdateIisHstsWin.ps1 -ServerListFile "C:\servers.txt" -Mode configure -Credential $cred
```

### Logging

All scripts provide comprehensive logging:

**Unix/Linux:**
- Default log location: `/tmp/TomcatHsts.log`
- Logs include timestamps, hostname, and detailed operation information

**Windows:**
- Default log location: `$env:LOCALAPPDATA\Temp\TomcatHsts.log` (Tomcat) or `$env:LOCALAPPDATA\Temp\IisHsts.log` (IIS)
- Custom log file: Use `-LogFile` parameter
- Logs include timestamps, hostname, and detailed operation information

**Remote Execution:**
- Logs are written on the remote server
- Client-side output shows remote server name prefix: `[SERVER-NAME]`

### Manual Processing of Specific Files

If you need to process a specific file instead of using auto-detection:

**Tomcat (Unix/Linux):**
```bash
sudo ./src/unix/Patch/bash/UpdateTomcatHstsUnix.sh --mode configure --custom-conf=/opt/tomcat/conf
```

**Tomcat (Windows):**
```powershell
.\src\windows\Patch\powershell\UpdateTomcatHstsWin.ps1 -Mode configure -TomcatConfPath "C:\Program Files\Apache Software Foundation\Tomcat 10.0\conf"
```

**IIS (Windows):**
```powershell
.\src\windows\Patch\powershell\UpdateIisHstsWin.ps1 -Mode configure -ConfigPath "C:\inetpub\wwwroot\MyApp\web.config"
```

### Automated Auditing

Create a scheduled task to audit HSTS configuration regularly:

**Unix cron example (daily at 2 AM):**
```bash
0 2 * * * /path/to/src/unix/Patch/bash/UpdateTomcatHstsUnix.sh --mode audit
```

**Windows Task Scheduler PowerShell script:**
```powershell
.\src\windows\Patch\powershell\UpdateIisHstsWin.ps1 -Mode audit -LogFile "C:\logs\hsts_audit.log"
```

## Code Review Summary

### Key Strengths
- ✅ **Auto-detection**: Automatically finds Tomcat and IIS installations
- ✅ **Comprehensive functionality**: Audit and configure modes
- ✅ **Safety features**: Automatic backups, XML validation, user confirmation
- ✅ **Cross-platform**: Unix/Linux (Bash) and Windows Server (PowerShell)
- ✅ **Remote support**: Windows scripts support remote execution
- ✅ **Clear error handling**: Comprehensive error messages and exit codes
- ✅ **Security validations**: Path traversal prevention, null byte checks
- ✅ **OWASP compliant**: Implements OWASP HSTS Cheat Sheet recommendations (RFC 6797)

### OWASP Compliance Verification

The scripts have been verified against the OWASP HSTS Cheat Sheet:
- ✅ Implements required `max-age=31536000` (1 year)
- ✅ Implements required `includeSubDomains`
- ✅ Allows optional `preload` directive (doesn't fail compliance check if present)
- ✅ Follows RFC 6797 (HTTP Strict Transport Security) specification
- ✅ Addresses all three primary threats mentioned in OWASP documentation:
  - User bookmarks or manually types `http://` → Auto-redirects to HTTPS
  - Web application inadvertently contains HTTP links → Auto-redirects to HTTPS
  - MITM attacker with invalid certificate → Prevents user override


## Quick Reference: Installation & Remote Setup Checklist

For a complete installation and setup guide, see **[INSTALLATION.md](INSTALLATION.md)**.

**Quick Checklist:**
- [ ] Apache Tomcat or IIS installed on Windows Server
- [ ] PowerShell Remoting (WinRM) enabled on target servers: `Enable-PSRemoting -Force`
- [ ] Firewall rules configured: `Enable-NetFirewallRule -DisplayGroup "Windows Remote Management"`
- [ ] Remote connectivity tested: `Test-WSMan -ComputerName targetserver`
- [ ] Credentials have administrator privileges on target servers

See [INSTALLATION.md](INSTALLATION.md) for detailed instructions and troubleshooting.

## Quick Reference: Complete Feature Matrix

| Feature | Unix/Linux Tomcat | Windows Tomcat | Windows IIS |
|---------|------------------|----------------|-------------|
| **Audit Mode** | ✅ | ✅ | ✅ |
| **Configure Mode** | ✅ | ✅ | ✅ |
| **Dry Run** | ✅ | ✅ | ✅ |
| **Auto-Detection** | ✅ | ✅ | ✅ |
| **Custom Single Path** | ✅ | ✅ | ✅ |
| **Custom Multiple Paths** | ✅ | ✅ | ✅ |
| **Paths File Support** | ✅ | ✅ | ✅ |
| **Remote Execution** | ❌ | ✅ | ✅ |
| **Server List Files** | ❌ | ✅ | ✅ |
| **Automatic Backups** | ✅ | ✅ | ✅ |
| **XML Validation** | ✅ | ✅ | ✅ |
| **Multiple File Processing** | ✅ | ✅ | ✅ |
| **Logging** | ✅ | ✅ | ✅ |
| **Installation Scripts** | ✅ | ✅ | ❌* |

*IIS is a Windows feature installed via Windows Features, not a standalone application.

## Complete Workflow Example

### 1. Install Tomcat (if needed)

**Windows:**
```powershell
cd install\windows
.\TomcatManager.ps1 -Action install -TomcatVersion 10.1
```

**Unix/Linux:**
```bash
cd install/unix
sudo ./tomcat_manager.sh -v 10.1
```

### 2. Audit Current Configuration

**Windows Tomcat:**
```powershell
.\src\windows\Patch\powershell\UpdateTomcatHstsWin.ps1 -Mode audit
```

**Windows IIS:**
```powershell
.\src\windows\Patch\powershell\UpdateIisHstsWin.ps1 -Mode audit
```

**Unix/Linux Tomcat:**
```bash
sudo ./src/unix/Patch/bash/UpdateTomcatHstsUnix.sh --mode audit
```

### 3. Preview Changes (Dry Run)

**Windows:**
```powershell
.\src\windows\Patch\powershell\UpdateTomcatHstsWin.ps1 -Mode configure -DryRun
.\src\windows\Patch\powershell\UpdateIisHstsWin.ps1 -Mode configure -DryRun
```

**Unix/Linux:**
```bash
sudo ./src/unix/Patch/bash/UpdateTomcatHstsUnix.sh --mode configure --dry-run
```

### 4. Apply Configuration

**Windows:**
```powershell
.\src\windows\Patch\powershell\UpdateTomcatHstsWin.ps1 -Mode configure
.\src\windows\Patch\powershell\UpdateIisHstsWin.ps1 -Mode configure
```

**Unix/Linux:**
```bash
sudo ./src/unix/Patch/bash/UpdateTomcatHstsUnix.sh --mode configure
```

### 5. Verify Configuration

Run audit mode again to confirm compliance.

### 6. Run Tests

**Windows:**
```powershell
cd tests\Patch\windows
.\test_hsts_win.ps1
```

**Unix/Linux:**
```bash
cd tests/Patch/unix
sudo ./test_hsts_unix.sh
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Acknowledgments

- OWASP HSTS Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html
- RFC 6797 (HTTP Strict Transport Security): https://tools.ietf.org/html/rfc6797
