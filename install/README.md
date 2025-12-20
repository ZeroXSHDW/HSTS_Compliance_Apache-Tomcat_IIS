# Installation Scripts

This directory contains cross-platform installation scripts for Apache Tomcat and Microsoft IIS, designed for automated deployment and configuration.

## Contents

- `windows/TomcatManager.ps1` — PowerShell script for Windows (Tomcat)
- `windows/IisManager.ps1` — PowerShell script for Windows (IIS)
- `unix/tomcat_manager.sh` — Bash script for Unix/Linux/macOS (Tomcat)

## Features

- Automatically downloads and installs the latest patch for the specified Tomcat version
- Detects or installs Java as needed
- Configures secure admin user(s) with hashed passwords
- Optionally installs Tomcat as a service and configures firewall rules
- Robust error handling, logging, and backup of configuration files

---

## Windows: TomcatManager.ps1

**Usage:**
```powershell
# Run as Administrator in PowerShell
cd <repo-root>\install\windows

# Example: Install Tomcat 9.0 with a secure user
.\TomcatManager.ps1 -Action install -TomcatVersion 9 -Username admin -Password MySecurePass! -Roles "manager-gui,admin-gui"
```

**Parameters:**
- `-Action` (required): Action to perform - `install` or `uninstall`
- `-TomcatVersion` (required for install): Tomcat major version (e.g., `7`, `8.5`, `9`, `10.0`, `10.1`)
- `-Username` (optional): Admin username (default: `tomcat`)
- `-Password` (optional): Admin password (default: `s3cretP@ssw0rd!`)
- `-Roles` (optional): Comma-separated roles (default: `manager-gui,admin-gui`)
- `-StartMode` (optional): Start mode - `service` (default) or `bat`

**What it does:**
- Downloads the latest available patch for the specified Tomcat version
- Installs Java if not found (OpenJDK 8 for Tomcat 7, OpenJDK 11 for others)
- Extracts Tomcat to `C:\tomcat`, configures the admin user with a secure hash, and installs as a service
- Sets environment variables (JAVA_HOME, CATALINA_HOME)
- Logs actions to `$env:TEMP\TomcatManager.log`

**Examples:**
```powershell
# Install Tomcat 10.1
.\TomcatManager.ps1 -Action install -TomcatVersion 10.1

# Install Tomcat 9.0 with custom credentials
.\TomcatManager.ps1 -Action install -TomcatVersion 9 -Username admin -Password SecurePass123! -Roles "manager-gui,admin-gui"

# Uninstall Tomcat
.\TomcatManager.ps1 -Action uninstall
```

---

## Windows: IisManager.ps1

**Usage:**
```powershell
# Run as Administrator in PowerShell
cd <repo-root>\install\windows

# Example: Install IIS with default features
.\IisManager.ps1 -Action install
```

**Parameters:**
- `-Action` (required): Action to perform - `install` or `uninstall`
- `-IncludeManagementTools` (optional): Include IIS Management Tools (default: `true`)
- `-IncludeAspNet` (optional): Include ASP.NET support (default: `false`)
- `-IncludeFtp` (optional): Include FTP Server (default: `false`)

**What it does:**
- Installs IIS with core web server features
- Optionally includes Management Tools, ASP.NET support, and FTP Server
- Verifies installation and starts IIS service
- Logs actions to `$env:TEMP\IisManager.log`

**Examples:**
```powershell
# Install IIS with default features (includes Management Tools)
.\IisManager.ps1 -Action install

# Install IIS with ASP.NET and FTP support
.\IisManager.ps1 -Action install -IncludeAspNet -IncludeFtp

# Install IIS without Management Tools
.\IisManager.ps1 -Action install -IncludeManagementTools:$false

# Uninstall IIS
.\IisManager.ps1 -Action uninstall
```

**Installed Features:**
- Core IIS web server components
- HTTP error pages, logging, compression
- Static content, default documents, directory browsing
- Security features (authentication, authorization, request filtering)
- Management Tools (IIS Manager, PowerShell cmdlets) - if enabled
- ASP.NET support - if enabled
- FTP Server - if enabled

**Default Website:**
- Location: `C:\inetpub\wwwroot`
- Accessible at: `http://localhost`
- Service: `W3SVC` (World Wide Web Publishing Service)

---

## Unix: tomcat_manager.sh

**Usage:**
```bash
# Run as root or with sudo
cd <repo-root>/install/unix

# Example: Install Tomcat 9.0 with a secure user
sudo ./tomcat_manager.sh -v 9.0 -u admin -w MySecurePass! -r manager,admin
```

**Options:**
- `-p, --path` — Installation path (default: `/opt/tomcat`)
- `-v, --version` — Tomcat major version (e.g., `7.0`, `8.5`, `9.0`, `10.0`, `10.1`)
- `-u, --username` — Admin username (default: `tomcat`)
- `-w, --password` — Admin password (default: `s3cret`)
- `-r, --roles` — Comma-separated roles (default: `manager,admin`)
- `-s, --no-service` — Skip service installation
- `-f, --no-firewall` — Skip firewall configuration

**What it does:**
- Downloads and extracts the latest patch for the specified Tomcat version
- Installs Java if not found (OpenJDK 11 for most versions)
- Configures secure admin user(s) with hashed passwords
- Optionally installs as a systemd service and configures firewall
- Logs actions to `~/TomcatManager.log`

**Examples:**
```bash
# Install Tomcat 10.1
sudo ./tomcat_manager.sh -v 10.1

# Install Tomcat 9.0 with custom path and credentials
sudo ./tomcat_manager.sh -p /opt/tomcat -v 9.0 -u admin -w SecurePass123! -r manager,admin

# Install without service or firewall configuration
sudo ./tomcat_manager.sh -v 9.0 -s -f
```

## Log Files

- **Windows Tomcat:** `$env:TEMP\TomcatManager.log`
- **Windows IIS:** `$env:TEMP\IisManager.log`
- **Unix:** `~/TomcatManager.log`

---

## Troubleshooting

- **Permissions:** Always run as Administrator (Windows) or with sudo/root (Unix).
- **Java Not Found:** The script will attempt to install Java if missing, but you may need to install it manually on some systems.
- **Firewall/Service Issues:** Use the `--no-firewall` or `--no-service` options if you do not want these configured.
- **Log Files:** Check the log files for detailed error messages if something fails.

---

## After Installation

Once Tomcat or IIS is installed, you can use the HSTS patching scripts to configure HSTS headers:

**Windows Tomcat:**
```powershell
.\src\windows\Patch\powershell\UpdateTomcatHstsWin.ps1 -Mode configure
```

**Windows IIS:**
```powershell
.\src\windows\Patch\powershell\UpdateIisHstsWin.ps1 -Mode configure
```

**Unix:**
```bash
sudo ./src/unix/Patch/bash/UpdateTomcatHstsUnix.sh --mode configure
```

For more details, see the main [README.md](../README.md) in the project root.

