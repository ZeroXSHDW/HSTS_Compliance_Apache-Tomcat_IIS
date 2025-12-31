![HSTS_Compliance_Apache-Tomcat_IIS](assets/images/banner.png)

# Installation Scripts

This directory contains cross-platform installation scripts for Apache Tomcat and Microsoft IIS, designed for automated deployment and configuration.

## Contents

- `windows/TomcatManager.ps1` — PowerShell script for Windows (Tomcat - local execution)
- `windows/Remote_TomcatManager.ps1` — PowerShell script for Windows (Tomcat - remote execution)
- `windows/IisManager.ps1` — PowerShell script for Windows (IIS - local execution)
- `windows/Remote_IisManager.ps1` — PowerShell script for Windows (IIS - remote execution)
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

---

## Remote Installation (Windows)

The remote installation scripts allow you to install Tomcat or IIS on multiple Windows servers remotely via PowerShell Remoting (WinRM).

### Prerequisites

- PowerShell Remoting (WinRM) enabled on both client and target servers
- Administrator credentials on target servers
- Network connectivity to target servers
- See [INSTALLATION.md](../INSTALLATION.md) for WinRM setup instructions

### Remote: Remote_TomcatManager.ps1

**Usage:**
```powershell
# Run as Administrator on CLIENT machine
cd <repo-root>\install\windows

# Example: Install Tomcat 10.1 on multiple servers
$cred = Get-Credential
.\Remote_TomcatManager.ps1 -ServerName @("server1", "server2", "server3") -Action install -TomcatVersion 10.1 -Credential $cred

# Example: Using server list file
# Create C:\servers.txt:
# webserver01.example.com
# webserver02.example.com
$cred = Get-Credential
.\Remote_TomcatManager.ps1 -ServerListFile "C:\servers.txt" -Action install -TomcatVersion 9.0 -Credential $cred

# Example: Uninstall Tomcat on multiple servers
.\Remote_TomcatManager.ps1 -ServerName @("server1", "server2") -Action uninstall -Credential $cred
```

**Parameters:**
- `-ServerName` (optional): Array of server names (e.g., `@("server1", "server2")`)
- `-ServerListFile` (optional): Path to file containing server names (one per line, comments with `#` supported)
- `-Action` (required): `install` or `uninstall`
- `-TomcatVersion` (required for install): Tomcat major version (`7`, `8.5`, `9`, `10.0`, `10.1`)
- `-Username` (optional): Admin username (default: `tomcat`)
- `-Password` (optional): Admin password (default: `s3cretP@ssw0rd!`)
- `-Roles` (optional): Comma-separated roles (default: `manager-gui,admin-gui`)
- `-StartMode` (optional): `service` (default) or `bat`
- `-Credential` (optional): PSCredential object for authentication (if not provided, uses current user)

**What it does:**
- Connects to each target server via PowerShell Remoting
- Executes Tomcat installation/uninstallation on remote servers
- Automatically tries multiple authentication methods (Negotiate, Basic, Kerberos, CredSSP)
- Logs actions to `$env:TEMP\TomcatManager.log` on each remote server

### Remote: Remote_IisManager.ps1

**Usage:**
```powershell
# Run as Administrator on CLIENT machine
cd <repo-root>\install\windows

# Example: Install IIS on multiple servers
$cred = Get-Credential
.\Remote_IisManager.ps1 -ServerName @("server1", "server2") -Action install -Credential $cred

# Example: Install IIS with ASP.NET and FTP on multiple servers
.\Remote_IisManager.ps1 -ServerName @("server1", "server2") -Action install -IncludeAspNet -IncludeFtp -Credential $cred

# Example: Uninstall IIS on multiple servers
.\Remote_IisManager.ps1 -ServerListFile "C:\servers.txt" -Action uninstall -Credential $cred
```

**Parameters:**
- `-ServerName` (optional): Array of server names
- `-ServerListFile` (optional): Path to file containing server names
- `-Action` (required): `install` or `uninstall`
- `-IncludeManagementTools` (optional): Include IIS Management Tools (default: `true`)
- `-IncludeAspNet` (optional): Include ASP.NET support (default: `false`)
- `-IncludeFtp` (optional): Include FTP Server (default: `false`)
- `-Credential` (optional): PSCredential object for authentication

**What it does:**
- Connects to each target server via PowerShell Remoting
- Executes IIS installation/uninstallation on remote servers
- Automatically tries multiple authentication methods
- Logs actions to `$env:TEMP\IisManager.log` on each remote server

### Remote Script Features

- **Multiple Authentication Methods:** Automatically tries Negotiate, Basic, Kerberos, and CredSSP
- **Server List Files:** Support for comments (lines starting with `#`) in server list files
- **Error Handling:** Continues processing other servers if one fails
- **Detailed Logging:** Logs are written to each remote server's temp directory
- **Credential Management:** Supports both credential-based and current user authentication

### Remote Script Examples

**Install Tomcat 10.1 on multiple servers:**
```powershell
$cred = Get-Credential
.\Remote_TomcatManager.ps1 `
    -ServerName @("webserver01.example.com", "webserver02.example.com") `
    -Action install `
    -TomcatVersion 10.1 `
    -Username admin `
    -Password SecurePass123! `
    -Credential $cred
```

**Install IIS with all features using server list:**
```powershell
# Create C:\iis_servers.txt:
# webserver01.example.com
# webserver02.example.com
# webserver03.example.com

$cred = Get-Credential
.\Remote_IisManager.ps1 `
    -ServerListFile "C:\iis_servers.txt" `
    -Action install `
    -IncludeManagementTools `
    -IncludeAspNet `
    -IncludeFtp `
    -Credential $cred
```

**Uninstall Tomcat on all servers in list:**
```powershell
$cred = Get-Credential
.\Remote_TomcatManager.ps1 -ServerListFile "C:\servers.txt" -Action uninstall -Credential $cred
```

### Troubleshooting Remote Scripts

**Error: "Cannot connect to remote server"**
- Ensure WinRM is enabled on both client and target servers
- Verify firewall rules allow WinRM traffic
- Check network connectivity: `Test-NetConnection -ComputerName server1 -Port 5985`

**Error: "Access Denied"**
- Ensure credentials have administrator privileges on target servers
- For workgroup environments, enable Basic authentication: `winrm set winrm/config/service/auth @{Basic="true"}`
- Configure TrustedHosts on client machine if using workgroup

**Error: "Authentication failed"**
- Try using FQDN instead of hostname
- Verify credentials are correct
- Check if account is locked or disabled

For detailed WinRM setup instructions, see [INSTALLATION.md](../INSTALLATION.md).

---

For more details, see the main [README.md](../README.md) in the project root.

