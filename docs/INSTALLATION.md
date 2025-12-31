# Installation Guide

This guide provides detailed instructions for installing Apache Tomcat, Microsoft IIS, and configuring PowerShell Remoting (WinRM) for remote execution.

## Table of Contents

- [Apache Tomcat Installation](#apache-tomcat-installation)
  - [Windows](#windows-tomcat-installation)
  - [Unix/Linux](#unixlinux-tomcat-installation)
- [Microsoft IIS Installation](#microsoft-iis-installation)
- [PowerShell Remoting (WinRM) Setup](#powershell-remoting-winrm-setup)
  - [Client Machine Setup](#client-machine-setup)
  - [Target Server Setup](#target-server-setup)
  - [Verification](#verification)
- [Troubleshooting](#troubleshooting)

---

## Apache Tomcat Installation

### Windows Tomcat Installation

#### Option 1: Automated Installation (Recommended)

Use the provided installation script for automated setup:

```powershell
# Run as Administrator
cd install\windows
.\TomcatManager.ps1 -Action install -TomcatVersion 10.1
```

**Available Versions:** 7.0, 8.5, 9.0, 10.0, 10.1

**Full Example:**
```powershell
.\TomcatManager.ps1 -Action install -TomcatVersion 9.0 -Username admin -Password MySecurePass! -Roles "manager-gui,admin-gui"
```

See [install/README.md](install/README.md) for complete documentation.

#### Option 2: Manual Installation

1. **Download Tomcat:**
   - Visit https://tomcat.apache.org/download-90.cgi (or appropriate version)
   - Download the "Windows Service Installer" (64-bit)

2. **Install Java:**
   - Tomcat requires Java (JRE or JDK)
   - For Tomcat 7.0: Java 6 or later
   - For Tomcat 8.5+: Java 7 or later
   - For Tomcat 9.0+: Java 8 or later
   - For Tomcat 10.0+: Java 11 or later
   - Download from: https://adoptium.net/ or https://www.oracle.com/java/

3. **Set JAVA_HOME:**
   ```powershell
   # Set environment variable (replace with your Java path)
   [System.Environment]::SetEnvironmentVariable("JAVA_HOME", "C:\Program Files\Java\jdk-11", "Machine")
   ```

4. **Run Installer:**
   - Run the downloaded `.exe` installer
   - Follow the installation wizard
   - Default installation path: `C:\Program Files\Apache Software Foundation\Tomcat X.X`

5. **Verify Installation:**
   ```powershell
   # Check Tomcat service
   Get-Service | Where-Object { $_.Name -like "*Tomcat*" }
   
   # Check if Tomcat is running
   Test-NetConnection -ComputerName localhost -Port 8080
   
   # Access Tomcat Manager (if configured)
   Start-Process "http://localhost:8080"
   ```

### Unix/Linux Tomcat Installation

#### Option 1: Automated Installation (Recommended)

Use the provided installation script:

```bash
# Run as root or with sudo
cd install/unix
sudo ./tomcat_manager.sh -v 10.1
```

**Available Versions:** 7.0, 8.5, 9.0, 10.0, 10.1

**Full Example:**
```bash
sudo ./tomcat_manager.sh -p /opt/tomcat -v 9.0 -u admin -w SecurePass123! -r manager,admin
```

See [install/README.md](install/README.md) for complete documentation.

#### Option 2: Manual Installation

1. **Install Java:**
   ```bash
   # Ubuntu/Debian
   sudo apt-get update
   sudo apt-get install openjdk-11-jdk
   
   # CentOS/RHEL
   sudo yum install java-11-openjdk-devel
   
   # Verify Java installation
   java -version
   ```

2. **Set JAVA_HOME:**
   ```bash
   # Find Java installation
   sudo update-alternatives --config java
   
   # Add to ~/.bashrc or /etc/environment
   export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
   export PATH=$PATH:$JAVA_HOME/bin
   ```

3. **Download and Extract Tomcat:**
   ```bash
   cd /opt
   sudo wget https://archive.apache.org/dist/tomcat/tomcat-9/v9.0.XX/bin/apache-tomcat-9.0.XX.tar.gz
   sudo tar -xzf apache-tomcat-9.0.XX.tar.gz
   sudo mv apache-tomcat-9.0.XX tomcat
   sudo chown -R tomcat:tomcat /opt/tomcat
   ```

4. **Configure Tomcat User:**
   ```bash
   sudo nano /opt/tomcat/conf/tomcat-users.xml
   ```
   Add:
   ```xml
   <user username="admin" password="secure_password" roles="manager-gui,admin-gui"/>
   ```

5. **Create Systemd Service (Optional):**
   ```bash
   sudo nano /etc/systemd/system/tomcat.service
   ```
   Add:
   ```ini
   [Unit]
   Description=Apache Tomcat
   After=network.target
   
   [Service]
   Type=forking
   User=tomcat
   Group=tomcat
   Environment="JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64"
   Environment="CATALINA_HOME=/opt/tomcat"
   Environment="CATALINA_BASE=/opt/tomcat"
   ExecStart=/opt/tomcat/bin/startup.sh
   ExecStop=/opt/tomcat/bin/shutdown.sh
   
   [Install]
   WantedBy=multi-user.target
   ```

6. **Start Tomcat:**
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl start tomcat
   sudo systemctl enable tomcat
   sudo systemctl status tomcat
   ```

7. **Verify Installation:**
   ```bash
   # Check if Tomcat is running
   curl http://localhost:8080
   
   # Check service status
   sudo systemctl status tomcat
   ```

---

## Microsoft IIS Installation

### Windows Server Installation

#### Option 1: Using PowerShell (Recommended)

```powershell
# Run as Administrator
# Install IIS with Management Tools
Install-WindowsFeature -Name Web-Server -IncludeManagementTools

# Optional: Include ASP.NET support
Install-WindowsFeature -Name Web-Asp-Net45

# Optional: Include FTP Server
Install-WindowsFeature -Name Web-Ftp-Server
```

#### Option 2: Using Server Manager

1. Open **Server Manager**
2. Click **Add Roles and Features**
3. Select **Web Server (IIS)**
4. Include Management Tools if needed
5. Complete the installation wizard

#### Option 3: Using Installation Script

```powershell
# Run as Administrator
cd install\windows
.\IisManager.ps1 -Action install
```

**With Additional Features:**
```powershell
.\IisManager.ps1 -Action install -IncludeAspNet -IncludeFtp
```

### Verify IIS Installation

```powershell
# Check IIS service
Get-Service W3SVC

# Test default website
Test-NetConnection -ComputerName localhost -Port 80

# Access default website
Start-Process "http://localhost"
```

### Default Website Location

- **Path:** `C:\inetpub\wwwroot`
- **URL:** `http://localhost`
- **Service:** `W3SVC` (World Wide Web Publishing Service)

---

## PowerShell Remoting (WinRM) Setup

PowerShell Remoting (WinRM) is required for remote execution of HSTS configuration scripts on Windows servers.

### Client Machine Setup

**Step 1: Enable WinRM on Client Machine**

```powershell
# Run PowerShell as Administrator
# IMPORTANT: Enable WinRM FIRST before configuring trusted hosts
Enable-PSRemoting -Force

# Verify WinRM service is running
Get-Service WinRM

# If not running, start it manually
Start-Service WinRM
Set-Service WinRM -StartupType Automatic
```

**Step 2: Configure Trusted Hosts**

```powershell
# Method 1: Add a single server
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "webserver01.example.com" -Force

# Method 2: Add multiple servers (comma-separated)
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "server1.domain.com,server2.domain.com" -Force

# Method 3: Append to existing trusted hosts
$current = (Get-Item WSMan:\localhost\Client\TrustedHosts).Value
if ($current) {
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value "$current,server1.domain.com" -Force
} else {
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value "server1.domain.com" -Force
}

# View current trusted hosts
Get-Item WSMan:\localhost\Client\TrustedHosts
```

**Note:** Using `*` for trusted hosts is less secure. Prefer specific server names or use domain authentication.

### Target Server Setup

**Step 1: Enable WinRM on Target Server**

```powershell
# Run PowerShell as Administrator on the TARGET server
Enable-PSRemoting -Force

# Configure firewall
Enable-NetFirewallRule -DisplayGroup "Windows Remote Management"
```

**Step 2: Configure Authentication Methods**

```powershell
# Enable multiple authentication methods for maximum compatibility
# Basic authentication (required for workgroup environments with credentials)
winrm set winrm/config/service/auth @{Basic="true"}

# Negotiate (works in both domain and workgroup)
winrm set winrm/config/service/auth @{Negotiate="true"}

# Kerberos (for domain environments)
winrm set winrm/config/service/auth @{Kerberos="true"}

# Verify authentication methods
winrm get winrm/config/service/auth
```

**Step 3: Verify WinRM Configuration**

```powershell
# Check WinRM service
Get-Service WinRM

# Test WinRM locally
Test-WSMan -ComputerName localhost

# View WinRM configuration
winrm get winrm/config
```

### Verification

**On Client Machine:**

```powershell
# Test basic connectivity
Test-WSMan -ComputerName "webserver01.example.com"

# Test remote command execution
$cred = Get-Credential
Invoke-Command -ComputerName "webserver01.example.com" -Credential $cred -ScriptBlock { $env:COMPUTERNAME }
```

**If successful, you can now use remote scripts:**

```powershell
$cred = Get-Credential
.\src\windows\Patch\powershell\Remote_UpdateTomcatHstsWin.ps1 -ServerName "webserver01.example.com" -Mode audit -Credential $cred
```

### Domain vs Workgroup Environments

**Domain Environment (Recommended):**
- Uses Kerberos/Negotiate authentication automatically
- No need to configure TrustedHosts
- More secure
- Just enable WinRM on both client and target servers

**Workgroup Environment:**
- Must configure TrustedHosts on client machine
- **MUST enable Basic authentication on target server:**
  ```powershell
  winrm set winrm/config/service/auth @{Basic="true"}
  ```
- Less secure but functional

---

## Troubleshooting

### Tomcat Installation Issues

**Java Not Found:**
```powershell
# Windows: Set JAVA_HOME
[System.Environment]::SetEnvironmentVariable("JAVA_HOME", "C:\Program Files\Java\jdk-11", "Machine")

# Unix/Linux: Set JAVA_HOME
export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
```

**Port Already in Use:**
- Check if another service is using port 8080
- Edit `server.xml` to change port
- Or stop the conflicting service

**Service Won't Start:**
- Check Tomcat logs: `logs/catalina.out`
- Verify Java installation
- Check file permissions

### IIS Installation Issues

**Feature Installation Fails:**
```powershell
# Check Windows Features
Get-WindowsFeature | Where-Object { $_.Name -like "*Web*" }

# Try alternative installation method
Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole -All
```

**Service Not Running:**
```powershell
# Start IIS service
Start-Service W3SVC

# Check service status
Get-Service W3SVC
```

### WinRM Connection Issues

**Error: "The client cannot connect to the destination specified"**

**Solution:** WinRM must be enabled on the CLIENT machine first:
```powershell
Enable-PSRemoting -Force
```

**Error: "Access Denied" or "Authentication Failed"**

**Solutions:**
1. Enable Basic authentication on target server:
   ```powershell
   winrm set winrm/config/service/auth @{Basic="true"}
   ```

2. Verify credentials have administrator privileges

3. Check if account is locked or disabled

4. For domain environments, ensure Kerberos is working:
   ```powershell
   winrm set winrm/config/service/auth @{Kerberos="true"}
   ```

5. Try using FQDN (fully qualified domain name) instead of hostname

**Error: "Cannot connect to remote server"**

**Solutions:**
1. Verify firewall rules:
   ```powershell
   Get-NetFirewallRule -DisplayGroup "Windows Remote Management" | Select-Object DisplayName, Enabled
   ```

2. Test network connectivity:
   ```powershell
   Test-NetConnection -ComputerName "server1" -Port 5985
   ```

3. Check DNS resolution:
   ```powershell
   Resolve-DnsName "server1.domain.com"
   ```

**Error: "WinRM cannot process the request"**

**Solutions:**
1. Ensure WinRM service is running:
   ```powershell
   Get-Service WinRM
   Start-Service WinRM
   ```

2. Check WinRM configuration:
   ```powershell
   winrm get winrm/config
   ```

3. Reset WinRM configuration if needed:
   ```powershell
   winrm quickconfig
   ```

---

## Complete Setup Checklist

### For Tomcat (Windows)
- [ ] Java installed and JAVA_HOME set
- [ ] Tomcat installed (via script or manually)
- [ ] Tomcat service running
- [ ] Default website accessible at http://localhost:8080
- [ ] For remote execution: WinRM enabled on client and target servers

### For Tomcat (Unix/Linux)
- [ ] Java installed and JAVA_HOME set
- [ ] Tomcat installed (via script or manually)
- [ ] Tomcat service running (systemd or init.d)
- [ ] Default website accessible at http://localhost:8080
- [ ] File permissions configured correctly

### For IIS (Windows)
- [ ] IIS installed with Management Tools
- [ ] W3SVC service running
- [ ] Default website accessible at http://localhost
- [ ] For remote execution: WinRM enabled on client and target servers

### For Remote Execution (Windows)
- [ ] WinRM enabled on CLIENT machine
- [ ] TrustedHosts configured on CLIENT machine (for workgroup)
- [ ] WinRM enabled on TARGET server(s)
- [ ] Basic authentication enabled on TARGET server (for workgroup)
- [ ] Firewall rules configured
- [ ] Remote connectivity tested successfully

---

## Next Steps

After installation, you can use the HSTS configuration scripts:

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

For detailed usage instructions, see the main [README.md](README.md).

