# Installation Guide

This guide provides step-by-step instructions for installing Apache Tomcat and Microsoft IIS on Windows Server, as well as configuring PowerShell Remoting (WinRM) for remote script execution.

## Table of Contents

- [Installing Apache Tomcat on Windows Server](#installing-apache-tomcat-on-windows-server)
- [Installing IIS on Windows Server](#installing-iis-on-windows-server)
- [Configuring PowerShell Remoting (WinRM) for Remote Execution](#configuring-powershell-remoting-winrm-for-remote-execution)
- [Troubleshooting Remote PowerShell Execution](#troubleshooting-remote-powershell-execution)
- [Quick Reference Checklist](#quick-reference-checklist)

## Installing Apache Tomcat on Windows Server

### Method 1: Using the Windows Service Installer (Recommended)

1. **Download Apache Tomcat:**
   - Visit: https://tomcat.apache.org/download-90.cgi (or latest version)
   - Download the 64-bit Windows Service Installer (e.g., `apache-tomcat-9.0.xx-windows-x64.exe`)

2. **Run the Installer:**
   - Right-click the installer and select "Run as Administrator"
   - Follow the installation wizard:
     - Choose installation path (default: `C:\Program Files\Apache Software Foundation\Tomcat X.X`)
     - Set the service name (default: `TomcatX`)
     - Configure the service to run as a Windows service
     - Set administrator username and password for the Tomcat service
     - Choose Java Virtual Machine (JVM) path (if not auto-detected)

3. **Verify Installation:**
   ```powershell
   # Check if Tomcat service is running
   Get-Service -Name "Tomcat*"
   
   # Check default installation path
   Test-Path "C:\Program Files\Apache Software Foundation\Tomcat*\conf\server.xml"
   ```

4. **Access Tomcat Manager:**
   - Open browser: `http://localhost:8080`
   - Default ports: HTTP (8080), HTTPS (8443), AJP (8009)

### Method 2: Manual Installation (ZIP Archive)

1. **Download and Extract:**
   - Download the ZIP archive from Apache Tomcat website
   - Extract to desired location (e.g., `C:\Tomcat9` or `C:\Apache\Tomcat9`)

2. **Set Environment Variables (Optional):**
   ```powershell
   # Set CATALINA_HOME
   [System.Environment]::SetEnvironmentVariable("CATALINA_HOME", "C:\Tomcat9", "Machine")
   
   # Set CATALINA_BASE (if different from CATALINA_HOME)
   [System.Environment]::SetEnvironmentVariable("CATALINA_BASE", "C:\Tomcat9", "Machine")
   ```

3. **Install as Windows Service (Optional):**
   ```powershell
   cd "C:\Tomcat9\bin"
   .\service.bat install
   ```

4. **Start Tomcat:**
   ```powershell
   # As a service
   Start-Service -Name "Tomcat9"
   
   # Or manually
   .\startup.bat
   ```

## Installing IIS on Windows Server

### Windows Server 2016/2019/2022

1. **Install IIS via PowerShell (Recommended):**
   ```powershell
   # Run PowerShell as Administrator
   Install-WindowsFeature -Name Web-Server -IncludeManagementTools
   
   # Or install with additional features
   Install-WindowsFeature -Name Web-Server,Web-Mgmt-Tools,Web-Mgmt-Console,Web-WebServer,Web-Common-Http,Web-Default-Doc,Web-Dir-Browsing,Web-Http-Errors,Web-Static-Content,Web-Http-Redirect,Web-Health,Web-Http-Logging,Web-Performance,Web-Stat-Compression,Web-Security,Web-Filtering,Web-Basic-Auth,Web-Windows-Auth,Web-App-Dev,Web-Net-Ext45,Web-Asp-Net45,Web-ISAPI-Ext,Web-ISAPI-Filter,Web-Mgmt-Compat,Web-Metabase
   ```

2. **Install IIS via Server Manager:**
   - Open **Server Manager**
   - Click **Add Roles and Features**
   - Select **Web Server (IIS)**
   - Choose required features (at minimum: Web Server, Management Tools)
   - Complete the installation

3. **Verify Installation:**
   ```powershell
   # Check IIS service
   Get-Service -Name W3SVC
   
   # Check default website
   Get-Website
   
   # Test default page
   Invoke-WebRequest -Uri http://localhost -UseBasicParsing
   ```

4. **Default IIS Paths:**
   - Web root: `C:\inetpub\wwwroot`
   - Configuration: `C:\Windows\System32\inetsrv\config`
   - Logs: `C:\inetpub\logs\LogFiles`

### Windows Server 2012 R2

1. **Install IIS via PowerShell:**
   ```powershell
   Import-Module ServerManager
   Add-WindowsFeature Web-Server,Web-Mgmt-Tools,Web-Mgmt-Console
   ```

2. **Or via Server Manager:**
   - Same process as above

## Configuring PowerShell Remoting (WinRM) for Remote Execution

PowerShell Remoting (WinRM) is required for the remote scripts to work. Follow these steps on **both** the client machine (where you run the script) and the target server(s).

### Step 1: Enable PowerShell Remoting on Target Server(s)

**On each target server (where Tomcat/IIS is installed):**

1. **Enable WinRM Service:**
   ```powershell
   # Run PowerShell as Administrator
   Enable-PSRemoting -Force
   ```

2. **Verify WinRM is Running:**
   ```powershell
   Get-Service -Name WinRM
   ```

3. **Check WinRM Listener:**
   ```powershell
   winrm enumerate winrm/config/Listener
   ```

### Step 2: Configure Windows Firewall

**On each target server:**

1. **Allow WinRM through Firewall (HTTP - Port 5985):**
   ```powershell
   # Run PowerShell as Administrator
   New-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)" -Name "WINRM-HTTP-In-TCP" -Profile Domain,Private -Direction Inbound -LocalPort 5985 -Protocol TCP -Action Allow
   ```

2. **Allow WinRM through Firewall (HTTPS - Port 5986, Optional but Recommended):**
   ```powershell
   New-NetFirewallRule -DisplayName "Windows Remote Management (HTTPS-In)" -Name "WINRM-HTTPS-In-TCP" -Profile Domain,Private -Direction Inbound -LocalPort 5986 -Protocol TCP -Action Allow
   ```

3. **Or use the built-in firewall rule:**
   ```powershell
   Enable-NetFirewallRule -DisplayGroup "Windows Remote Management"
   ```

4. **Verify Firewall Rules:**
   ```powershell
   Get-NetFirewallRule -DisplayGroup "Windows Remote Management" | Select-Object DisplayName, Enabled, Direction, Action
   ```

### Step 3: Configure Trusted Hosts (If Not Using Domain Authentication)

**On the client machine (where you run the remote script):**

If you're not using domain authentication, you may need to add target servers to the trusted hosts list:

```powershell
# Run PowerShell as Administrator
# Add specific server
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "server1.domain.com" -Force

# Add multiple servers
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "server1,server2,server3" -Force

# Add all servers (less secure, use with caution)
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force

# View current trusted hosts
Get-Item WSMan:\localhost\Client\TrustedHosts
```

**Note:** Using `*` for trusted hosts is less secure. Prefer adding specific server names or using domain authentication.

### Step 4: Test PowerShell Remoting

**On the client machine:**

1. **Test Basic Connectivity:**
   ```powershell
   Test-WSMan -ComputerName "server1.domain.com"
   ```

2. **Test Remote Command Execution:**
   ```powershell
   # Without credentials (if using same account)
   Invoke-Command -ComputerName "server1.domain.com" -ScriptBlock { Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion }

   # With credentials
   $cred = Get-Credential
   Invoke-Command -ComputerName "server1.domain.com" -Credential $cred -ScriptBlock { Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion }
   ```

3. **If you get errors:**
   - **"Access Denied"**: Check firewall rules and ensure WinRM is enabled
   - **"Cannot connect"**: Verify network connectivity and DNS resolution
   - **"Authentication failed"**: Check credentials and trusted hosts configuration

### Step 5: Configure WinRM for Domain Environments (Optional but Recommended)

For domain environments, you can use Kerberos authentication:

1. **On Domain Controller:**
   - Ensure SPN (Service Principal Name) is registered for the server
   - Usually automatic, but can be verified with: `setspn -L server1`

2. **On Target Server:**
   ```powershell
   # Configure WinRM to use Kerberos
   winrm set winrm/config/service/auth @{Kerberos="true"}
   ```

3. **On Client:**
   ```powershell
   # Use default authentication (Kerberos in domain)
   # No need to set TrustedHosts when using domain authentication
   ```

## Troubleshooting Remote PowerShell Execution

### Common Issues and Solutions

1. **"WinRM cannot process the request"**
   - **Solution:** Ensure WinRM service is running: `Start-Service WinRM`
   - Verify listener is configured: `winrm enumerate winrm/config/Listener`

2. **"Access Denied" or "Authentication Failed"**
   - **Solution:** 
     - Verify credentials have administrator privileges on target server
     - Check if account is locked or disabled
     - For domain environments, ensure Kerberos authentication is working

3. **"Cannot connect to remote server"**
   - **Solution:**
     - Verify firewall rules are enabled: `Get-NetFirewallRule -DisplayGroup "Windows Remote Management"`
     - Test network connectivity: `Test-NetConnection -ComputerName server1 -Port 5985`
     - Check DNS resolution: `Resolve-DnsName server1.domain.com`

4. **"The client cannot connect to the destination specified"**
   - **Solution:**
     - Verify WinRM is enabled: `Get-Service WinRM`
     - Check trusted hosts if not using domain: `Get-Item WSMan:\localhost\Client\TrustedHosts`
     - Ensure target server name is resolvable

5. **"The WinRM client cannot process the request"**
   - **Solution:**
     - Check WinRM configuration: `winrm get winrm/config`
     - Verify PowerShell execution policy: `Get-ExecutionPolicy` (should be RemoteSigned or Unrestricted)
     - Reset WinRM configuration if needed: `winrm quickconfig`

### Verification Checklist

Before running remote scripts, verify:

- [ ] WinRM service is running on target server: `Get-Service WinRM`
- [ ] Firewall allows port 5985 (and 5986 if using HTTPS): `Get-NetFirewallRule -DisplayGroup "Windows Remote Management"`
- [ ] Can connect from client: `Test-WSMan -ComputerName targetserver`
- [ ] Can execute remote command: `Invoke-Command -ComputerName targetserver -ScriptBlock { $env:COMPUTERNAME }`
- [ ] Credentials have admin rights on target server
- [ ] Target server name is resolvable (DNS or hosts file)

## Quick Reference Checklist

### For Apache Tomcat on Windows Server

1. **Install Tomcat:**
   - Download Windows Service Installer from https://tomcat.apache.org
   - Run installer as Administrator
   - Default path: `C:\Program Files\Apache Software Foundation\Tomcat X.X`

2. **Enable PowerShell Remoting (for remote scripts):**
   ```powershell
   Enable-PSRemoting -Force
   ```

3. **Configure Firewall:**
   ```powershell
   Enable-NetFirewallRule -DisplayGroup "Windows Remote Management"
   ```

4. **Test Remote Connection:**
   ```powershell
   Test-WSMan -ComputerName "targetserver"
   ```

### For IIS on Windows Server

1. **Install IIS:**
   ```powershell
   Install-WindowsFeature -Name Web-Server -IncludeManagementTools
   ```

2. **Enable PowerShell Remoting (for remote scripts):**
   ```powershell
   Enable-PSRemoting -Force
   ```

3. **Configure Firewall:**
   ```powershell
   Enable-NetFirewallRule -DisplayGroup "Windows Remote Management"
   ```

### Remote Execution Setup (Both Tomcat and IIS)

**On Target Server(s):**
- [ ] WinRM service is running: `Get-Service WinRM`
- [ ] PowerShell Remoting enabled: `Enable-PSRemoting -Force`
- [ ] Firewall allows WinRM: `Enable-NetFirewallRule -DisplayGroup "Windows Remote Management"`
- [ ] Test connectivity: `Test-WSMan -ComputerName localhost`

**On Client Machine (where you run remote scripts):**
- [ ] Can connect to target: `Test-WSMan -ComputerName targetserver`
- [ ] Credentials have admin rights on target
- [ ] Trusted hosts configured (if not using domain): `Set-Item WSMan:\localhost\Client\TrustedHosts -Value "server1,server2"`

**Test Remote Execution:**
```powershell
$cred = Get-Credential
Invoke-Command -ComputerName "targetserver" -Credential $cred -ScriptBlock { $env:COMPUTERNAME }
```

## Additional Resources

- [Apache Tomcat Documentation](https://tomcat.apache.org/documentation.html)
- [IIS Documentation](https://docs.microsoft.com/en-us/iis/)
- [PowerShell Remoting Documentation](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_remote_requirements)
- [WinRM Configuration Guide](https://docs.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management)

