# Remote_TomcatManager.ps1
# Remote installation and uninstallation of Apache Tomcat 7.0, 8.5, 9.0, 10.0, and 10.1 on Windows
# Supports remote execution via PowerShell Remoting (WinRM)
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string[]]$ServerName = @(),
    
    [Parameter(Mandatory=$false)]
    [string]$ServerListFile = $null,
    
    [Parameter(Mandatory=$true)]
    [ValidateSet("install", "uninstall")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("7", "8.5", "9", "10.0", "10.1")]
    [string]$TomcatVersion = $null,
    
    [Parameter(Mandatory=$false)]
    [string]$Username = "tomcat",
    
    [Parameter(Mandatory=$false)]
    [string]$Password = "s3cretP@ssw0rd!",
    
    [Parameter(Mandatory=$false)]
    [string]$Roles = "manager-gui,admin-gui",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("service", "bat")]
    [string]$StartMode = "service",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential = $null
)

$ErrorActionPreference = "Stop"

# Function: Load server names from file
function Get-ServersFromFile {
    param(
        [string]$ServerFile
    )
    
    $servers = @()
    if (-not $ServerFile -or -not (Test-Path $ServerFile)) {
        return $servers
    }
    
    try {
        $fileContent = Get-Content -Path $ServerFile -ErrorAction Stop
        foreach ($line in $fileContent) {
            $trimmedLine = $line.Trim()
            if ($trimmedLine -and -not $trimmedLine.StartsWith("#")) {
                $servers += $trimmedLine
            }
        }
        Write-Host "Loaded $($servers.Count) server(s) from file: $ServerFile"
    } catch {
        Write-Host "ERROR: Failed to read server list file: $ServerFile - $_" -ForegroundColor Red
    }
    
    return $servers
}

# Collect servers from parameter and file
$allServers = @()
if ($ServerName.Count -gt 0) {
    $allServers += $ServerName
}
if ($ServerListFile) {
    $fileServers = Get-ServersFromFile -ServerFile $ServerListFile
    $allServers += $fileServers
}

if ($allServers.Count -eq 0) {
    Write-Host "ERROR: No servers specified. Use -ServerName or -ServerListFile parameter." -ForegroundColor Red
    Write-Host "  Example: -ServerName @('server1', 'server2')" -ForegroundColor Yellow
    Write-Host "  Example: -ServerListFile 'C:\servers.txt' (one server per line)" -ForegroundColor Yellow
    exit 1
}

# Validate Action and TomcatVersion
if ($Action -eq "install" -and -not $TomcatVersion) {
    Write-Host "ERROR: -TomcatVersion is required when -Action is 'install'" -ForegroundColor Red
    Write-Host "  Valid versions: 7, 8.5, 9, 10.0, 10.1" -ForegroundColor Yellow
    exit 1
}

$uniqueServers = $allServers | Select-Object -Unique
Write-Host "Processing $($uniqueServers.Count) unique server(s) for Tomcat $Action operation"

foreach ($server in $uniqueServers) {
    Write-Host "========================================="
    Write-Host "Processing server: $server"
    Write-Host "========================================="
    
    try {
        # Try multiple authentication methods
        $authMethods = @()
        if ($Credential) {
            $authMethods = @("Negotiate", "Basic", "Kerberos", "CredSSP")
        } else {
            $authMethods = @("Default", "Negotiate", "Kerberos")
        }
        
        $connected = $false
        $lastError = $null
        
        foreach ($authMethod in $authMethods) {
            try {
                Write-Host "Attempting connection to $server using $authMethod authentication..."
                
                $invokeParams = @{
                    ComputerName = $server
                    ScriptBlock = {
                        param($Action, $TomcatVersion, $Username, $Password, $Roles, $StartMode)
                        
                        # Global Variables
                        $TOMCAT_DIR = "C:\tomcat"
                        $LOG_FILE = "$env:TEMP\TomcatManager.log"
                        
                        # Log function
                        function Write-Log {
                            param (
                                [string]$Message
                            )
                            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                            $logMessage = "[$timestamp] [$env:COMPUTERNAME] $Message"
                            Write-Output $logMessage | Out-File -FilePath $LOG_FILE -Append
                            Write-Output $logMessage
                        }
                        
                        # Check for Administrator privileges
                        function Test-Admin {
                            $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
                            if (-not $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
                                Write-Log "ERROR: This script must be run as Administrator."
                                throw "Administrator privileges required"
                            }
                        }
                        
                        # Include all functions from local script (abbreviated for space - full implementation would include all functions)
                        # For brevity, I'll include the key functions. In production, include the complete TomcatManager.ps1 logic
                        
                        # Install OpenJDK 8 manually from Adoptium
                        function Install-OpenJDK8Manual {
                            Write-Log "Attempting manual installation of OpenJDK 8 from Adoptium..."
                            $JDK_URL = "https://github.com/adoptium/temurin8-binaries/releases/download/jdk8u412-b08/OpenJDK8U-jdk_x64_windows_hotspot_8u412b08.zip"
                            $JDK_ZIP = "$env:TEMP\OpenJDK8U-jdk_x64_windows_hotspot_8u412b08.zip"
                            $JAVA_HOME = "C:\Program Files\Java\jdk8u412-b08"
                            $TEMP_EXTRACT_PATH = "$env:TEMP\jdk8u412-b08"
                            
                            Write-Log "Downloading OpenJDK 8 from $JDK_URL..."
                            try {
                                $webClient = New-Object System.Net.WebClient
                                $webClient.DownloadFile($JDK_URL, $JDK_ZIP)
                            } catch {
                                Write-Log "ERROR: Failed to download OpenJDK 8: $($_.Exception.Message)"
                                throw
                            }
                            
                            if (-not (Test-Path $JDK_ZIP)) {
                                Write-Log "ERROR: Downloaded JDK ZIP file not found."
                                throw "Download failed"
                            }
                            
                            Write-Log "Extracting OpenJDK 8..."
                            try {
                                New-Item -ItemType Directory -Path $TEMP_EXTRACT_PATH -Force | Out-Null
                                Expand-Archive -Path $JDK_ZIP -DestinationPath $TEMP_EXTRACT_PATH -Force
                            } catch {
                                Write-Log "ERROR: Failed to extract JDK: $($_.Exception.Message)"
                                throw
                            }
                            Remove-Item $JDK_ZIP -Force
                            
                            Write-Log "Moving extracted files to $JAVA_HOME..."
                            try {
                                New-Item -ItemType Directory -Path $JAVA_HOME -Force | Out-Null
                                $nestedPath = Join-Path -Path $TEMP_EXTRACT_PATH -ChildPath "jdk8u412-b08"
                                if (Test-Path $nestedPath) {
                                    Get-ChildItem -Path $nestedPath | Move-Item -Destination $JAVA_HOME -Force
                                } else {
                                    throw "Expected nested directory not found"
                                }
                                Remove-Item -Path $TEMP_EXTRACT_PATH -Recurse -Force
                            } catch {
                                Write-Log "ERROR: Failed to move files: $($_.Exception.Message)"
                                throw
                            }
                            
                            $javaExe = "$JAVA_HOME\bin\java.exe"
                            if (-not (Test-Path $javaExe)) {
                                Write-Log "ERROR: java.exe not found after installation."
                                throw "Java installation incomplete"
                            }
                            
                            [Environment]::SetEnvironmentVariable("JAVA_HOME", $JAVA_HOME, [EnvironmentVariableTarget]::Machine)
                            $env:JAVA_HOME = $JAVA_HOME
                            
                            $currentPath = [Environment]::GetEnvironmentVariable("PATH", [EnvironmentVariableTarget]::Machine)
                            if ($currentPath -notlike "*$JAVA_HOME\bin*") {
                                [Environment]::SetEnvironmentVariable("PATH", "$currentPath;$JAVA_HOME\bin", [EnvironmentVariableTarget]::Machine)
                                $env:PATH = "$env:PATH;$JAVA_HOME\bin"
                            }
                            
                            Write-Log "OpenJDK 8 successfully installed at $JAVA_HOME"
                        }
                        
                        # Install OpenJDK 11 manually from Adoptium
                        function Install-OpenJDK11Manual {
                            Write-Log "Attempting manual installation of OpenJDK 11 from Adoptium..."
                            $JDK_URL = "https://github.com/adoptium/temurin11-binaries/releases/download/jdk-11.0.22%2B7/OpenJDK11U-jdk_x64_windows_hotspot_11.0.22_7.zip"
                            $JDK_ZIP = "$env:TEMP\OpenJDK11U-jdk_x64_windows_hotspot_11.0.22_7.zip"
                            $JAVA_HOME = "C:\Program Files\Java\jdk-11"
                            $TEMP_EXTRACT_PATH = "$env:TEMP\jdk-11.0.22"
                            
                            Write-Log "Downloading OpenJDK 11 from $JDK_URL..."
                            try {
                                $webClient = New-Object System.Net.WebClient
                                $webClient.DownloadFile($JDK_URL, $JDK_ZIP)
                            } catch {
                                Write-Log "ERROR: Failed to download OpenJDK 11: $($_.Exception.Message)"
                                throw
                            }
                            
                            if (-not (Test-Path $JDK_ZIP)) {
                                Write-Log "ERROR: Downloaded JDK ZIP file not found."
                                throw "Download failed"
                            }
                            
                            Write-Log "Extracting OpenJDK 11..."
                            try {
                                New-Item -ItemType Directory -Path $TEMP_EXTRACT_PATH -Force | Out-Null
                                Expand-Archive -Path $JDK_ZIP -DestinationPath $TEMP_EXTRACT_PATH -Force
                            } catch {
                                Write-Log "ERROR: Failed to extract JDK: $($_.Exception.Message)"
                                throw
                            }
                            Remove-Item $JDK_ZIP -Force
                            
                            Write-Log "Moving extracted files to $JAVA_HOME..."
                            try {
                                New-Item -ItemType Directory -Path $JAVA_HOME -Force | Out-Null
                                $nestedPath = Join-Path -Path $TEMP_EXTRACT_PATH -ChildPath "jdk-11.0.22+7"
                                if (Test-Path $nestedPath) {
                                    Get-ChildItem -Path $nestedPath | Move-Item -Destination $JAVA_HOME -Force
                                } else {
                                    throw "Expected nested directory not found"
                                }
                                Remove-Item -Path $TEMP_EXTRACT_PATH -Recurse -Force
                            } catch {
                                Write-Log "ERROR: Failed to move files: $($_.Exception.Message)"
                                throw
                            }
                            
                            $javaExe = "$JAVA_HOME\bin\java.exe"
                            if (-not (Test-Path $javaExe)) {
                                Write-Log "ERROR: java.exe not found after installation."
                                throw "Java installation incomplete"
                            }
                            
                            [Environment]::SetEnvironmentVariable("JAVA_HOME", $JAVA_HOME, [EnvironmentVariableTarget]::Machine)
                            $env:JAVA_HOME = $JAVA_HOME
                            
                            $currentPath = [Environment]::GetEnvironmentVariable("PATH", [EnvironmentVariableTarget]::Machine)
                            if ($currentPath -notlike "*$JAVA_HOME\bin*") {
                                [Environment]::SetEnvironmentVariable("PATH", "$currentPath;$JAVA_HOME\bin", [EnvironmentVariableTarget]::Machine)
                                $env:PATH = "$env:PATH;$JAVA_HOME\bin"
                            }
                            
                            Write-Log "OpenJDK 11 successfully installed at $JAVA_HOME"
                        }
                        
                        # Uninstall Java
                        function Uninstall-Java {
                            Write-Log "Starting Java uninstallation process..."
                            $javaDirs = @(
                                "C:\Program Files\Java\jdk-11",
                                "C:\Program Files\Java\jdk8u412-b08"
                            )
                            foreach ($dir in $javaDirs) {
                                if (Test-Path $dir) {
                                    try {
                                        Remove-Item -Path $dir -Recurse -Force
                                        Write-Log "Removed Java directory: $dir"
                                    } catch {
                                        Write-Log "ERROR: Failed to remove Java directory $dir: $($_.Exception.Message)"
                                    }
                                }
                            }
                            [Environment]::SetEnvironmentVariable("JAVA_HOME", $null, [EnvironmentVariableTarget]::Machine)
                            $env:JAVA_HOME = $null
                            $currentPath = [Environment]::GetEnvironmentVariable("PATH", [EnvironmentVariableTarget]::Machine)
                            $paths = $currentPath -split ";"
                            $filteredPaths = $paths | Where-Object { $_ -notmatch "Java\\jdk-11\\bin" -and $_ -notmatch "Java\\jdk8u412-b08\\bin" }
                            $newPath = ($filteredPaths -join ";").TrimEnd(';')
                            [Environment]::SetEnvironmentVariable("PATH", $newPath, [EnvironmentVariableTarget]::Machine)
                            $env:PATH = $newPath
                            Write-Log "Java uninstallation completed."
                        }
                        
                        # Uninstall Tomcat
                        function Uninstall-Tomcat {
                            Write-Log "Starting Tomcat uninstallation process..."
                            
                            if (Test-Path $TOMCAT_DIR) {
                                Remove-Item -Path $TOMCAT_DIR -Recurse -Force
                                Write-Log "Removed Tomcat directory: $TOMCAT_DIR"
                            }
                            
                            $tomcatUser = Get-LocalUser -Name "tomcat" -ErrorAction SilentlyContinue
                            if ($tomcatUser) {
                                Remove-LocalUser -Name "tomcat" -ErrorAction SilentlyContinue
                                Write-Log "Removed tomcat user"
                            }
                            
                            Uninstall-Java
                            
                            Write-Log "Tomcat uninstallation completed successfully"
                        }
                        
                        # Install Tomcat function (complete implementation)
                        function Install-Tomcat {
                            param (
                                [string]$TomcatMajor,
                                [string]$Username,
                                [string]$Password,
                                [string]$Roles,
                                [string]$StartMode = "service"
                            )

                            $TOMCAT_VERSION = ""
                            $TOMCAT_URLS = @()
                            $JAVA_HOME = ""
                            $JAVA_VERSION = ""
                            $JAVA_OPTS = ""
                            $JAVA_BIN = ""
                            $CHECKSUM_URL = ""
                            $CHECKSUM = ""
                            $LOCAL_FILE = ""

                            switch ($TomcatMajor) {
                                "7" {
                                    $TOMCAT_VERSION = "7.0.100"
                                    $LOCAL_FILE = "$env:TEMP\apache-tomcat-$TOMCAT_VERSION-windows-x64.zip"
                                    $TOMCAT_URLS = @(
                                        "https://archive.apache.org/dist/tomcat/tomcat-7/v$TOMCAT_VERSION/bin/apache-tomcat-$TOMCAT_VERSION-windows-x64.zip",
                                        "https://dlcdn.apache.org/tomcat/tomcat-7/v$TOMCAT_VERSION/bin/apache-tomcat-$TOMCAT_VERSION-windows-x64.zip",
                                        "https://downloads.apache.org/tomcat/tomcat-7/v$TOMCAT_VERSION/bin/apache-tomcat-$TOMCAT_VERSION-windows-x64.zip"
                                    )
                                    $JAVA_VERSION = "8"
                                    $JAVA_HOME = "C:\Program Files\Java\jdk8u412-b08"
                                    $JAVA_OPTS = "-Djava.awt.headless=true -Djava.security.egd=file:/dev/./urandom"
                                    $JAVA_BIN = "$JAVA_HOME\bin\java.exe"
                                    $CHECKSUM_URL = "https://archive.apache.org/dist/tomcat/tomcat-7/v$TOMCAT_VERSION/bin/apache-tomcat-$TOMCAT_VERSION-windows-x64.zip.sha512"
                                    $CHECKSUM = "e01bff687ca8480374324ac2f66ead5c60626b4db4cec93448820396fc7ec07dea1ad968d55b4bcd0a4362f3ad5d2080a1598d514da88ec9cbd2282b32a397a4"
                                    Write-Log "Tomcat 7 requires Java 8. JAVA_HOME will be set to $JAVA_HOME."
                                }
                                "8.5" {
                                    $TOMCAT_VERSION = "8.5.100"
                                    $LOCAL_FILE = "$env:TEMP\apache-tomcat-$TOMCAT_VERSION-windows-x64.zip"
                                    $TOMCAT_URLS = @(
                                        "https://dlcdn.apache.org/tomcat/tomcat-8/v$TOMCAT_VERSION/bin/apache-tomcat-$TOMCAT_VERSION-windows-x64.zip",
                                        "https://archive.apache.org/dist/tomcat/tomcat-8/v$TOMCAT_VERSION/bin/apache-tomcat-$TOMCAT_VERSION-windows-x64.zip",
                                        "https://downloads.apache.org/tomcat/tomcat-8/v$TOMCAT_VERSION/bin/apache-tomcat-$TOMCAT_VERSION-windows-x64.zip",
                                        "https://dlcdn.apache.org/tomcat/tomcat-8/v$TOMCAT_VERSION/bin/apache-tomcat-$TOMCAT_VERSION.zip",
                                        "https://archive.apache.org/dist/tomcat/tomcat-8/v$TOMCAT_VERSION/bin/apache-tomcat-$TOMCAT_VERSION.zip",
                                        "https://downloads.apache.org/tomcat/tomcat-8/v$TOMCAT_VERSION/bin/apache-tomcat-$TOMCAT_VERSION.zip"
                                    )
                                    $JAVA_VERSION = "11"
                                    $JAVA_HOME = "C:\Program Files\Java\jdk-11"
                                    $JAVA_OPTS = "-Djava.awt.headless=true -Djava.security.egd=file:/dev/./urandom --add-opens=java.base/java.lang=ALL-UNNAMED --add-opens=java.base/java.io=ALL-UNNAMED"
                                    $JAVA_BIN = "$JAVA_HOME\bin\java.exe"
                                    $CHECKSUM_URL = "https://archive.apache.org/dist/tomcat/tomcat-8/v$TOMCAT_VERSION/bin/apache-tomcat-$TOMCAT_VERSION-windows-x64.zip.sha512"
                                    $CHECKSUM = ""
                                    Write-Log "Tomcat 8.5 requires Java 11. JAVA_HOME will be set to $JAVA_HOME."
                                }
                                "9" {
                                    $TOMCAT_VERSION = "9.0.104"
                                    $LOCAL_FILE = "$env:TEMP\apache-tomcat-$TOMCAT_VERSION-windows-x64.zip"
                                    $TOMCAT_URLS = @(
                                        "https://dlcdn.apache.org/tomcat/tomcat-9/v$TOMCAT_VERSION/bin/apache-tomcat-$TOMCAT_VERSION-windows-x64.zip",
                                        "https://archive.apache.org/dist/tomcat/tomcat-9/v$TOMCAT_VERSION/bin/apache-tomcat-$TOMCAT_VERSION-windows-x64.zip",
                                        "https://downloads.apache.org/tomcat/tomcat-9/v$TOMCAT_VERSION/bin/apache-tomcat-$TOMCAT_VERSION-windows-x64.zip",
                                        "https://dlcdn.apache.org/tomcat/tomcat-9/v$TOMCAT_VERSION/bin/apache-tomcat-$TOMCAT_VERSION.zip",
                                        "https://archive.apache.org/dist/tomcat/tomcat-9/v$TOMCAT_VERSION/bin/apache-tomcat-$TOMCAT_VERSION.zip",
                                        "https://downloads.apache.org/tomcat/tomcat-9/v$TOMCAT_VERSION/bin/apache-tomcat-$TOMCAT_VERSION.zip"
                                    )
                                    $JAVA_VERSION = "11"
                                    $JAVA_HOME = "C:\Program Files\Java\jdk-11"
                                    $JAVA_OPTS = "-Djava.awt.headless=true -Djava.security.egd=file:/dev/./urandom"
                                    $JAVA_BIN = "$JAVA_HOME\bin\java.exe"
                                    $CHECKSUM_URL = "https://archive.apache.org/dist/tomcat/tomcat-9/v$TOMCAT_VERSION/bin/apache-tomcat-$TOMCAT_VERSION-windows-x64.zip.sha512"
                                    $CHECKSUM = ""
                                    Write-Log "Tomcat 9 requires Java 11. JAVA_HOME will be set to $JAVA_HOME."
                                }
                                "10.0" {
                                    $TOMCAT_VERSION = "10.0.27"
                                    $LOCAL_FILE = "$env:TEMP\apache-tomcat-$TOMCAT_VERSION-windows-x64.zip"
                                    $TOMCAT_URLS = @(
                                        "https://dlcdn.apache.org/tomcat/tomcat-10/v$TOMCAT_VERSION/bin/apache-tomcat-$TOMCAT_VERSION-windows-x64.zip",
                                        "https://archive.apache.org/dist/tomcat/tomcat-10/v$TOMCAT_VERSION/bin/apache-tomcat-$TOMCAT_VERSION-windows-x64.zip",
                                        "https://downloads.apache.org/tomcat/tomcat-10/v$TOMCAT_VERSION/bin/apache-tomcat-$TOMCAT_VERSION-windows-x64.zip",
                                        "https://dlcdn.apache.org/tomcat/tomcat-10/v$TOMCAT_VERSION/bin/apache-tomcat-$TOMCAT_VERSION.zip",
                                        "https://archive.apache.org/dist/tomcat/tomcat-10/v$TOMCAT_VERSION/bin/apache-tomcat-$TOMCAT_VERSION.zip",
                                        "https://downloads.apache.org/tomcat/tomcat-10/v$TOMCAT_VERSION/bin/apache-tomcat-$TOMCAT_VERSION.zip"
                                    )
                                    $JAVA_VERSION = "11"
                                    $JAVA_HOME = "C:\Program Files\Java\jdk-11"
                                    $JAVA_OPTS = "-Djava.awt.headless=true -Djava.security.egd=file:/dev/./urandom"
                                    $JAVA_BIN = "$JAVA_HOME\bin\java.exe"
                                    $CHECKSUM_URL = "https://archive.apache.org/dist/tomcat/tomcat-10/v$TOMCAT_VERSION/bin/apache-tomcat-$TOMCAT_VERSION-windows-x64.zip.sha512"
                                    $CHECKSUM = ""
                                    Write-Log "Tomcat 10.0 requires Java 11. JAVA_HOME will be set to $JAVA_HOME."
                                }
                                "10.1" {
                                    $TOMCAT_VERSION = "10.1.31"
                                    $LOCAL_FILE = "$env:TEMP\apache-tomcat-$TOMCAT_VERSION-windows-x64.zip"
                                    $TOMCAT_URLS = @(
                                        "https://dlcdn.apache.org/tomcat/tomcat-10/v$TOMCAT_VERSION/bin/apache-tomcat-$TOMCAT_VERSION-windows-x64.zip",
                                        "https://archive.apache.org/dist/tomcat/tomcat-10/v$TOMCAT_VERSION/bin/apache-tomcat-$TOMCAT_VERSION-windows-x64.zip",
                                        "https://downloads.apache.org/tomcat/tomcat-10/v$TOMCAT_VERSION/bin/apache-tomcat-$TOMCAT_VERSION-windows-x64.zip",
                                        "https://dlcdn.apache.org/tomcat/tomcat-10/v$TOMCAT_VERSION/bin/apache-tomcat-$TOMCAT_VERSION.zip",
                                        "https://archive.apache.org/dist/tomcat/tomcat-10/v$TOMCAT_VERSION/bin/apache-tomcat-$TOMCAT_VERSION.zip",
                                        "https://downloads.apache.org/tomcat/tomcat-10/v$TOMCAT_VERSION/bin/apache-tomcat-$TOMCAT_VERSION.zip"
                                    )
                                    $JAVA_VERSION = "11"
                                    $JAVA_HOME = "C:\Program Files\Java\jdk-11"
                                    $JAVA_OPTS = "-Djava.awt.headless=true -Djava.security.egd=file:/dev/./urandom"
                                    $JAVA_BIN = "$JAVA_HOME\bin\java.exe"
                                    $CHECKSUM_URL = "https://archive.apache.org/dist/tomcat/tomcat-10/v$TOMCAT_VERSION/bin/apache-tomcat-$TOMCAT_VERSION-windows-x64.zip.sha512"
                                    $CHECKSUM = ""
                                    Write-Log "Tomcat 10.1 requires Java 11 (with PBKDF2 support). JAVA_HOME will be set to $JAVA_HOME."
                                }
                                default {
                                    Write-Log "ERROR: Unsupported Tomcat version. Choose 7, 8.5, 9, 10.0, or 10.1."
                                    throw "Unsupported version"
                                }
                            }

                            Write-Log "Starting installation of Tomcat $TomcatMajor ($TOMCAT_VERSION)"

                            # Check internet connectivity
                            Write-Log "Checking internet connectivity..."
                            try {
                                Test-Connection -ComputerName google.com -Count 1 -Quiet | Out-Null
                            } catch {
                                Write-Log "ERROR: No internet connection. Please connect to the internet and try again."
                                throw "No internet connection"
                            }

                            # Install required Java version
                            Write-Log "Checking OpenJDK $JAVA_VERSION..."
                            if ($JAVA_VERSION -eq "8") {
                                if (-not (Test-Path "$JAVA_HOME\bin\java.exe")) {
                                    Write-Log "OpenJDK 8 not found. Attempting manual installation..."
                                    Install-OpenJDK8Manual
                                }
                            } elseif ($JAVA_VERSION -eq "11") {
                                if (-not (Test-Path "$JAVA_HOME\bin\java.exe")) {
                                    Write-Log "OpenJDK 11 not found. Attempting manual installation..."
                                    Install-OpenJDK11Manual
                                }
                            }

                            # Verify Java installation
                            Write-Log "Verifying Java installation..."
                            if (-not (Test-Path $JAVA_BIN)) {
                                Write-Log "ERROR: Java binary $JAVA_BIN not found. Ensure $JAVA_HOME is correct."
                                throw "Java not found"
                            }
                            $JAVA_VERSION_OUTPUT = & $JAVA_BIN -version 2>&1 | ForEach-Object { $_ -replace '^.*?(openjdk version.*)$', '$1' } | Out-String
                            Write-Log "java -version output: $JAVA_VERSION_OUTPUT"
                            if ($JAVA_VERSION_OUTPUT -notmatch "1${JAVA_VERSION}\." -and $JAVA_VERSION_OUTPUT -notmatch "${JAVA_VERSION}\." -and $JAVA_VERSION_OUTPUT -notmatch "openjdk version.*${JAVA_VERSION}") {
                                Write-Log "ERROR: Java $JAVA_VERSION not detected with $JAVA_BIN."
                                throw "Java version mismatch"
                            }

                            # Create tomcat user
                            Write-Log "Creating tomcat user..."
                            $tomcatUser = Get-LocalUser -Name "tomcat" -ErrorAction SilentlyContinue
                            if (-not $tomcatUser) {
                                New-LocalUser -Name "tomcat" -NoPassword -UserMayNotChangePassword -AccountNeverExpires -Description "Tomcat Service User" | Out-Null
                            } else {
                                Write-Log "Tomcat user already exists"
                            }

                            # Download Tomcat with fallback
                            Write-Log "Downloading Apache Tomcat $TOMCAT_VERSION..."
                            $DOWNLOADED = $false
                            $downloadedFilePath = $null
                            foreach ($TOMCAT_URL in $TOMCAT_URLS) {
                                $fileName = Split-Path $TOMCAT_URL -Leaf
                                $targetPath = Join-Path $env:TEMP $fileName
                                Write-Log "Attempting download from $TOMCAT_URL..."
                                try {
                                    $webClient = New-Object System.Net.WebClient
                                    $webClient.DownloadFile($TOMCAT_URL, $targetPath)
                                    Write-Log "Successfully downloaded from $TOMCAT_URL"
                                    $DOWNLOADED = $true
                                    $downloadedFilePath = $targetPath
                                    break
                                } catch {
                                    Write-Log "WARNING: Failed to download from $TOMCAT_URL. Trying next URL..."
                                    Start-Sleep -Seconds 2
                                }
                            }

                            # Check for local file if download failed
                            if (-not $DOWNLOADED) {
                                Write-Log "All download URLs failed. Checking for local file at $LOCAL_FILE..."
                                if (Test-Path $LOCAL_FILE) {
                                    Write-Log "Found local file $LOCAL_FILE. Proceeding with installation..."
                                    $DOWNLOADED = $true
                                    $downloadedFilePath = $LOCAL_FILE
                                } else {
                                    Write-Log "ERROR: Failed to download Tomcat archive from all URLs and no local file found."
                                    Write-Log "URLs tried: $TOMCAT_URLS"
                                    throw "Download failed"
                                }
                            }

                            # Verify downloaded file
                            if (-not (Test-Path $downloadedFilePath)) {
                                Write-Log "ERROR: Downloaded Tomcat archive not found."
                                throw "Archive not found"
                            }

                            # Verify checksum
                            Write-Log "Verifying checksum of downloaded file..."
                            $checksumFileUrl = $downloadedFilePath + ".sha512"
                            $baseName = [System.IO.Path]::GetFileName($downloadedFilePath)
                            $checksumUrlBase = "https://archive.apache.org/dist/tomcat/tomcat-$($TomcatMajor -replace '\\.','')/v$TOMCAT_VERSION/bin/$baseName.sha512"
                            $skipChecksum = $false
                            try {
                                (New-Object System.Net.WebClient).DownloadFile($checksumUrlBase, $checksumFileUrl)
                            } catch {
                                $is404 = $false
                                if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
                                    if ($_.Exception.Response.StatusCode.value__ -eq 404) {
                                        $is404 = $true
                                    }
                                } elseif ($_.Exception.Message -match "404") {
                                    $is404 = $true
                                }
                                if ($is404) {
                                    Write-Log "WARNING: No checksum file found for $baseName. Skipping checksum verification."
                                    $skipChecksum = $true
                                } else {
                                    Write-Log "WARNING: Failed to download checksum. Continuing without verification."
                                    $skipChecksum = $true
                                }
                            }
                            if (-not $skipChecksum) {
                                try {
                                    $checksumContent = Get-Content $checksumFileUrl | Select-Object -First 1
                                    $expectedChecksum = $checksumContent.Split(" ")[0].Trim().ToLower()
                                    $COMPUTED_CHECKSUM = (Get-FileHash -Path $downloadedFilePath -Algorithm SHA512).Hash.ToLower()
                                    if ($COMPUTED_CHECKSUM -ne $expectedChecksum) {
                                        Write-Log "ERROR: Checksum verification failed."
                                        Write-Log "Expected SHA512: $expectedChecksum"
                                        Write-Log "Computed SHA512: $COMPUTED_CHECKSUM"
                                        Remove-Item -Path $downloadedFilePath -Force
                                        throw "Checksum verification failed"
                                    }
                                    Write-Log "Checksum verification passed."
                                } catch {
                                    Write-Log "WARNING: Failed to verify checksum: $($_.Exception.Message)"
                                }
                            }

                            # Remove existing installation
                            Write-Log "Removing previous installations..."
                            if (Test-Path $TOMCAT_DIR) {
                                Remove-Item -Path $TOMCAT_DIR -Recurse -Force
                            }

                            # Extract Tomcat
                            Write-Log "Extracting Tomcat to $TOMCAT_DIR..."
                            New-Item -ItemType Directory -Path $TOMCAT_DIR -Force | Out-Null
                            try {
                                Expand-Archive -Path $downloadedFilePath -DestinationPath $TOMCAT_DIR -Force
                            } catch {
                                Write-Log "ERROR: Failed to extract Tomcat archive: $($_.Exception.Message)"
                                throw
                            }
                            $extractedFolder = Get-ChildItem -Path $TOMCAT_DIR -Directory | Select-Object -First 1
                            Get-ChildItem -Path "$TOMCAT_DIR\$($extractedFolder.Name)" | Move-Item -Destination $TOMCAT_DIR -Force
                            Remove-Item -Path "$TOMCAT_DIR\$($extractedFolder.Name)" -Recurse -Force
                            Remove-Item -Path $downloadedFilePath -Force

                            # Verify startup.bat exists
                            $startupBin = "$TOMCAT_DIR\bin\startup.bat"
                            if (-not (Test-Path $startupBin)) {
                                Write-Log "ERROR: startup.bat not found in $TOMCAT_DIR\bin."
                                throw "Invalid Tomcat archive"
                            }

                            # Set permissions
                            Write-Log "Setting permissions..."
                            try {
                                $acl = Get-Acl $TOMCAT_DIR
                                $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("tomcat", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
                                $acl.SetAccessRule($rule)
                                Set-Acl -Path $TOMCAT_DIR -AclObject $acl
                            } catch {
                                Write-Log "ERROR: Failed to set permissions: $($_.Exception.Message)"
                                throw
                            }

                            # Install Tomcat as a Windows service
                            Write-Log "Installing Tomcat Windows service..."
                            $serviceName = "Tomcat10"
                            $serviceBat = "$TOMCAT_DIR\bin\service.bat"
                            $serviceExists = $false
                            try {
                                $svc = Get-Service -Name $serviceName -ErrorAction Stop
                                $serviceExists = $true
                                Write-Log "Tomcat service '$serviceName' already exists. Removing it..."
                                if (Test-Path $serviceBat) {
                                    & $serviceBat remove
                                    Start-Sleep -Seconds 2
                                }
                            } catch {
                                $serviceExists = $false
                            }
                            
                            if (Test-Path $serviceBat) {
                                try {
                                    Start-Process -FilePath "cmd.exe" -ArgumentList "/c $serviceBat install" -WorkingDirectory "$TOMCAT_DIR\bin" -Wait -NoNewWindow
                                    Write-Log "Tomcat service '$serviceName' installed."
                                } catch {
                                    Write-Log "ERROR: Failed to install Tomcat as a service: $($_.Exception.Message)"
                                    throw
                                }
                            } else {
                                Write-Log "ERROR: service.bat not found."
                                throw "Service installation failed"
                            }
                            
                            # Verify service registration
                            try {
                                $svc = Get-WmiObject -Class Win32_Service -Filter "Name='$serviceName'"
                                if ($svc) {
                                    Write-Log "Service '$serviceName' registered. Path: $($svc.PathName)"
                                } else {
                                    Write-Log "ERROR: Service '$serviceName' not found after installation."
                                    throw "Service registration failed"
                                }
                            } catch {
                                Write-Log "ERROR: Could not verify service registration: $($_.Exception.Message)"
                                throw
                            }

                            Write-Log "JAVA_HOME (system): $([Environment]::GetEnvironmentVariable('JAVA_HOME', [EnvironmentVariableTarget]::Machine))"
                            Write-Log "JAVA_HOME (process): $env:JAVA_HOME"

                            if ($StartMode -eq "bat") {
                                Write-Log "Starting Tomcat using startup.bat..."
                                try {
                                    $startupBat = "$TOMCAT_DIR\bin\startup.bat"
                                    Start-Process -FilePath "cmd.exe" -ArgumentList "/c $startupBat" -WorkingDirectory "$TOMCAT_DIR\bin" -NoNewWindow
                                    Write-Log "Started Tomcat via startup.bat."
                                } catch {
                                    Write-Log "ERROR: Failed to run startup.bat: $($_.Exception.Message)"
                                    throw
                                }
                            } else {
                                Write-Log "Attempting to start Tomcat service..."
                                $serviceStarted = Start-TomcatService
                            }

                            # Wait for Tomcat to initialize
                            Write-Log "Waiting 5 seconds for Tomcat to initialize..."
                            Start-Sleep -Seconds 5

                            # Verify installation
                            Write-Log "Verifying installation..."
                            $tomcatRunning = $false
                            try {
                                $response = Invoke-WebRequest -Uri "http://localhost:8080" -UseBasicParsing -TimeoutSec 10
                                if ($response.StatusCode -eq 200) {
                                    Write-Log "SUCCESS: Tomcat $TOMCAT_VERSION is running at http://localhost:8080"
                                    $tomcatRunning = $true
                                }
                            } catch {
                                Write-Log "WARNING: Tomcat started but web interface not accessible. Check $TOMCAT_DIR\logs\catalina.out."
                            }

                            # Set CATALINA_HOME environment variable
                            Write-Log "Setting CATALINA_HOME environment variable to $TOMCAT_DIR..."
                            [Environment]::SetEnvironmentVariable("CATALINA_HOME", $TOMCAT_DIR, [EnvironmentVariableTarget]::Machine)
                            $env:CATALINA_HOME = $TOMCAT_DIR

                            # Update tomcat-users.xml
                            Set-TomcatUser -TomcatHome $TOMCAT_DIR -Username $Username -Password $Password -Roles $Roles -Version $TOMCAT_VERSION.Split('.')[0..1] -join '.'

                            Write-Log "Installation complete. Configure tomcat-users.xml in $TOMCAT_DIR\conf for auditing."
                            if (-not $tomcatRunning) {
                                Write-Log "WARNING: Tomcat is not running as a service."
                            }
                        }
                        
                        # Function to update or create a Tomcat user in tomcat-users.xml
                        function Set-TomcatUser {
                            param(
                                [string]$TomcatHome,
                                [string]$Username,
                                [string]$Password,
                                [string]$Roles,
                                [string]$Version
                            )
                            $usersXmlPath = Join-Path $TomcatHome "conf\tomcat-users.xml"
                            if (-not (Test-Path $usersXmlPath)) {
                                Write-Log "tomcat-users.xml not found. Creating new file."
                                $xmlContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<tomcat-users></tomcat-users>
"@
                                Set-Content -Path $usersXmlPath -Value $xmlContent -Encoding UTF8
                            }
                            [xml]$usersXml = Get-Content $usersXmlPath
                            $userNode = $usersXml.SelectSingleNode("//user[@username='$Username']")
                            $binPath = Join-Path $TomcatHome "bin"
                            $hash = $Password
                            $finalHashResult = $null
                            if ($Version -eq "7.0") {
                                $algorithm = "SHA-256"
                                $digestScript = Join-Path $binPath "digest.bat"
                                if (Test-Path $digestScript) {
                                    $hashResult = & $digestScript -a $algorithm $Password | Select-String -Pattern "^[0-9a-fA-F]{64}$"
                                    $firstResult = $hashResult | Select-Object -First 1
                                    if ($firstResult) {
                                        if ($firstResult -is [System.Management.Automation.MatchInfo]) {
                                            $finalHashResult = $firstResult.Line
                                        } else {
                                            $finalHashResult = ($firstResult | Out-String).Trim()
                                        }
                                    }
                                }
                            } elseif ($Version -in @("8.5", "9.0", "10.0", "10.1")) {
                                $algorithm = "PBKDF2WithHmacSHA512"
                                $digestScript = Join-Path $binPath "digest.bat"
                                if (Test-Path $digestScript) {
                                    $hashResult = & $digestScript -a $algorithm -i 10000 -s 16 $Password | Select-String -Pattern ":"
                                    $firstResult = $hashResult | Select-Object -First 1
                                    if ($firstResult) {
                                        if ($firstResult -is [System.Management.Automation.MatchInfo]) {
                                            $finalHashResult = $firstResult.Line.Split(":")[0]
                                        } else {
                                            $finalHashResult = (($firstResult | Out-String).Split(":")[0]).Trim()
                                        }
                                    }
                                }
                            }
                            if ($finalHashResult -and $finalHashResult -ne "") { $hash = [string]$finalHashResult }
                            if ($userNode -ne $null) {
                                $userNode.SetAttribute("password", $hash)
                                $userNode.SetAttribute("roles", $Roles)
                            } else {
                                $newUser = $usersXml.CreateElement("user")
                                $newUser.SetAttribute("username", $Username)
                                $newUser.SetAttribute("password", $hash)
                                $newUser.SetAttribute("roles", $Roles)
                                $usersXml.DocumentElement.AppendChild($newUser) | Out-Null
                            }
                            $usersXml.Save($usersXmlPath)
                            Write-Log "Configured Tomcat user $Username with roles $Roles in tomcat-users.xml."
                        }
                        
                        # Function to find and start the Tomcat service
                        function Start-TomcatService {
                            $tomcatServices = Get-Service | Where-Object {
                                $_.Name -like '*Tomcat*' -or $_.DisplayName -like '*Tomcat*'
                            }

                            if (-not $tomcatServices -or $tomcatServices.Count -eq 0) {
                                Write-Log "ERROR: No Tomcat-related Windows service found."
                                return $false
                            }

                            Write-Log "Found the following Tomcat-related services:"
                            foreach ($svc in $tomcatServices) {
                                Write-Log "  Name: $($svc.Name), DisplayName: $($svc.DisplayName), Status: $($svc.Status)"
                            }

                            $serviceToStart = $tomcatServices | Where-Object { $_.Status -eq 'Stopped' } | Select-Object -First 1
                            if (-not $serviceToStart) {
                                $serviceToStart = $tomcatServices | Select-Object -First 1
                            }

                            if (-not $serviceToStart) {
                                Write-Log "ERROR: No Tomcat service found to start."
                                return $false
                            }

                            Write-Log "Attempting to start Tomcat service: Name='$($serviceToStart.Name)'"

                            try {
                                if ($serviceToStart.Status -eq 'Running') {
                                    Write-Log "Tomcat service '$($serviceToStart.Name)' is already running."
                                    return $true
                                } else {
                                    Start-Service -Name $serviceToStart.Name
                                    Start-Sleep -Seconds 3
                                    $svc = Get-Service -Name $serviceToStart.Name
                                    if ($svc.Status -eq 'Running') {
                                        Write-Log "Tomcat service '$($serviceToStart.Name)' started successfully."
                                        return $true
                                    } else {
                                        Write-Log "Tomcat service '$($serviceToStart.Name)' failed to start. Status: $($svc.Status)"
                                        return $false
                                    }
                                }
                            } catch {
                                Write-Log "ERROR: Failed to start Tomcat service: $($_.Exception.Message)"
                                return $false
                            }
                        }
                        
                        # Main execution
                        Test-Admin
                        
                        if ($Action -eq "install") {
                            if (-not $TomcatVersion) {
                                Write-Log "ERROR: Please specify a Tomcat version (7, 8.5, 9, 10.0, or 10.1)"
                                throw "Version required"
                            }
                            Install-Tomcat -TomcatMajor $TomcatVersion -Username $Username -Password $Password -Roles $Roles -StartMode $StartMode
                        } elseif ($Action -eq "uninstall") {
                            Uninstall-Tomcat
                        }
                        
                        return @{ Success = $true; Message = "Operation completed successfully" }
                    }
                    ArgumentList = @($Action, $TomcatVersion, $Username, $Password, $Roles, $StartMode)
                    ErrorAction = "Stop"
                }
                
                if ($Credential) {
                    $invokeParams.Credential = $Credential
                }
                
                if ($authMethod -ne "Default") {
                    $invokeParams.Authentication = $authMethod
                }
                
                $result = Invoke-Command @invokeParams
                $connected = $true
                Write-Host "SUCCESS: Connected to $server using $authMethod authentication" -ForegroundColor Green
                Write-Host "Result: $($result.Message)" -ForegroundColor Green
                break
                
            } catch {
                $lastError = $_
                Write-Host "Failed to connect using $authMethod: $($_.Exception.Message)" -ForegroundColor Yellow
                continue
            }
        }
        
        if (-not $connected) {
            Write-Host "ERROR: Failed to connect to $server using all authentication methods" -ForegroundColor Red
            Write-Host "Last error: $($lastError.Exception.Message)" -ForegroundColor Red
            Write-Host "Ensure WinRM is enabled and configured on the target server." -ForegroundColor Yellow
            continue
        }
        
    } catch {
        Write-Host "ERROR: Failed to process server $server : $_" -ForegroundColor Red
        continue
    }
}

Write-Host ""
Write-Host "Remote Tomcat management operation completed."
Write-Host "Check individual server logs at: \\$server\C$\Users\$env:USERNAME\AppData\Local\Temp\TomcatManager.log"

