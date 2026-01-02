#!/bin/bash
# Quick Start Script for HSTS Compliance Tools
# Auto-detects OS and runs the appropriate HSTS audit

set -e

echo "🔒 HSTS Compliance Tools - Quick Start"
echo "========================================"

OS="$(uname -s)"
case "${OS}" in
    Linux*)     machine=Linux;;
    Darwin*)    machine=Mac;;
    CYGWIN*)    machine=Cygwin;;
    MINGW*)     machine=MinGw;;
    *)          machine="UNKNOWN:${OS}"
esac

echo "Detected Platform: ${machine}"

if [ "$machine" == "Linux" ]; then
    echo "Running Unix/Linux Tomcat Audit..."
    if [ -f "./src/unix/UpdateTomcatHstsUnix.sh" ]; then
        sudo ./src/unix/UpdateTomcatHstsUnix.sh --mode audit
    else
        echo "Error: Script not found in current directory."
        echo "Please clone the repository and run this script from the root:"
        echo "git clone https://github.com/ZeroXSHDW/HSTS_Compliance_Apache-Tomcat_IIS.git"
        echo "cd HSTS_Compliance_Apache-Tomcat_IIS"
    fi
elif [[ "$machine" == "MinGw" || "$machine" == "Cygwin" ]]; then
    echo "This looks like a Windows environment (Git Bash/Cygwin)."
    echo "Please use PowerShell to run the Windows scripts:"
    echo ".\src\windows\UpdateTomcatHstsWin.ps1 -Mode audit"
    echo ".\src\windows\UpdateIisHstsWin.ps1 -Mode audit"
else
    echo "Unsupported platform for auto-audit: ${machine}"
    echo "Please refer to README.md for manual instructions."
fi
