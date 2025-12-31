# Example Configuration Files

This directory contains example configuration files for testing HSTS configuration.

## Files

- **test_web.xml** - Example Tomcat web.xml file (minimal configuration)
- **test_web.config** - Example IIS web.config file (minimal configuration with customHeaders section)
- **web.xml** - Another example Tomcat web.xml file

## Usage

These files can be used to test the HSTS configuration scripts:

### Tomcat Example (Unix/Linux)
```bash
# Audit the example file
sudo ./src/unix/UpdateTomcatHstsUnix.sh --mode audit --custom-conf=examples

# Configure the example file (dry run)
sudo ./src/unix/UpdateTomcatHstsUnix.sh --mode configure --custom-conf=examples --dry-run
```

### Tomcat Example (Windows)
```powershell
# Audit the example file
.\src\windows\UpdateTomcatHstsWin.ps1 -Mode audit -CustomPaths @("examples")

# Configure the example file (dry run)
.\src\windows\UpdateTomcatHstsWin.ps1 -Mode configure -CustomPaths @("examples") -DryRun
```

### IIS Example (Windows)
```powershell
# Audit the example file
.\src\windows\UpdateIisHstsWin.ps1 -Mode audit -ConfigPath "examples\test_web.config"

# Configure the example file (dry run)
.\src\windows\UpdateIisHstsWin.ps1 -Mode configure -ConfigPath "examples\test_web.config" -DryRun
```

## Note

These are minimal example files. In production, your configuration files will have additional settings and may be more complex. Always test in a non-production environment first.

