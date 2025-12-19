# Example Configuration Files

This directory contains example configuration files for testing HSTS configuration.

## Files

- **test_web.xml** - Example Tomcat web.xml file (minimal configuration)
- **test_web.config** - Example IIS web.config file (minimal configuration with customHeaders section)
- **web.xml** - Another example Tomcat web.xml file

## Usage

These files can be used to test the HSTS configuration scripts:

### Tomcat Example
```bash
# Audit the example file
./tomcat_hsts.sh --mode audit --config_path examples/test_web.xml

# Configure the example file (dry run)
./tomcat_hsts.sh --mode configure --config_path examples/test_web.xml --dry_run
```

### IIS Example
```powershell
# Audit the example file
.\iis_hsts.ps1 -Mode audit -ConfigPath "examples\test_web.config"

# Configure the example file (dry run)
.\iis_hsts.ps1 -Mode configure -ConfigPath "examples\test_web.config" -DryRun
```

## Note

These are minimal example files. In production, your configuration files will have additional settings and may be more complex. Always test in a non-production environment first.

