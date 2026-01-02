# Platform Support Matrix

## Overview

The HSTS Compliance Suite provides comprehensive support for Apache Tomcat and Microsoft IIS across all modern versions, with forward compatibility built-in.

---

## Apache Tomcat Support

### Supported Versions

| Version | Status | Jakarta EE | Namespace | Notes |
|---------|--------|------------|-----------|-------|
| **11.x** | ✅ Fully Supported | Yes | `jakarta.ee` | Latest version with Jakarta EE |
| **10.1.x** | ✅ Fully Supported | Yes | `jakarta.ee` | Jakarta EE 10 |
| **10.0.x** | ✅ Fully Supported | Yes | `jakarta.ee` | Jakarta EE 9 |
| **9.0.x** | ✅ Fully Supported | No | `javax` | Java EE 8 |
| **8.5.x** | ✅ Fully Supported | No | `javax` | Java EE 7 |
| **8.0.x** | ✅ Fully Supported | No | `javax` | Java EE 7 (EOL) |
| **7.0.x** | ✅ Fully Supported | No | `javax` | Java EE 6 (EOL) |

### Version Detection

The scripts automatically detect Tomcat versions through:
- `RELEASE-NOTES` file parsing
- `version.sh` execution
- JAR manifest inspection
- Environment variables (`CATALINA_HOME`, `CATALINA_BASE`)

### HSTS Filter Support

**HttpHeaderSecurityFilter** support added in:
- Tomcat 9.0.0.M6+
- Tomcat 8.5.1+
- Tomcat 8.0.35+
- Tomcat 7.0.69+

**All supported versions include HSTS filter support.**

### Forward Compatibility

The scripts are designed to work with **future Tomcat versions** (12.x, 13.x, etc.) through:

1. **Version-agnostic detection:**
   ```bash
   # Supports any major version >= 9
   if [[ $major -ge 9 ]]; then return 0; fi
   ```

2. **Namespace flexibility:**
   - Supports both `javax` (legacy) and `jakarta.ee` (modern) namespaces
   - Automatically detects XML namespace in use

3. **Path scanning:**
   - Searches for `tomcat*` directories
   - No hardcoded version limits
   - Package manager integration (dpkg, rpm, pacman)

---

## Microsoft IIS Support

### Supported Versions

| Version | Status | Native HSTS | Notes |
|---------|--------|-------------|-------|
| **IIS 10.0+** | ✅ Fully Supported | Yes | Windows Server 2016+ |
| **IIS 8.5** | ✅ Fully Supported | No | Windows Server 2012 R2 |
| **IIS 8.0** | ✅ Fully Supported | No | Windows Server 2012 |
| **IIS 7.5** | ✅ Fully Supported | No | Windows Server 2008 R2 |
| **IIS 7.0** | ✅ Fully Supported | No | Windows Server 2008 |

### Native HSTS Support

**IIS 10.0+** includes native HSTS configuration:
```xml
<hsts enabled="true" max-age="31536000" includeSubDomains="true" />
```

The scripts automatically detect and configure both:
- Native IIS HSTS (IIS 10.0+)
- Custom headers (all versions)

### Forward Compatibility

Future IIS versions will be automatically supported through:
- Registry-based detection
- Service enumeration
- File system scanning
- No version-specific code

---

## Operating System Support

### Linux/Unix

| Distribution | Status | Package Manager | Notes |
|--------------|--------|-----------------|-------|
| **Ubuntu** | ✅ Supported | dpkg/apt | All LTS versions |
| **Debian** | ✅ Supported | dpkg/apt | All stable versions |
| **Kali Linux** | ✅ Supported | dpkg/apt | Latest versions |
| **RHEL** | ✅ Supported | rpm/yum | 7.x, 8.x, 9.x |
| **CentOS** | ✅ Supported | rpm/yum | 7.x, 8.x, Stream |
| **Rocky Linux** | ✅ Supported | rpm/dnf | 8.x, 9.x |
| **AlmaLinux** | ✅ Supported | rpm/dnf | 8.x, 9.x |
| **Fedora** | ✅ Supported | rpm/dnf | Recent versions |
| **Arch Linux** | ✅ Supported | pacman | Rolling release |
| **openSUSE** | ✅ Supported | zypper | Leap, Tumbleweed |

### Windows

| Version | Status | PowerShell | Notes |
|---------|--------|------------|-------|
| **Windows Server 2022** | ✅ Supported | 5.1+ | Latest |
| **Windows Server 2019** | ✅ Supported | 5.1+ | Recommended |
| **Windows Server 2016** | ✅ Supported | 5.1+ | Supported |
| **Windows Server 2012 R2** | ✅ Supported | 5.1+ | Extended support |
| **Windows Server 2012** | ✅ Supported | 5.1+ | Extended support |
| **Windows 11** | ✅ Supported | 5.1+ | Desktop testing |
| **Windows 10** | ✅ Supported | 5.1+ | Desktop testing |

---

## Installation Path Detection

### Tomcat (Unix/Linux)

The scripts automatically search:

**Standard Paths:**
- `/opt/tomcat*/conf`
- `/usr/local/tomcat*/conf`
- `/var/lib/tomcat*/conf`
- `/etc/tomcat*/conf`
- `/srv/tomcat*/conf`
- `/app/tomcat*/conf`

**Package Manager Paths:**
- dpkg-installed locations
- rpm-installed locations
- pacman-installed locations

**Environment Variables:**
- `$CATALINA_HOME/conf`
- `$CATALINA_BASE/conf`

**Process Detection:**
- Running Tomcat processes
- systemd service files
- init.d scripts

### Tomcat (Windows)

The scripts automatically search:

**All Drive Letters** (C: through K:):
- `Program Files\Apache Software Foundation\Tomcat *\conf`
- `Program Files (x86)\Apache Software Foundation\Tomcat *\conf`
- `Tomcat*\conf`
- `Apache\Tomcat*\conf`

**Alternative Locations:**
- `C:\Apps\Tomcat*\conf`
- `C:\Applications\Tomcat*\conf`
- `C:\Software\Tomcat*\conf`

**Network Drives:**
- Mapped network drives scanned automatically

### IIS (Windows)

The scripts automatically search:

**Registry Detection:**
- `HKLM:\SOFTWARE\Microsoft\InetStp`
- `HKLM:\SOFTWARE\WOW6432Node\Microsoft\InetStp`

**Standard Paths:**
- `C:\inetpub\wwwroot\web.config`
- All drive letters checked
- Subdirectories scanned

**Service Detection:**
- W3SVC service paths
- IIS-related services

**Environment Variables:**
- `$env:IIS_PATH`
- `$env:WWWROOT`
- `$env:IIS_HOME`

---

## Future Version Support

### Automatic Support for New Versions

The scripts are designed to **automatically support future versions** without code changes:

1. **Version-agnostic logic:**
   - No hardcoded version limits
   - Major version comparison (`>= 9`)
   - Wildcard path scanning

2. **Namespace flexibility:**
   - Supports both `javax` and `jakarta.ee`
   - XML namespace auto-detection
   - No namespace-specific code

3. **Dynamic path discovery:**
   - Searches for `tomcat*` patterns
   - No version-specific paths required
   - Package manager integration

### Testing New Versions

To test with a new Tomcat version:

```bash
# Unix
sudo ./src/unix/UpdateTomcatHstsUnix.sh --mode audit --custom-conf=/path/to/tomcat-XX/conf

# Windows
.\src\windows\UpdateTomcatHstsWin.ps1 -Mode audit -CustomPaths @("C:\Tomcat-XX\conf")
```

---

## Compatibility Notes

### Tomcat 11.x (Jakarta EE)

**Namespace Change:**
- Old: `xmlns="http://xmlns.jcp.org/xml/ns/javaee"`
- New: `xmlns="https://jakarta.ee/xml/ns/jakartaee"`

**Fully Supported** - Scripts detect and handle both namespaces.

### Tomcat 10.x (Jakarta EE)

**First Jakarta EE version:**
- Tomcat 10.0.x = Jakarta EE 9
- Tomcat 10.1.x = Jakarta EE 10

**Fully Supported** - No code changes required.

### IIS 10.0+ (Native HSTS)

**Native HSTS element:**
```xml
<hsts enabled="true" max-age="31536000" includeSubDomains="true" />
```

**Fully Supported** - Scripts detect and configure native HSTS.

---

## Unsupported Platforms

### Not Supported

- ❌ **macOS** - Scripts designed for Linux/Unix servers only
- ❌ **Apache HTTP Server** - Different configuration method
- ❌ **Nginx** - Different configuration method
- ❌ **Tomcat 6.x and earlier** - End of life, no HSTS filter support

### Workarounds

For unsupported platforms, manual HSTS configuration is required. See [OWASP HSTS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html).

---

## Verification

### Check Supported Version

**Unix:**
```bash
# Check Tomcat version
cat /opt/tomcat/RELEASE-NOTES | grep "Apache Tomcat Version"

# Run audit
sudo ./src/unix/UpdateTomcatHstsUnix.sh --mode audit
```

**Windows:**
```powershell
# Check Tomcat version
Get-Content "C:\Tomcat\RELEASE-NOTES" | Select-String "Apache Tomcat Version"

# Run audit
.\src\windows\UpdateTomcatHstsWin.ps1 -Mode audit
```

### Verify HSTS Configuration

After configuration, verify headers are sent:

```bash
curl -I https://your-server.com | grep -i strict-transport-security
```

Expected output:
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

---

## Support Policy

### Current Support

- ✅ **Tomcat 7.0+** - All versions
- ✅ **IIS 7.0+** - All versions
- ✅ **Future versions** - Automatic support

### Updates

The project is maintained to support:
- Latest Tomcat releases
- Latest IIS releases
- Latest OS distributions
- Security updates

### Community

For questions or issues with specific versions:
1. Check [GitHub Issues](https://github.com/ZeroXSHDW/HSTS_Compliance_Apache-Tomcat_IIS/issues)
2. Review [docs/INSTALLATION.md](INSTALLATION.md)
3. See [docs/VERIFICATION.md](VERIFICATION.md)

---

**Last Updated:** 2026-01-02  
**Project Version:** 1.0.0  
**Supported Tomcat Versions:** 7.0 - 11.x and future  
**Supported IIS Versions:** 7.0 - 10.x and future
