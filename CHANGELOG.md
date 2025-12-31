# Changelog

All notable changes to the HSTS Compliance Tools project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-12-31

### 🎉 Initial Production Release

This is the first stable release of the HSTS Compliance Tools for Apache Tomcat and Microsoft IIS.

### Added

#### Core Features
- **Audit Mode**: Check HSTS configuration compliance without making changes
- **Configure Mode**: Automatically fix HSTS configuration to OWASP standards
- **Auto-Detection**: Automatically find Tomcat and IIS installations across common paths
- **Backup Support**: Automatic timestamped backups before any modifications
- **Dry Run**: Preview changes without applying them
- **XML Validation**: Validates XML structure before and after modifications
- **Idempotency**: Ensures exactly one compliant HSTS definition (removes duplicates)

#### Platform Support
- **Windows**: PowerShell scripts for Tomcat and IIS
- **Unix/Linux**: Bash scripts for Tomcat (Ubuntu, Debian, Kali, RHEL, CentOS)
- **Remote Execution**: Windows scripts support remote execution via PowerShell Remoting (WinRM)
- **Version Support**: Works with Tomcat 7.0+ and IIS 7.0+, including Tomcat 11.0 and native IIS 10.0+ HSTS

#### Enterprise Features
- **JSON Output**: Machine-readable output for SIEM/dashboard integration
- **Consolidated Reporting**: Single master report (JSON/CSV) for entire server fleet
- **Server List Files**: Execute on multiple servers from a list file
- **Multi-Instance Detection**: Discover all Tomcat/IIS instances on a single host
- **Report Generation**: Save detailed audit results for archival and compliance

#### Security Features
- Path traversal protection in all path-accepting parameters
- Null byte detection
- Symlink/junction detection and warnings
- Restricted permissions (600) for sensitive log files
- No hardcoded passwords or credentials

#### Installation Scripts
- `TomcatManager.ps1`: Windows Tomcat installation (7.0, 8.5, 9.0, 10.0, 10.1)
- `IisManager.ps1`: Windows IIS installation and configuration
- `tomcat_manager.sh`: Unix/Linux Tomcat installation
- Remote installation variants for all scripts

#### Documentation
- Comprehensive README with examples and troubleshooting
- INSTALLATION.md with step-by-step guides
- CONTRIBUTING.md with development guidelines
- VERIFICATION.md for testing procedures
- DEPLOYMENT_EMAIL_TEMPLATE.md for enterprise rollouts

#### Testing
- 5-scenario test suite for Windows (Tomcat and IIS)
- 4-scenario test suite for Unix/Linux (Tomcat)
- CI/CD pipeline with syntax validation, linting, and security scanning
- Automated release workflow with changelog generation

### Security

- All scripts follow OWASP HSTS Cheat Sheet recommendations
- Required: `max-age=31536000` (1 year)
- Required: `includeSubDomains`
- Optional: `preload` (allowed but not configured by default)

---

## [Unreleased]

### Planned Features
- Apache HTTP Server HSTS support
- Nginx HSTS configuration support
- Ansible playbook integration
- Terraform module for cloud deployments

---

## Version History

| Version | Date | Description |
|---------|------|-------------|
| 1.0.0 | 2025-12-31 | Initial production release |

---

[1.0.0]: https://github.com/yourusername/HSTS_Compliance_Apache-Tomcat_IIS/releases/tag/v1.0.0
[Unreleased]: https://github.com/yourusername/HSTS_Compliance_Apache-Tomcat_IIS/compare/v1.0.0...HEAD
