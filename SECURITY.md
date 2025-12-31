# Security Policy

## Supported Versions

We release patches for security vulnerabilities for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

We take the security of HSTS Compliance Tools seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via one of the following methods:

1. **GitHub Private Vulnerability Reporting**: Use GitHub's private vulnerability reporting feature at the "Security" tab of this repository.

2. **Email**: Send details to the repository maintainers (add your security contact email here).

### What to Include

Please include the following information in your report:

- **Type of vulnerability** (e.g., path traversal, command injection, privilege escalation)
- **Full paths of source file(s)** related to the vulnerability
- **Location of affected code** (function name, line numbers)
- **Step-by-step instructions** to reproduce the issue
- **Proof-of-concept or exploit code** (if possible)
- **Impact assessment** of the vulnerability
- **Suggested fix** (if you have one)

### Response Timeline

- **Initial Response**: Within 48 hours of receiving your report
- **Status Update**: Within 7 days with our assessment
- **Fix Timeline**: Critical vulnerabilities will be addressed within 30 days

### What to Expect

1. **Acknowledgment**: We will acknowledge receipt of your report within 48 hours.

2. **Assessment**: We will investigate and determine the severity and impact of the vulnerability.

3. **Fix Development**: If confirmed, we will develop a fix and coordinate disclosure timing with you.

4. **Disclosure**: We will publish security advisories and release patches in a coordinated manner.

### Safe Harbor

We support responsible disclosure and will not take legal action against researchers who:

- Make a good faith effort to avoid privacy violations, data destruction, or service interruption
- Only interact with accounts you own or with explicit permission of the account holder
- Do not exploit a security issue for purposes other than verification
- Report vulnerabilities promptly and allow reasonable time for remediation
- Do not publicly disclose the vulnerability before it has been addressed

## Security Best Practices for Users

When using HSTS Compliance Tools, please follow these security guidelines:

### General

1. **Run with least privilege**: Only use Administrator/root when necessary
2. **Review before executing**: Always use `--dry-run` or `-DryRun` before making changes
3. **Backup configurations**: Scripts create backups, but consider additional backup strategies
4. **Monitor logs**: Review log files for any unexpected behavior

### Remote Execution (Windows PowerShell Remoting)

1. **Use HTTPS**: Configure WinRM to use HTTPS for encrypted communication
2. **Credential Security**: Never store credentials in plain text; use secure credential management
3. **Network Segmentation**: Limit WinRM access to management networks
4. **Audit Access**: Enable and review WinRM audit logs

### File Permissions

1. **Log Files**: Scripts create logs with restricted permissions; verify this in your environment
2. **Configuration Files**: Ensure web.xml/web.config files have appropriate permissions
3. **Backup Files**: Secure backup files with appropriate access controls

## Security Features in This Project

The HSTS Compliance Tools include several security features:

### Input Validation
- Path traversal protection (detects `..` and null bytes)
- Symlink/junction detection with warnings
- XML validation before and after modifications

### Safe Execution
- Automatic backups before any modifications
- Dry-run mode for previewing changes
- Interactive confirmation for destructive operations
- Force mode requires explicit opt-in

### Logging
- Timestamped logs with hostname
- Restricted log file permissions (600 on Unix)
- Detailed operation tracking for audit purposes

### Code Quality
- Strict error handling (`set -euo pipefail` in Bash)
- Comprehensive error messages with exit codes
- No hardcoded credentials or secrets

## Known Security Considerations

### WinRM Remote Execution
- Remote execution uses PowerShell Remoting which requires proper WinRM configuration
- Credentials are transmitted; ensure HTTPS is configured for WinRM
- See `INSTALLATION.md` for secure WinRM setup instructions

### XML Parsing
- Scripts parse XML configuration files; malformed XML is detected and rejected
- Complex XML structures may require manual review after modification

### Temporary Files
- Scripts use secure temporary file creation (`mktemp` on Unix)
- Temporary files are cleaned up automatically via trap handlers

## Updates and Patches

Security updates will be released as:

1. **Patch versions** (e.g., 1.0.1) for security fixes
2. **GitHub Security Advisories** for documented vulnerabilities
3. **Release notes** documenting security-related changes

Subscribe to repository releases to receive notifications of security updates.

---

Thank you for helping keep HSTS Compliance Tools and our users safe!
