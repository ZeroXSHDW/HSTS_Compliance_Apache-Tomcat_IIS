# Contributing Guidelines

Thank you for your interest in contributing to the HSTS Compliance Tools project! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Reporting Issues](#reporting-issues)

## Code of Conduct

- Be respectful and inclusive
- Welcome newcomers and help them learn
- Focus on constructive feedback
- Respect different viewpoints and experiences

## How to Contribute

### Reporting Bugs

If you find a bug, please create an issue with:
- **Description:** Clear description of the bug
- **Steps to Reproduce:** Detailed steps to reproduce the issue
- **Expected Behavior:** What should happen
- **Actual Behavior:** What actually happens
- **Environment:** OS, PowerShell/Bash version, Tomcat/IIS version
- **Error Messages:** Full error messages and stack traces
- **Logs:** Relevant log file excerpts (remove sensitive information)

### Suggesting Features

Feature suggestions are welcome! Please include:
- **Use Case:** Why this feature would be useful
- **Proposed Solution:** How you envision it working
- **Alternatives:** Other solutions you've considered

### Submitting Code Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes following our coding standards
4. Add tests if applicable
5. Ensure all tests pass
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## Development Setup

### Prerequisites

**For Windows Development:**
- PowerShell 5.1 or later
- Windows Server or Windows 10/11
- Administrator privileges for testing

**For Unix/Linux Development:**
- Bash 4.0 or later
- Linux/Unix server environment
- Root or sudo access for testing

### Cloning the Repository

```bash
git clone https://github.com/yourusername/HSTS_Compliance_Apache-Tomcat_IIS.git
cd HSTS_Compliance_Apache-Tomcat_IIS
```

### Running Tests

**Windows:**
```powershell
cd tests\Patch\windows
.\test_hsts_win.ps1
```

**Unix/Linux:**
```bash
cd tests/Patch/unix
sudo ./test_hsts_unix.sh
```

## Coding Standards

### PowerShell Scripts

1. **Function Naming:**
   - Use approved PowerShell verbs (Get, Set, Test, etc.)
   - Use PascalCase for function names
   - Use descriptive names: `Get-TomcatConfigPaths` not `Get-Paths`

2. **Error Handling:**
   - Use `try-catch` blocks for error handling
   - Log errors with `Log-Error` function
   - Use appropriate exit codes (0=success, 1=failure, 2=error)

3. **Comments:**
   - Add function headers with description, parameters, and return values
   - Comment complex logic
   - Use `# Function:` for function definitions

4. **Security:**
   - Always validate file paths (prevent path traversal)
   - Check for null bytes in paths
   - Warn about symlinks/junctions
   - Validate XML before and after modifications

5. **Code Style:**
   ```powershell
   # Good
   function Get-TomcatConfigPaths {
       param(
           [string]$CustomConfPath
       )
       # Function body
   }
   
   # Bad
   function get-paths($path) {
       # Function body
   }
   ```

### Bash Scripts

1. **Function Naming:**
   - Use lowercase with underscores: `get_tomcat_conf_paths`
   - Use descriptive names

2. **Error Handling:**
   - Use `set -euo pipefail` for strict error handling
   - Use `trap` for cleanup
   - Return appropriate exit codes

3. **Comments:**
   - Add function headers with description
   - Comment complex logic
   - Use `# Function:` for function definitions

4. **Security:**
   - Always validate file paths
   - Check for path traversal attempts
   - Validate XML before modifications

5. **Code Style:**
   ```bash
   # Good
   get_tomcat_conf_paths() {
       local custom_path="$1"
       # Function body
   }
   
   # Bad
   getPaths() {
       # Function body
   }
   ```

### General Guidelines

1. **Consistency:**
   - Follow existing code patterns
   - Maintain consistent formatting
   - Use the same logging approach as existing code

2. **Documentation:**
   - Update README.md if adding new features
   - Add comments for complex logic
   - Document new parameters and options

3. **Safety:**
   - Always create backups before modifications
   - Validate inputs
   - Test error conditions
   - Add safety checks for destructive operations

## Testing

### Test Requirements

- All new features must include tests
- Tests should cover both success and failure cases
- Tests should be runnable in isolated environments

### Running Tests

**Windows Tests:**
```powershell
cd tests\Patch\windows
.\test_hsts_win.ps1
```

**Unix Tests:**
```bash
cd tests/Patch/unix
sudo ./test_hsts_unix.sh
```

### Writing Tests

Tests should:
- Use example configuration files from `examples/` directory
- Test both audit and configure modes
- Verify XML structure after modifications
- Check for proper error handling
- Clean up test files after execution

## Pull Request Process

### Before Submitting

1. **Update Documentation:**
   - Update README.md if needed
   - Add/update comments in code
   - Update CHANGELOG if applicable

2. **Run Tests:**
   - Ensure all existing tests pass
   - Add tests for new features
   - Verify tests pass in clean environment

3. **Check Code Quality:**
   - Follow coding standards
   - Remove debug code
   - Remove commented-out code
   - Check for security issues

### Pull Request Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Code refactoring

## Testing
- [ ] Tests pass locally
- [ ] Tested on Windows (if applicable)
- [ ] Tested on Unix/Linux (if applicable)

## Checklist
- [ ] Code follows coding standards
- [ ] Documentation updated
- [ ] Tests added/updated
- [ ] No breaking changes (or documented)
```

### Review Process

1. Maintainers will review your PR
2. Address any feedback
3. Once approved, your PR will be merged

## Reporting Issues

### Bug Reports

Use the GitHub issue tracker with:
- Clear title
- Detailed description
- Steps to reproduce
- Expected vs actual behavior
- Environment details
- Relevant logs (sanitized)

### Security Issues

**DO NOT** create a public issue for security vulnerabilities. Instead:
- Email security concerns privately
- Include detailed information
- Allow time for fix before disclosure

## Questions?

If you have questions about contributing:
- Check existing issues and PRs
- Review the README.md
- Open a discussion issue

Thank you for contributing to HSTS Compliance Tools!

