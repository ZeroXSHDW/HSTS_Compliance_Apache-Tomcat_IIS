# Contributing to HSTS Configuration Tools

Thank you for your interest in contributing to this project! This document provides guidelines and instructions for contributing.

## Code of Conduct

- Be respectful and inclusive
- Welcome newcomers and help them learn
- Focus on constructive feedback
- Respect different viewpoints and experiences

## How to Contribute

### Reporting Issues

If you find a bug or have a feature request:

1. Check if the issue already exists in the issue tracker
2. If not, create a new issue with:
   - Clear description of the problem or feature
   - Steps to reproduce (for bugs)
   - Expected vs actual behavior
   - Environment details (OS, Tomcat/IIS version, etc.)

### Submitting Changes

1. **Fork the repository**
2. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes**:
   - Follow existing code style
   - Add comments for complex logic
   - Update documentation if needed
4. **Test your changes**:
   - Test on both Tomcat and IIS if applicable
   - Test audit and configure modes
   - Test error cases
5. **Commit your changes**:
   ```bash
   git commit -m "Description of your changes"
   ```
   - Use clear, descriptive commit messages
   - Reference issue numbers if applicable
6. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```
7. **Create a Pull Request**:
   - Provide a clear description
   - Reference related issues
   - Include test results if applicable

## Development Guidelines

### Code Style

- **Bash scripts**: Follow POSIX-compliant bash practices
- **PowerShell scripts**: Follow PowerShell best practices
- **Comments**: Add comments for complex logic
- **Error handling**: Always handle errors gracefully
- **Logging**: Use consistent logging format

### Testing

Before submitting:
- Test on multiple platforms (Linux, macOS, Windows)
- Test with different Tomcat/IIS versions
- Test edge cases (empty files, invalid XML, etc.)
- Test both audit and configure modes
- Test dry-run mode

### Documentation

- Update README.md if adding features
- Update INSTALLATION.md if changing installation procedures
- Add examples if adding new functionality

## Project Structure

```
.
├── README.md                    # Main documentation
├── INSTALLATION.md              # Installation guide
├── LICENSE                      # MIT License
├── CONTRIBUTING.md              # This file
├── .gitignore                   # Git ignore patterns
├── src/
│   ├── unix/
│   │   └── Patch/
│   │       └── bash/
│   │           └── UpdateTomcatHstsUnix.sh    # Unix/Linux Tomcat script
│   └── windows/
│       └── Patch/
│           └── powershell/
│               ├── UpdateTomcatHstsWin.ps1           # Windows Tomcat script (local)
│               ├── Remote_UpdateTomcatHstsWin.ps1    # Windows Tomcat script (remote)
│               ├── UpdateIisHstsWin.ps1              # Windows IIS script (local)
│               └── Remote_UpdateIisHstsWin.ps1       # Windows IIS script (remote)
└── examples/                    # Example configuration files
    ├── README.md
    ├── test_web.xml
    ├── test_web.config
    └── web.xml
```

## Areas for Contribution

- Unit tests
- Additional web server support (Apache, Nginx, etc.)
- Configuration file validation improvements
- Performance optimizations
- Documentation improvements
- Bug fixes
- Feature enhancements

## Questions?

If you have questions, please open an issue with the `question` label.

Thank you for contributing! 🎉

