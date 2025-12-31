# Internationalization (i18n) and Localization (l10n) Guide

This document outlines the internationalization considerations for the HSTS Compliance Tools.

## Character Encoding

All scripts and configuration files are designed to handle **UTF-8** encoding.

- **PowerShell:** Scripts default to UTF-8 encoding for file operations.
- **Bash:** Scripts rely on the system locale, but explicitly handle text files with standard tools compliant with UTF-8.
- **XML Files:** The tools preserve the encoding specified in the XML declaration (defaults to UTF-8 or ISO-8859-1).

## Language Support

Currently, the tool's output (logs, console messages) is in **English (US)**.

### Future Localization Support

We plan to support message catalogs in future releases. The proposed structure for localization files is:

```plaintext
resources/
  ├── messages_en.json
  ├── messages_es.json
  ├── messages_fr.json
  └── messages_de.json
```

## Date and Time Formats

- **Logs:** Use ISO 8601 format (`YYYY-MM-DD HH:MM:SS`) which is unambiguous across regions.
- **File Names:** Generated backup files use `YYYYMMDD_HHMMSS` format.

## Considerations for Non-English Deployments

### System Paths

The scripts incorporate logic to handle:
- Spaces in paths (common in Windows "Program Files", but also possible in localized folders).
- Non-ASCII characters in paths (fully supported via proper quoting and Unicode handling in PowerShell/Bash).

### IIS / Tomcat Localized Error Pages

The HSTS configuration (HTTP headers) is independent of the content language. However, if your web server serves custom error pages, ensure the `web.xml` or `web.config` modifications do not interfere with existing `<error-page>` definitions (the scripts are designed to add filters/modules non-destructively).

## Contributing Translations

If you would like to contribute translations for the documentation:

1. Copy the Markdown file (e.g., `README.md` -> `README.es.md`).
2. Translate the content.
3. Submit a Pull Request.
