# HSTS Compliance Project - GitHub Release Checklist

This checklist tracks the tasks required for the final production release of the HSTS Compliance project.

> **Current-status notice (2026-08-24):** The maintenance branch is review-ready
> but is not itself a production release. Local Unix, PowerShell parsing,
> contract, patch-hygiene, and actionlint checks pass; merge approval,
> current hosted validation, Windows execution, and live Tomcat/IIS validation
> remain release gates. See the repository quality scorecard for the current
> evidence and score.

## 1. Code Quality & Standards (✅ Complete)
- [x] All PowerShell scripts use approved verbs (e.g., `Write-LogMessage` instead of `Log-Message`).
- [x] PSScriptAnalyzer warnings for unapproved verbs resolved.
- [x] Unused variables (e.g., `$RecommendedHsts` in remote scripts) removed.
- [x] Unix script `UpdateTomcatHstsUnix.sh` syntax errors fixed (redundant `fi` removed).
- [x] Logic for preserving original file permissions and ownership implemented and verified in Unix/Linux.
- [x] Shell scripts using secure temporary file creation with `mktemp`.

## 2. Advanced Feature Verification (✅ Complete)
- [x] **Enterprise Reporting**: Verified `--json` and `--report-file` flags in Unix scripts.
- [x] **Consolidated Fleet Monitoring**: Verified consolidated JSON/CSV reports in remote Windows scripts.
- [x] **Multi-Instance Auto-Discovery**: Verified capability to detect multiple Tomcat/IIS instances on a single host.
- [x] **Audit Mode Correctness**: Confirmed audit mode correctly identifies non-compliant HSTS configurations and exits with non-zero status.

## 3. Documentation (✅ Complete)
- [x] **README.md**: Updated with new enterprise features, remote WinRM setup guide, and project status.
- [x] **INSTALLATION.md**: Comprehensive guide for local and remote server installations.
- [x] **VERIFICATION.md**: Updated with specific verification steps for enterprise and reporting features.
- [x] **PROJECT_STATUS.md**: Records the implemented feature baseline and its external release gates.
- [x] **DEPLOYMENT_EMAIL_TEMPLATE.md**: Professional template for enterprise-wide rollout created.

## 4. Testing & Reliability (✅ Complete)
- [x] All 5 scenario tests for Windows (`test_hsts_win.ps1`) pass successfully.
- [x] All 5 scenario tests for Unix (`test_hsts_unix.sh`), including JSON reporting, pass successfully.
- [x] Dry-run functionality verified to accurately preview changes without modification.
- [x] Idempotency verified: running scripts multiple times does not duplicate filter definitions.

## 5. Security Performance (✅ Complete)
- [x] Path traversal protection verified in all path-accepting parameters.
- [x] Restricted permissions (600) for sensitive log files if possible.
- [x] No hardcoded passwords or sensitive credentials in any scripts.

## Final Approval Status
**Current State:** 🟡 **Review-ready maintenance branch; release approval pending**
**Release Target:** Public GitHub Repository after the external gates above are verified

The repository must not be described as 100% production-ready until the
maintenance review is merged, the default-branch gate is green, and Windows
plus live-target validation has been recorded.

---
Created on 2025-12-31
