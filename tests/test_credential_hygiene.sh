#!/bin/bash

set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
README_PATH="$ROOT_DIR/README.md"

for heading in \
    'Architecture and boundaries' \
    'Features' \
    'Configuration reference' \
    'Verification' \
    'Pre-publication validation checklist' \
    'Prerequisites' \
    'Contributing' \
    'License'; do
    grep -Fqx "## $heading" "$README_PATH"
done
[[ "$(grep -Fxc '## Features' "$README_PATH")" -eq 1 ]]
grep -Fiq 'audit-only defaults' "$README_PATH"
grep -Fq 'CI never changes a production host' "$README_PATH"

if grep -R -n -E 's3cretP@ssw0rd|PASSWORD="s3cret"|default: s3cret|MySecurePass|SecurePass123' \
    "$ROOT_DIR/install" "$ROOT_DIR/docs"; then
    echo "Credential hygiene check failed: tracked default/example password detected." >&2
    exit 1
fi

grep -Fq '[string]$Password = $null' "$ROOT_DIR/install/windows/TomcatManager.ps1"
grep -Fq '[string]$Password = $null' "$ROOT_DIR/install/windows/Remote_TomcatManager.ps1"
grep -Fq 'PASSWORD=""' "$ROOT_DIR/install/unix/tomcat_manager.sh"
grep -Fq -- '--password-stdin' "$ROOT_DIR/install/unix/tomcat_manager.sh"
grep -Fq -- 'Password is required for install actions' "$ROOT_DIR/install/windows/TomcatManager.ps1"
grep -Fq -- 'Password is required for install actions' "$ROOT_DIR/install/windows/Remote_TomcatManager.ps1"
grep -Fq 'mktemp "${config_path}.tmp.XXXXXX"' "$ROOT_DIR/src/unix/UpdateTomcatHstsUnix.sh"
if grep -Fq 'config_path}.tmp.$$' "$ROOT_DIR/src/unix/UpdateTomcatHstsUnix.sh"; then
    echo "Configuration write safety check failed: predictable temporary path detected." >&2
    exit 1
fi

echo "Credential and configuration-write hygiene contracts passed."
