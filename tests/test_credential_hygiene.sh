#!/bin/bash

set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "$0")/.." && pwd -P)

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

echo "Credential hygiene contract passed."
