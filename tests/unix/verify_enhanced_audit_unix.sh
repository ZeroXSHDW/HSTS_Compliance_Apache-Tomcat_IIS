#!/bin/bash

# verify_enhanced_audit_unix.sh
# Verifies the enhanced audit output in UpdateTomcatHstsUnix.sh

set -e

TEST_DIR="$(pwd)/tests/EnhancedAuditTest"
SCRIPT_PATH="$(dirname "$0")/../../src/unix/UpdateTomcatHstsUnix.sh"
LOG_FILE="$TEST_DIR/verification.log"

mkdir -p "$TEST_DIR/conf"

write_log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

run_audit() {
    local name="$1"
    local web_xml="$2"
    local audit_log="$TEST_DIR/${name}_audit.log"
    
    write_log "--- Testing Scenario: $name ---" >&2
    echo "$web_xml" > "$TEST_DIR/conf/web.xml"
    touch "$TEST_DIR/conf/server.xml"
    echo "Apache Tomcat Version 9.0.50" > "$TEST_DIR/RELEASE-NOTES"
    
    # Run audit mode
    "$SCRIPT_PATH" --mode audit --custom-conf="$TEST_DIR/conf" --log-file="$audit_log" > /dev/null 2>&1 || true
    
    echo "$audit_log"
}

# Scenario 1: No HSTS Configuration Found
audit_log=$(run_audit "No_HSTS" '<?xml version="1.0" encoding="UTF-8"?><web-app><filter><filter-name>SomeOtherFilter</filter-name></filter></web-app>')
if grep -q "=== AUDIT: No HSTS Configuration Found ===" "$audit_log" && \
   grep -q "Configuration Context:" "$audit_log" && \
   grep -q "SomeOtherFilter" "$audit_log" && \
   grep -q "Available Security Levels" "$audit_log"; then
    write_log "SUCCESS: No HSTS scenario output verified."
else
    write_log "FAILURE: No HSTS scenario output mismatch."
    cat "$audit_log"
    exit 1
fi

# Scenario 2: Non-Compliant HSTS (Detailed Parameters)
audit_log=$(run_audit "Non_Compliant" '<?xml version="1.0" encoding="UTF-8"?>
<web-app>
    <filter>
        <filter-name>HstsHeaderFilter</filter-name>
        <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>
        <init-param>
            <param-name>hstsMaxAgeSeconds</param-name>
            <param-value>86400</param-value>
        </init-param>
        <init-param>
            <param-name>hstsIncludeSubDomains</param-name>
            <param-value>false</param-value>
        </init-param>
    </filter>
</web-app>')

check_grep() {
    if ! grep -q "$1" "$2"; then
        write_log "MISSING: $1 in $2" "ERROR"
        return 1
    fi
    return 0
}

if check_grep "=== Audit Result Breakdown ===" "$audit_log" && \
   check_grep "hstsMaxAgeSeconds: 86400" "$audit_log" && \
   check_grep "\[FAIL\] Filter-based HSTS (Target Level: high): max-age=86400" "$audit_log" && \
   check_grep "FAILURE: Non-compliant HSTS configuration found: 1 failed issues." "$audit_log"; then
    write_log "SUCCESS: Non-compliant filter scenario output verified."
else
    write_log "FAILURE: Non-compliant filter scenario output mismatch."
    cat "$audit_log"
    exit 1
fi

# Scenario 3: Multiple Direct Headers
audit_log=$(run_audit "Multiple_Headers" '<?xml version="1.0" encoding="UTF-8"?>
<web-app>
    Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header set Strict-Transport-Security "max-age=60"
</web-app>')

if check_grep "=== Audit Result Breakdown ===" "$audit_log" && \
   check_grep "\[FAIL\] Direct header (Target Level: high):.*Header set Strict-Transport-Security \"max-age=60\"" "$audit_log" && \
   check_grep "\[PASS\] Direct header (Level: high):.*Strict-Transport-Security \"max-age=31536000; includeSubDomains\"" "$audit_log"; then
    write_log "SUCCESS: Multiple direct headers scenario output verified."
else
    write_log "FAILURE: Multiple direct headers scenario output mismatch."
    cat "$audit_log"
    exit 1
fi

write_log "=== All Unix Enhanced Audit Verifications Passed ==="
