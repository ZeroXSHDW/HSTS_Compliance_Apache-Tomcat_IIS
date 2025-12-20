#!/bin/bash

# test_hsts_unix.sh
# Tests HSTS patching script for Tomcat on Unix/Linux
# Tests UpdateTomcatHstsUnix.sh

set -e

LOG_FILE="$HOME/TestHstsUnix.log"
TEST_DIR="$HOME/HstsTest"
BACKUP_DIR="$HOME/HstsTestBackup"
SCRIPT_PATH="$(dirname "$0")/../../../src/unix/Patch/bash/UpdateTomcatHstsUnix.sh"

# Function to write log messages
write_log() {
    local message="$1"
    local level="${2:-INFO}"
    local log_message="[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message"
    echo "$log_message" >> "$LOG_FILE"
    echo "$log_message"
}

write_log "Starting HSTS patching tests for Unix/Linux..."

# Check if script exists
if [ ! -f "$SCRIPT_PATH" ]; then
    write_log "ERROR: UpdateTomcatHstsUnix.sh not found at $SCRIPT_PATH" "ERROR"
    exit 1
fi

# Make script executable
chmod +x "$SCRIPT_PATH"

# Create test directories
if [ -d "$TEST_DIR" ]; then
    rm -rf "$TEST_DIR"
fi
mkdir -p "$TEST_DIR/conf"
mkdir -p "$BACKUP_DIR"

# Test scenarios
test_scenario() {
    local name="$1"
    local description="$2"
    local web_xml="$3"
    local expected_result="$4"
    
    write_log "Testing scenario: $name - $description"
    
    # Create test web.xml
    local web_xml_path="$TEST_DIR/conf/web.xml"
    echo "$web_xml" > "$web_xml_path"
    
    # Backup original
    cp "$web_xml_path" "$BACKUP_DIR/web.xml.$name"
    
    # Run audit mode
    write_log "Running audit mode..."
    if sudo "$SCRIPT_PATH" --mode audit --custom-conf="$TEST_DIR/conf" >> "$LOG_FILE" 2>&1; then
        write_log "Audit completed successfully"
    else
        write_log "Audit failed or found issues (this may be expected)" "WARNING"
    fi
    
    # Run configure mode (dry run first)
    write_log "Running configure mode (dry run)..."
    if sudo "$SCRIPT_PATH" --mode configure --custom-conf="$TEST_DIR/conf" --dry-run >> "$LOG_FILE" 2>&1; then
        write_log "Dry run completed successfully"
    else
        write_log "Dry run failed" "ERROR"
    fi
    
    # Restore for next test
    cp "$BACKUP_DIR/web.xml.$name" "$web_xml_path"
}

# Scenario 1: No HSTS Header
test_scenario "No_HSTS_Header" \
    "Configuration with no HSTS header" \
    '<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
         http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
         version="4.0">
    <display-name>Test Application</display-name>
</web-app>' \
    "Should add compliant HSTS header"

# Scenario 2: Non-Compliant HSTS (Short MaxAge)
test_scenario "Non_Compliant_HSTS_Short_MaxAge" \
    "HSTS with max-age less than 31536000" \
    '<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
         http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
         version="4.0">
    <filter>
        <filter-name>HstsHeaderFilter</filter-name>
        <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>
        <init-param>
            <param-name>hstsMaxAgeSeconds</param-name>
            <param-value>86400</param-value>
        </init-param>
        <init-param>
            <param-name>hstsIncludeSubDomains</param-name>
            <param-value>true</param-value>
        </init-param>
    </filter>
    <filter-mapping>
        <filter-name>HstsHeaderFilter</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>
</web-app>' \
    "Should replace with compliant HSTS header (max-age=31536000)"

# Scenario 3: Non-Compliant HSTS (No IncludeSubDomains)
test_scenario "Non_Compliant_HSTS_No_IncludeSubDomains" \
    "HSTS with max-age correct but missing includeSubDomains" \
    '<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
         http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
         version="4.0">
    <filter>
        <filter-name>HstsHeaderFilter</filter-name>
        <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>
        <init-param>
            <param-name>hstsMaxAgeSeconds</param-name>
            <param-value>31536000</param-value>
        </init-param>
        <init-param>
            <param-name>hstsIncludeSubDomains</param-name>
            <param-value>false</param-value>
        </init-param>
    </filter>
    <filter-mapping>
        <filter-name>HstsHeaderFilter</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>
</web-app>' \
    "Should add includeSubDomains"

# Scenario 4: Compliant HSTS
test_scenario "Compliant_HSTS" \
    "Already compliant HSTS configuration" \
    '<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
         http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
         version="4.0">
    <filter>
        <filter-name>HstsHeaderFilter</filter-name>
        <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>
        <init-param>
            <param-name>hstsMaxAgeSeconds</param-name>
            <param-value>31536000</param-value>
        </init-param>
        <init-param>
            <param-name>hstsIncludeSubDomains</param-name>
            <param-value>true</param-value>
        </init-param>
    </filter>
    <filter-mapping>
        <filter-name>HstsHeaderFilter</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>
</web-app>' \
    "Should remain unchanged (already compliant)"

write_log "=== All HSTS tests completed ==="
write_log "Test log saved to: $LOG_FILE"
write_log "Test files saved to: $TEST_DIR"
write_log "Backups saved to: $BACKUP_DIR"

