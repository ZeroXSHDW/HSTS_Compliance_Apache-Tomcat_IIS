#!/bin/bash
# test_verification_logic.sh
# Comprehensive test suite to verify the configuration verification logic
# This prevents the verification failure that occurred on Kali Linux

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNIX_SCRIPT="$SCRIPT_DIR/../../src/unix/UpdateTomcatHstsUnix.sh"
TEST_DIR="$SCRIPT_DIR/tests/VerificationTest"
LOG_FILE="$SCRIPT_DIR/verification_test.log"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] SUCCESS: $1${NC}" | tee -a "$LOG_FILE"
}

log_failure() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] FAILURE: $1${NC}" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}" | tee -a "$LOG_FILE"
}

# Cleanup function
cleanup() {
    if [[ -d "$TEST_DIR" ]]; then
        rm -rf "$TEST_DIR"
    fi
}

# Setup test environment
setup_test_env() {
    cleanup
    mkdir -p "$TEST_DIR/conf"
    
    # Create mock server.xml and RELEASE-NOTES for Tomcat detection
    echo '<?xml version="1.0" encoding="UTF-8"?><Server></Server>' > "$TEST_DIR/conf/server.xml"
    echo "Apache Tomcat Version 9.0.113" > "$TEST_DIR/RELEASE-NOTES"
}

# Test 1: Filter-based HSTS configuration (like Kali Linux scenario)
test_filter_based_config() {
    log_message "=== Test 1: Filter-based HSTS Configuration ==="
    
    local test_xml='<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
                             http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
         version="4.0">
    <filter>
        <filter-name>httpHeaderSecurity</filter-name>
        <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>
        <init-param>
            <param-name>hstsEnabled</param-name>
            <param-value>true</param-value>
        </init-param>
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
        <filter-name>httpHeaderSecurity</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>
</web-app>'
    
    echo "$test_xml" > "$TEST_DIR/conf/web.xml"
    
    # Run configure mode (should succeed as already compliant)
    if bash "$UNIX_SCRIPT" --mode configure --security-level high --custom-conf="$TEST_DIR/conf" 2>&1 | grep -q "SUCCESS"; then
        log_success "Filter-based configuration verified correctly"
        return 0
    else
        log_failure "Filter-based configuration verification failed"
        return 1
    fi
}

# Test 2: Empty configuration (needs configuration)
test_empty_config() {
    log_message "=== Test 2: Empty Configuration (Needs HSTS) ==="
    
    local test_xml='<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
                             http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
         version="4.0">
</web-app>'
    
    echo "$test_xml" > "$TEST_DIR/conf/web.xml"
    
    # Run configure mode (should add HSTS configuration)
    if bash "$UNIX_SCRIPT" --mode configure --security-level high --custom-conf="$TEST_DIR/conf" 2>&1 | grep -q "SUCCESS"; then
        log_success "Empty configuration successfully configured with HSTS"
        
        # Verify the configuration was actually added
        if grep -q "hstsMaxAgeSeconds" "$TEST_DIR/conf/web.xml" && grep -q "31536000" "$TEST_DIR/conf/web.xml"; then
            log_success "HSTS configuration verified in file"
            return 0
        else
            log_failure "HSTS configuration not found in file after configuration"
            return 1
        fi
    else
        log_failure "Empty configuration failed to configure"
        return 1
    fi
}

# Test 3: Non-compliant configuration (weak max-age)
test_weak_config() {
    log_message "=== Test 3: Weak Configuration (Low max-age) ==="
    
    local test_xml='<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
                             http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
         version="4.0">
    <filter>
        <filter-name>httpHeaderSecurity</filter-name>
        <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>
        <init-param>
            <param-name>hstsEnabled</param-name>
            <param-value>true</param-value>
        </init-param>
        <init-param>
            <param-name>hstsMaxAgeSeconds</param-name>
            <param-value>86400</param-value>
        </init-param>
    </filter>
    <filter-mapping>
        <filter-name>httpHeaderSecurity</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>
</web-app>'
    
    echo "$test_xml" > "$TEST_DIR/conf/web.xml"
    
    # Run configure mode (should replace weak config with compliant one)
    if bash "$UNIX_SCRIPT" --mode configure --security-level high --custom-conf="$TEST_DIR/conf" 2>&1 | grep -q "SUCCESS"; then
        log_success "Weak configuration successfully upgraded"
        
        # Verify the configuration was upgraded
        if grep -q "31536000" "$TEST_DIR/conf/web.xml" && ! grep -q "86400" "$TEST_DIR/conf/web.xml"; then
            log_success "Configuration upgraded to compliant max-age"
            return 0
        else
            log_failure "Configuration not properly upgraded"
            return 1
        fi
    else
        log_failure "Weak configuration failed to upgrade"
        return 1
    fi
}

# Test 4: Multiple HSTS definitions (should consolidate)
test_multiple_definitions() {
    log_message "=== Test 4: Multiple HSTS Definitions ==="
    
    local test_xml='<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
                             http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
         version="4.0">
    <filter>
        <filter-name>httpHeaderSecurity1</filter-name>
        <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>
        <init-param>
            <param-name>hstsMaxAgeSeconds</param-name>
            <param-value>31536000</param-value>
        </init-param>
    </filter>
    <filter>
        <filter-name>httpHeaderSecurity2</filter-name>
        <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>
        <init-param>
            <param-name>hstsMaxAgeSeconds</param-name>
            <param-value>86400</param-value>
        </init-param>
    </filter>
</web-app>'
    
    echo "$test_xml" > "$TEST_DIR/conf/web.xml"
    
    # Run configure mode (should consolidate to single compliant config)
    if bash "$UNIX_SCRIPT" --mode configure --security-level high --custom-conf="$TEST_DIR/conf" 2>&1 | grep -q "SUCCESS"; then
        log_success "Multiple definitions successfully consolidated"
        
        # Verify only one HSTS filter remains
        local filter_count=$(grep -c "HttpHeaderSecurityFilter" "$TEST_DIR/conf/web.xml" || echo "0")
        if [[ "$filter_count" -eq 1 ]]; then
            log_success "Consolidated to single HSTS filter"
            return 0
        else
            log_warning "Found $filter_count HSTS filters (expected 1)"
            return 1
        fi
    else
        log_failure "Multiple definitions failed to consolidate"
        return 1
    fi
}

# Test 5: Dry-run mode (should not modify files)
test_dry_run() {
    log_message "=== Test 5: Dry-Run Mode ==="
    
    local test_xml='<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
                             http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
         version="4.0">
</web-app>'
    
    echo "$test_xml" > "$TEST_DIR/conf/web.xml"
    local original_checksum=$(md5sum "$TEST_DIR/conf/web.xml" | awk '{print $1}')
    
    # Run dry-run mode
    bash "$UNIX_SCRIPT" --mode configure --security-level high --custom-conf="$TEST_DIR/conf" --dry-run > /dev/null 2>&1
    
    local new_checksum=$(md5sum "$TEST_DIR/conf/web.xml" | awk '{print $1}')
    
    if [[ "$original_checksum" == "$new_checksum" ]]; then
        log_success "Dry-run mode did not modify file"
        return 0
    else
        log_failure "Dry-run mode modified file (should not happen)"
        return 1
    fi
}

# Main test execution
main() {
    log_message "========================================="
    log_message "HSTS Configuration Verification Test Suite"
    log_message "========================================="
    log_message ""
    
    setup_test_env
    
    local total_tests=0
    local passed_tests=0
    local failed_tests=0
    
    # Run all tests
    for test_func in test_filter_based_config test_empty_config test_weak_config test_multiple_definitions test_dry_run; do
        total_tests=$((total_tests + 1))
        setup_test_env  # Reset environment for each test
        
        if $test_func; then
            passed_tests=$((passed_tests + 1))
        else
            failed_tests=$((failed_tests + 1))
        fi
        log_message ""
    done
    
    # Summary
    log_message "========================================="
    log_message "Test Summary"
    log_message "========================================="
    log_message "Total Tests: $total_tests"
    log_success "Passed: $passed_tests"
    if [[ $failed_tests -gt 0 ]]; then
        log_failure "Failed: $failed_tests"
    else
        log_message "Failed: $failed_tests"
    fi
    log_message "========================================="
    
    cleanup
    
    if [[ $failed_tests -eq 0 ]]; then
        log_success "=== All Verification Tests Passed ==="
        exit 0
    else
        log_failure "=== Some Verification Tests Failed ==="
        exit 1
    fi
}

# Run main function
main
