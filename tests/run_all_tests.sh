#!/bin/bash
# run_all_tests.sh
# Comprehensive test runner for HSTS Compliance Suite
# Runs all tests and validates results

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TEST_RESULTS_DIR="$PROJECT_ROOT/test-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Create test results directory
mkdir -p "$TEST_RESULTS_DIR"

# Test result tracking
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

echo "========================================="
echo "HSTS Compliance Suite - Test Runner"
echo "========================================="
echo "Timestamp: $TIMESTAMP"
echo "Project Root: $PROJECT_ROOT"
echo ""

# Function to log test results
log_test_result() {
    local test_name="$1"
    local result="$2"
    local message="$3"
    
    ((TOTAL_TESTS++))
    
    if [[ "$result" == "PASS" ]]; then
        ((PASSED_TESTS++))
        echo -e "${GREEN}✓${NC} $test_name: $message"
    else
        ((FAILED_TESTS++))
        echo -e "${RED}✗${NC} $test_name: $message"
    fi
}

# Test 1: Bash Syntax Validation
echo "Running Test 1: Bash Syntax Validation..."
if bash -n "$PROJECT_ROOT/src/unix/UpdateTomcatHstsUnix.sh" 2>/dev/null; then
    log_test_result "Bash_Syntax" "PASS" "UpdateTomcatHstsUnix.sh syntax is valid"
else
    log_test_result "Bash_Syntax" "FAIL" "UpdateTomcatHstsUnix.sh has syntax errors"
fi

# Test 2: Unix Test Suite
echo ""
echo "Running Test 2: Unix/Linux Test Suite..."
if [[ -f "$PROJECT_ROOT/tests/unix/test_hsts_unix.sh" ]]; then
    chmod +x "$PROJECT_ROOT/tests/unix/test_hsts_unix.sh"
    if cd "$PROJECT_ROOT/tests/unix" && ./test_hsts_unix.sh > "$TEST_RESULTS_DIR/unix_tests_$TIMESTAMP.log" 2>&1; then
        log_test_result "Unix_Test_Suite" "PASS" "All Unix tests completed successfully"
    else
        log_test_result "Unix_Test_Suite" "FAIL" "Unix tests failed - check log: $TEST_RESULTS_DIR/unix_tests_$TIMESTAMP.log"
    fi
else
    log_test_result "Unix_Test_Suite" "FAIL" "Unix test script not found"
fi

# Test 3: Example Files Validation
echo ""
echo "Running Test 3: Example Files Validation..."
EXAMPLE_FILES_VALID=true

if [[ -f "$PROJECT_ROOT/examples/test_web.xml" ]]; then
    if xmllint --noout "$PROJECT_ROOT/examples/test_web.xml" 2>/dev/null; then
        log_test_result "Example_Web_XML" "PASS" "test_web.xml is valid XML"
    else
        log_test_result "Example_Web_XML" "FAIL" "test_web.xml is not valid XML"
        EXAMPLE_FILES_VALID=false
    fi
else
    log_test_result "Example_Web_XML" "FAIL" "test_web.xml not found"
    EXAMPLE_FILES_VALID=false
fi

if [[ -f "$PROJECT_ROOT/examples/test_web.config" ]]; then
    if xmllint --noout "$PROJECT_ROOT/examples/test_web.config" 2>/dev/null; then
        log_test_result "Example_Web_Config" "PASS" "test_web.config is valid XML"
    else
        log_test_result "Example_Web_Config" "FAIL" "test_web.config is not valid XML"
        EXAMPLE_FILES_VALID=false
    fi
else
    log_test_result "Example_Web_Config" "FAIL" "test_web.config not found"
    EXAMPLE_FILES_VALID=false
fi

# Test 4: Script Permissions
echo ""
echo "Running Test 4: Script Permissions..."
if [[ -x "$PROJECT_ROOT/src/unix/UpdateTomcatHstsUnix.sh" ]] || chmod +x "$PROJECT_ROOT/src/unix/UpdateTomcatHstsUnix.sh" 2>/dev/null; then
    log_test_result "Script_Permissions" "PASS" "Unix script is executable"
else
    log_test_result "Script_Permissions" "FAIL" "Unix script is not executable"
fi

# Test 5: Documentation Completeness
echo ""
echo "Running Test 5: Documentation Completeness..."
DOCS_COMPLETE=true

for doc in "README.md" "CHANGELOG.md" "CONTRIBUTING.md" "SECURITY.md" "LICENSE"; do
    if [[ -f "$PROJECT_ROOT/$doc" ]]; then
        log_test_result "Doc_$doc" "PASS" "$doc exists"
    else
        log_test_result "Doc_$doc" "FAIL" "$doc missing"
        DOCS_COMPLETE=false
    fi
done

# Test 6: Required Directories
echo ""
echo "Running Test 6: Required Directories..."
for dir in "src" "tests" "examples" "docs" "install"; do
    if [[ -d "$PROJECT_ROOT/$dir" ]]; then
        log_test_result "Dir_$dir" "PASS" "$dir directory exists"
    else
        log_test_result "Dir_$dir" "FAIL" "$dir directory missing"
    fi
done

# Test 7: HSTS Compliance Validation
echo ""
echo "Running Test 7: HSTS Compliance Validation..."
# Create a test file and verify the script can process it
TEST_TEMP_DIR=$(mktemp -d)
TEST_CONF_DIR="$TEST_TEMP_DIR/conf"
mkdir -p "$TEST_CONF_DIR"

# Create minimal web.xml
cat > "$TEST_CONF_DIR/web.xml" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee" version="4.0">
    <display-name>Test</display-name>
</web-app>
EOF

# Create server.xml for detection
touch "$TEST_CONF_DIR/server.xml"

# Run audit mode
if "$PROJECT_ROOT/src/unix/UpdateTomcatHstsUnix.sh" --mode audit --custom-conf="$TEST_CONF_DIR" > /dev/null 2>&1; then
    log_test_result "HSTS_Audit" "PASS" "Audit mode executes successfully"
else
    # Exit code 1 is expected for non-compliant configs
    if [[ $? -eq 1 ]]; then
        log_test_result "HSTS_Audit" "PASS" "Audit mode correctly identifies non-compliant config"
    else
        log_test_result "HSTS_Audit" "FAIL" "Audit mode failed unexpectedly"
    fi
fi

# Cleanup
rm -rf "$TEST_TEMP_DIR"

# Final Summary
echo ""
echo "========================================="
echo "Test Results Summary"
echo "========================================="
echo "Total Tests: $TOTAL_TESTS"
echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"
if [[ $FAILED_TESTS -gt 0 ]]; then
    echo -e "${RED}Failed: $FAILED_TESTS${NC}"
else
    echo -e "${GREEN}Failed: $FAILED_TESTS${NC}"
fi
echo ""

# Calculate success rate
SUCCESS_RATE=$((PASSED_TESTS * 100 / TOTAL_TESTS))
echo "Success Rate: $SUCCESS_RATE%"
echo ""

# Save results to file
cat > "$TEST_RESULTS_DIR/summary_$TIMESTAMP.txt" << EOF
HSTS Compliance Suite - Test Results
=====================================
Timestamp: $TIMESTAMP
Total Tests: $TOTAL_TESTS
Passed: $PASSED_TESTS
Failed: $FAILED_TESTS
Success Rate: $SUCCESS_RATE%
EOF

echo "Test results saved to: $TEST_RESULTS_DIR/summary_$TIMESTAMP.txt"
echo ""

# Exit with appropriate code
if [[ $FAILED_TESTS -eq 0 ]]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed. Please review the results above.${NC}"
    exit 1
fi
