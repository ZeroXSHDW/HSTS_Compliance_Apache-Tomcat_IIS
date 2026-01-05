#!/bin/bash
# UpdateTomcatHstsUnix.sh
# Audit and Configure HSTS (HTTP Strict Transport Security) in Apache Tomcat
# For Linux/Unix server environments only (not macOS)
#
# This script automatically detects Tomcat installations and configures HSTS
# headers in web.xml files for OWASP compliance.
#
# Compliance: This script implements the OWASP HSTS Cheat Sheet recommendations:
# - Required: max-age=31536000 (1 year)
# - Required: includeSubDomains
# - Optional: preload (allowed but not configured by default due to permanent consequences)
# Reference: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html
#
# The recommended HSTS value is: Strict-Transport-Security: max-age=31536000; includeSubDomains
#
# Usage: sudo ./UpdateTomcatHstsUnix.sh [--mode audit|configure] [--custom-conf=/path/to/conf] [--dry-run]
#   --mode: audit (check only) or configure (audit + patch). Default: configure
#   --custom-conf: Optional custom Tomcat conf directory path
#   --dry-run: Preview changes without applying (configure mode only)
#
# Exit codes:
#   0 - Success (audit: correctly configured, configure: patch applied successfully)
#   1 - Failure (audit: incorrectly configured, configure: patch failed)
#   2 - Error occurred during execution

set -euo pipefail

# Default values
MODE="configure"  # Default to configure mode
CONFIG_PATH=""
CUSTOM_CONF_PATH=""
CUSTOM_CONF_PATHS=()  # Array for multiple custom paths
CUSTOM_PATHS_FILE=""
LOG_FILE="/var/log/tomcat-hsts-$(date +%Y%m%d_%H%M%S).log"
REPORT_FILE=""
JSON_OUTPUT=false
DRY_RUN=false
QUIET_MODE=false
SCRIPT_NAME=$(basename "$0")
RECOMMENDED_HSTS="max-age=31536000; includeSubDomains"
RECOMMENDED_HSTS_FULL="Strict-Transport-Security: max-age=31536000; includeSubDomains"
HOSTNAME=$(hostname)
OS_INFO=$(uname -sr)
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
SECURITY_LEVEL="high"
MIN_MAX_AGE=31536000
REQUIRE_SUBDOMAINS=true
REQUIRE_PRELOAD=false

# Global variables for tracking results
RESULTS_JSON=""
SUMMARY_ENTRIES=()

# Global variables for compliance tracking (table output)
COMPLIANCE_TABLE_ROWS=()
COMPLIANT_COUNT=0
NON_COMPLIANT_COUNT=0
NOT_CONFIGURED_COUNT=0

# Global variables for cleanup
TEMP_FILES=()
BACKUP_PATH=""

# Cleanup function for temporary files
cleanup_temp_files() {
    # Check if TEMP_FILES exists and has elements to avoid unbound variable errors with set -u
    if [[ -n "${TEMP_FILES[*]:-}" ]]; then
        for temp_file in "${TEMP_FILES[@]}"; do
            if [[ -f "$temp_file" ]]; then
                rm -f "$temp_file" 2>/dev/null || true
            fi
        done
    fi
}

# Trap to ensure cleanup on exit, error, interrupt, and termination
trap cleanup_temp_files EXIT ERR INT TERM

# Function: Print usage information
usage() {
    echo "Usage: sudo $SCRIPT_NAME [--mode audit|configure] [--custom-conf=/path/to/conf] [--custom-paths-file=/path/to/file] [--json] [--report-file=path] [--dry-run]"
    echo ""
    echo "Options:"
    echo "  --mode <audit|configure>     Operation mode (default: configure)"
    echo "                               audit: Check HSTS configuration compliance"
    echo "                               configure: Fix HSTS configuration to be compliant"
    echo "  --custom-conf <path>         Optional: Custom Tomcat conf directory path (can be specified multiple times)"
    echo "                               If not provided, script will auto-detect Tomcat installation"
    echo "  --custom-paths-file <file>   Optional: File containing custom paths (one path per line)"
    echo "  --json                       Output summary in JSON format to stdout"
    echo "  --report-file <path>         Path to save a detailed JSON report of all processed servers"
    echo "  --dry-run                    Show what would be changed without making changes (configure mode only)"
    echo "  --security-level <level>     Target security level (basic, high, veryhigh, maximum). Default: high"
    echo "                               basic:    max-age=1yr"
    echo "                               high:     max-age=1yr, includeSubDomains"
    echo "                               veryhigh: max-age=1yr, includeSubDomains, preload"
    echo "                               maximum:  max-age=2yr, includeSubDomains, preload"
    echo ""
    echo "Examples:"
    echo "  sudo $SCRIPT_NAME                                    # Auto-detect and configure"
    echo "  sudo $SCRIPT_NAME --mode audit                       # Auto-detect and audit only"
    echo "  sudo $SCRIPT_NAME --json --report-file=report.json   # Generate enterprise reports"
    echo "  sudo $SCRIPT_NAME --mode configure --dry-run         # Preview changes"
    exit 2
}

# Function: Log message to console and optionally to file
log_message() {
    local message="$1"
    local force="${2:-false}"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local log_entry="[$timestamp] $message"
    
    # Only print to console if not in quiet mode OR force is true
    if [[ "$QUIET_MODE" != "true" ]] || [[ "$force" == "true" ]]; then
        echo "$log_entry" >&2
    fi
    
    # Always log to file if configured
    if [[ -n "$LOG_FILE" ]]; then
        echo "$log_entry" >> "$LOG_FILE" 2>/dev/null || true
    fi
}

# Function: Log error message
log_error() {
    log_message "ERROR: $1" true >&2
}

# Function: Print header for output
print_header() {
    local hostname_line=$(printf '#%.0s' {1..80})
    hostname_line="${hostname_line:0:$((40 - ${#HOSTNAME}/2))}$HOSTNAME${hostname_line:0:$((40 - (${#HOSTNAME}+1)/2))}"
    
    echo "Checking Tomcat HSTS Configuration..."
    echo "$hostname_line"
    echo "Execution Time: $TIMESTAMP"
    echo "HOSTNAME: $HOSTNAME"
    echo "==========================="
}

# Function: Add row to compliance table
add_table_row() {
    local file="$1"
    local status="$2"
    local details="$3"
    
    COMPLIANCE_TABLE_ROWS+=("$file|$status|$details")
    
    case "$status" in
        "Compliant")
            COMPLIANT_COUNT=$((COMPLIANT_COUNT + 1))
            ;;
        "Non-Compliant")
            NON_COMPLIANT_COUNT=$((NON_COMPLIANT_COUNT + 1))
            ;;
        "Not Configured")
            NOT_CONFIGURED_COUNT=$((NOT_CONFIGURED_COUNT + 1))
            ;;
    esac
}

# Function: Print compliance table
print_compliance_table() {
    if [[ ${#COMPLIANCE_TABLE_ROWS[@]} -eq 0 ]]; then
        return
    fi
    
    echo ""
    echo "HSTS Compliance Results:"
    printf "%-40s | %-15s | %s\n" "File" "Status" "Details"
    echo "-----------------------------------------+-----------------+-----------------------------------------"
    
    for row in "${COMPLIANCE_TABLE_ROWS[@]}"; do
        IFS='|' read -r file status details <<< "$row"
        local file_basename=$(basename "$file")
        printf "%-40s | %-15s | %s\n" "${file_basename:0:40}" "${status:0:15}" "${details:0:40}"
    done
    
    echo ""
    echo "==========================="
}

# Function: Validate XML file
# Parameters: xml_file
# Returns: 0 if valid, 1 if invalid
validate_xml() {
    local xml_file="$1"
    
    # Check if xmllint is available
    if command -v xmllint >/dev/null 2>&1; then
        if xmllint --noout "$xml_file" >/dev/null 2>&1; then
            return 0
        else
            log_error "XML validation failed: $xml_file"
            return 1
        fi
    fi
    
    # Fallback: basic XML structure check
    if ! grep -q "<?xml" "$xml_file" 2>/dev/null; then
        return 1
    fi
    
    return 0
}

# Function: Validate file path
# Parameters: file_path
# Returns: 0 if valid, 1 if invalid
validate_file_path() {
    local file_path="$1"
    
    # Check for path traversal attempts
    if [[ "$file_path" =~ \.\. ]]; then
        log_error "Invalid path: contains '..' (path traversal attempt)"
        return 1
    fi
    
#     # Check for null bytes
#     if [[ "$file_path" =~ $'\0' ]]; then
#         log_error "Invalid path: contains null byte"
#         return 1
#     fi
    
    # Warn if path is not absolute (recommended for security, but allow relative paths)
    if [[ ! "$file_path" =~ ^/ ]]; then
        log_message "WARNING: Using relative path. Absolute paths are recommended for security: $file_path"
    fi
    
    # Check if it's a symlink (warn but allow)
    if [[ -L "$file_path" ]]; then
        local real_path=$(readlink -f "$file_path" 2>/dev/null || echo "$file_path")
        log_message "WARNING: Configuration path is a symlink, resolved to: $real_path"
    fi
    
    return 0
}

# Function: Load configuration file content
# Parameters: config_path
# Returns: File content as string
load_config() {
    local config_path="$1"
    
    # Validate path first
    if ! validate_file_path "$config_path"; then
        return 1
    fi
    
    if [[ ! -f "$config_path" ]]; then
        log_error "Configuration file not found: $config_path"
        return 1
    fi
    
    if [[ ! -r "$config_path" ]]; then
        log_error "Permission denied: Cannot read configuration file: $config_path"
        return 1
    fi
    
    # Check if file is empty
    if [[ ! -s "$config_path" ]]; then
        log_error "Configuration file is empty: $config_path"
        return 1
    fi
    
    cat "$config_path"
}

# Function: Find all HSTS header definitions in configuration
# Parameters: config_content
# Returns: Array of HSTS header locations and details
find_all_hsts_headers() {
    local config_content="$1"
    local headers=()
    local line_num=1
    
    # Search for various HSTS patterns
    while IFS= read -r line; do
        # Check for Strict-Transport-Security in header name/value
        if echo "$line" | grep -qi "Strict-Transport-Security"; then
            headers+=("$line_num:$line")
        fi
        # Check for hstsMaxAgeSeconds (Tomcat filter parameter)
        if echo "$line" | grep -qi "hstsMaxAgeSeconds\|hstsIncludeSubDomains"; then
            headers+=("$line_num:$line")
        fi
        # Check for HSTS in filter names
        if echo "$line" | grep -qi "HstsHeaderFilter\|httpHeaderSecurity"; then
            headers+=("$line_num:$line")
        fi
        ((line_num++))
    done <<< "$config_content"
    
    if [[ ${#headers[@]} -gt 0 ]]; then
        printf '%s\n' "${headers[@]}"
    fi
}

# Function: Check if HSTS header value is compliant
# Parameters: header_value
# Returns: 0 if compliant, 1 if not
# Compliance per OWASP HSTS Cheat Sheet:
# - Required: max-age=31536000 (1 year)
# - Required: includeSubDomains
# - Optional: preload (allowed but not required)
is_compliant_header() {
    local header_value="$1"
    
    # Check for max-age directive
    local max_age=$(echo "$header_value" | grep -oi "max-age=[0-9]\+" | head -1 | cut -d= -f2)
    if [[ -z "$max_age" ]]; then
        return 1  # Missing max-age is non-compliant
    fi
    
    # Check for max-age against target level
    if [[ "$max_age" -lt "$MIN_MAX_AGE" ]]; then
        return 1  # max-age too short for selected level
    fi
    
    # Check for includeSubDomains if required for selected level
    if [[ "$REQUIRE_SUBDOMAINS" == "true" ]]; then
        if ! echo "$header_value" | grep -qi "includeSubDomains"; then
            return 1
        fi
    fi
    
    # Check for preload if required for selected level
    if [[ "$REQUIRE_PRELOAD" == "true" ]]; then
        if ! echo "$header_value" | grep -qi "preload"; then
            return 1
        fi
    fi
    
    return 0
}

# Function: Audit HSTS header configuration
# Parameters: config_content
# Returns: Exit code 0 if correctly configured, 1 if not, plus details
audit_hsts_headers() {
    local config_content="$1"
    local all_headers
    local header_count=0
    local compliant_count=0
    local non_compliant_count=0
    local details=""
    local is_correct=1
    
    # Find all HSTS header definitions (using while loop for legacy Bash compatibility)
    local all_headers=()
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            all_headers+=("$line")
        fi
    done <<< "$(find_all_hsts_headers "$config_content")"
    header_count=${#all_headers[@]}
    
    if [[ $header_count -eq 0 ]]; then
        details="No HSTS header definitions found in configuration"
        log_message "=== AUDIT: No HSTS Configuration Found ==="
        log_message "No HSTS headers or filters detected in the configuration file."
        log_message ""
        log_message "Configuration Context:"
        # Show what filters ARE present
        local all_filters=$(echo "$config_content" | grep -i "<filter-name>" | sed 's/^[[:space:]]*//' | head -10)
        if [[ -n "$all_filters" ]]; then
            log_message "Other filters found in configuration:"
            echo "$all_filters" | while IFS= read -r filter_line; do
                log_message "  $filter_line"
            done
        else
            log_message "  No filters found in configuration"
        fi
        log_message ""
        log_message "=== Current HSTS Configuration ==="
        log_message "  Status: NOT CONFIGURED"
        log_message "  Header: (none)"
        log_message ""
        log_message "=== Available Security Levels ==="
        log_message ""
        log_message "  [1] BASIC - Minimum HSTS protection"
        log_message "      Header: Strict-Transport-Security: max-age=31536000"
        log_message "      Use when: Subdomains should NOT be affected"
        log_message ""
        log_message "  [2] HIGH - OWASP Recommended (Default)"
        log_message "      Header: Strict-Transport-Security: max-age=31536000; includeSubDomains"
        log_message "      Use when: All subdomains also use HTTPS"
        log_message ""
        log_message "  [3] VERY HIGH - Preload Ready"
        log_message "      Header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        log_message "      Use when: Ready for browser preload list submission"
        log_message ""
        log_message "  [4] MAXIMUM - Highest Security"
        log_message "      Header: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload"
        log_message "      Use when: Maximum protection with 2-year cache"
        log_message ""
        log_message "=== Configure Commands (copy and run) ==="
        log_message ""
        log_message "  Option 1: sudo $0 --mode configure --security-level basic"
        log_message "  Option 2: sudo $0 --mode configure --security-level high"
        log_message "  Option 3: sudo $0 --mode configure --security-level veryhigh"
        log_message "  Option 4: sudo $0 --mode configure --security-level maximum"
        log_message ""
        log_message "  Add --dry-run to preview changes without applying"
        log_message "=========================================="
        AUDIT_RESULT="$details"
        AUDIT_HEADER_COUNT=0
        AUDIT_COMPLIANT_COUNT=0
        AUDIT_NON_COMPLIANT_COUNT=0
        return 1
    fi
    
    log_message "Found $header_count HSTS header definition(s)"
    
    # Initialize counts
    local compliant_count=0
    local non_compliant_count=0
    local is_correct=1
    local details=""
    
    # Check each header for compliance
    local compliant_headers=()
    local non_compliant_headers=()
    local weak_headers=()
    
    # Check for filter-based HSTS configuration (Tomcat specific)
    if echo "$config_content" | grep -qi "hstsMaxAgeSeconds"; then
        # Extract the value of hstsMaxAgeSeconds even if it's on the next line
        local max_age_val=$(echo "$config_content" | sed -n '/hstsMaxAgeSeconds/{n;p;}' | grep -o '[0-9]\+')
        # Fallback if it's on the same line
        if [[ -z "$max_age_val" ]]; then
            max_age_val=$(echo "$config_content" | grep "hstsMaxAgeSeconds" | sed 's/.*hstsMaxAgeSeconds.*\>\([0-9]\+\)<.*/\1/' | grep -o '^[0-9]\+$')
        fi
        
        # Extract includeSubDomains value
        local include_subdomains_val=$(echo "$config_content" | sed -n '/hstsIncludeSubDomains/{n;p;}' | grep -io "true\|false" | head -1)
        if [[ -z "$include_subdomains_val" ]]; then
            include_subdomains_val=$(echo "$config_content" | grep "hstsIncludeSubDomains" | grep -io "true\|false" | head -1)
        fi
        
        log_message "=== Current Filter-Based HSTS Configuration ==="
        log_message "  hstsMaxAgeSeconds: ${max_age_val:-not found}"
        log_message "  hstsIncludeSubDomains: ${include_subdomains_val:-not found}"
        log_message "==============================================="
        
        local filter_compliant=true
        local filter_weak=false
        
        # Check max-age
        if [[ -z "$max_age_val" ]] || [[ "$max_age_val" -lt "$MIN_MAX_AGE" ]]; then
            filter_compliant=false
        fi
        
        # Check subdomains
        if [[ "$REQUIRE_SUBDOMAINS" == "true" ]] && [[ "$include_subdomains_val" != "true" ]]; then
            filter_compliant=false
            filter_weak=true
        fi
        
        # Note: Preload is usually NOT supported natively in Tomcat HttpHeaderSecurityFilter param-names
        # unless it is Tomcat 9.0.35+, 8.5.55+, 10.0.0-M5+ via hstsPreload
        local preload_val=$(echo "$config_content" | sed -n '/hstsPreload/{n;p;}' | grep -io "true\|false" | head -1)
        if [[ -z "$preload_val" ]]; then
            preload_val=$(echo "$config_content" | grep "hstsPreload" | grep -io "true\|false" | head -1)
        fi
        
        if [[ "$REQUIRE_PRELOAD" == "true" ]] && [[ "$preload_val" != "true" ]]; then
            filter_compliant=false
        fi

        if [[ "$filter_compliant" == "true" ]]; then
            compliant_count=$((compliant_count + 1))
            compliant_headers+=("[PASS] Filter-based HSTS (Level: $SECURITY_LEVEL): max-age=$max_age_val; includeSubDomains=${include_subdomains_val:-false}; preload=${preload_val:-false}")
        elif [[ "$filter_weak" == "true" ]] && [[ "$SECURITY_LEVEL" == "basic" ]]; then
             # Technically if level is basic, missing subdomains is still pass? 
             # No, if level is basic, we don't REQUIRE subdomains.
             # Wait, my logic above: filter_compliant=false if REQUIRE_SUBDOMAINS=true.
             compliant_count=$((compliant_count + 1))
             compliant_headers+=("[PASS] Filter-based HSTS (Level: $SECURITY_LEVEL): max-age=$max_age_val")
        else
            non_compliant_count=$((non_compliant_count + 1))
            non_compliant_headers+=("[FAIL] Filter-based HSTS (Target Level: $SECURITY_LEVEL): max-age=${max_age_val:-not set}; includeSubDomains=${include_subdomains_val:-false}; preload=${preload_val:-false}")
        fi
    fi
    
    # Check for direct header definitions (Strict-Transport-Security)
    # Only count direct headers that are NOT part of filter configuration
    local direct_headers=$(echo "$config_content" | grep -i "Strict-Transport-Security" | grep -v "^#" | grep -v "^[[:space:]]*#" | grep -v "hstsMaxAgeSeconds\|hstsIncludeSubDomains\|HttpHeaderSecurityFilter\|HstsHeaderFilter" || true)
    if [[ -n "$direct_headers" ]]; then
        # Filter out empty lines if any
        direct_headers=$(echo "$direct_headers" | grep . || true)
        if [[ -n "$direct_headers" ]]; then
            while IFS= read -r header_line; do
                log_message "  Found direct header: $header_line"
                if is_compliant_header "$header_line"; then
                    compliant_count=$((compliant_count + 1))
                    compliant_headers+=("[PASS] Direct header (Level: $SECURITY_LEVEL): $header_line")
                else
                    non_compliant_count=$((non_compliant_count + 1))
                    non_compliant_headers+=("[FAIL] Direct header (Target Level: $SECURITY_LEVEL): $header_line")
                fi
            done <<< "$direct_headers"
        fi
    fi
    
    # Consolidated Audit Result Breakdown
    log_message "=== Audit Result Breakdown ==="
    for h in ${compliant_headers[@]+"${compliant_headers[@]}"}; do log_message "  $h"; done
    for h in ${weak_headers[@]+"${weak_headers[@]}"}; do log_message "  $h"; done
    for h in ${non_compliant_headers[@]+"${non_compliant_headers[@]}"}; do log_message "  $h"; done
    log_message "=============================="
    
    # Update total header count to reflect all detected configurations
    header_count=$((compliant_count + non_compliant_count))
    
    # Determine overall status
    if [[ $header_count -gt 1 ]]; then
        details="Multiple HSTS configurations found ($header_count total). Only one compliant configuration should exist."
        is_correct=1
    elif [[ $compliant_count -eq 1 ]] && [[ $non_compliant_count -eq 0 ]]; then
        if [[ ${#weak_headers[@]} -gt 0 ]]; then
            details="HSTS is compliant but weak (missing includeSubDomains directive)."
            is_correct=0 # Still counted as successful audit/compliant
        else
            details="HSTS is correctly configured with exactly one compliant definition."
            is_correct=0
        fi
    elif [[ $header_count -eq 0 ]]; then
        details="No HSTS header definitions found in configuration"
        is_correct=1
    else
        details="Non-compliant HSTS configuration found: $non_compliant_count failed issues."
        is_correct=1
    fi
    
    AUDIT_RESULT="$details"
    AUDIT_HEADER_COUNT=$header_count
    AUDIT_COMPLIANT_COUNT=$compliant_count
    AUDIT_NON_COMPLIANT_COUNT=$non_compliant_count
    AUDIT_CURRENT_MAX_AGE="${max_age_val:-}"
    AUDIT_CURRENT_SUBDOMAINS="${include_subdomains_val:-}"
    AUDIT_CURRENT_PRELOAD="${preload_val:-}"
    return $is_correct
}

# Function: Remove all existing HSTS configurations
# Parameters: config_content, output_file
# Returns: 0 on success, 1 on failure
remove_all_hsts_configs() {
    local config_content="$1"
    local output_file="$2"
    
    # Use a temporary file for intermediate steps
    local temp_xml=$(mktemp)
    echo "$config_content" > "$temp_xml"
    
    # Remove filter and filter-mapping blocks containing HSTS keywords
    # Use a more robust approach that handles single-line and multi-line blocks
    # We use sed to first normalize potential single-line blocks into multi-line for easier processing
    # but that might be overkill. A better awk script that checks for closing tags on the same line:
    awk '
    {
        if (/<filter>|<filter-mapping>/) {
            block = $0
            if (/<filter>.*<\/filter>|<filter-mapping>.*<\/filter-mapping>/) {
                # Single line block
                if (block !~ /HstsHeaderFilter|HttpHeaderSecurityFilter|org\.apache\.catalina\.filters\.HttpHeaderSecurityFilter/) {
                    print block
                }
            } else {
                # Multi-line block
                found = (block ~ /HstsHeaderFilter|HttpHeaderSecurityFilter|org\.apache\.catalina\.filters\.HttpHeaderSecurityFilter/)
                while ((getline line) > 0) {
                    block = block "\n" line
                    if (line ~ /HstsHeaderFilter|HttpHeaderSecurityFilter|org\.apache\.catalina\.filters\.HttpHeaderSecurityFilter/) found = 1
                    if (line ~ /<\/filter>|<\/filter-mapping>/) break
                }
                if (!found) print block
            }
        } else {
            print $0
        }
    }
    ' "$temp_xml" > "$output_file"
    
    rm -f "$temp_xml"
    return 0
}

# Function: Apply compliant HSTS configuration
# Parameters: config_content, config_path, output_file
# Returns: 0 on success, 1 on failure
apply_compliant_hsts() {
    local config_content="$1"
    local config_path="$2"
    local output_file="$3"
    local filename=$(basename "$config_path")
    
    # First, remove all existing HSTS configurations
    local temp_file=$(mktemp) || {
        log_error "Failed to create temporary file"
        return 1
    }
    TEMP_FILES+=("$temp_file")
    remove_all_hsts_configs "$config_content" "$temp_file"
    local cleaned_content=$(cat "$temp_file")
    # Clean up this temp file immediately after use
    rm -f "$temp_file"
    
    # Check if file is XML (check both original and cleaned content for robustness)
    local is_xml=0
    local first_line_config=$(echo "$config_content" | head -n 1)
    local first_line_cleaned=$(echo "$cleaned_content" | head -n 1)
    
    if echo "$first_line_config" | grep -q "<?xml" 2>/dev/null; then
        is_xml=1
    elif echo "$first_line_cleaned" | grep -q "<?xml" 2>/dev/null; then
        is_xml=1
    fi
    
    # Debug: Log XML detection result (removed - was for testing only)
    # log_message "DEBUG: is_xml=$is_xml, filename=$filename"
    
    if [[ $is_xml -eq 1 ]]; then
        # XML-based configuration (web.xml, context.xml, server.xml)
        if [[ "$filename" == "web.xml" ]] || [[ "$filename" == "context.xml" ]] || echo "$filename" | grep -q "web\.xml$" || echo "$filename" | grep -q "context\.xml$"; then
            # Add compliant filter configuration
            local filter_block="    <filter>
        <filter-name>HstsHeaderFilter</filter-name>
        <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>
        <init-param>
            <param-name>hstsMaxAgeSeconds</param-name>
            <param-value>$MIN_MAX_AGE</param-value>
        </init-param>
        <init-param>
            <param-name>hstsIncludeSubDomains</param-name>
            <param-value>$REQUIRE_SUBDOMAINS</param-value>
        </init-param>"
            
            if [[ "$REQUIRE_PRELOAD" == "true" ]]; then
                filter_block="$filter_block
        <init-param>
            <param-name>hstsPreload</param-name>
            <param-value>true</param-value>
        </init-param>"
            fi
            
            filter_block="$filter_block
    </filter>
    <filter-mapping>
        <filter-name>HstsHeaderFilter</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>"
            
            # Insert before closing tag with proper indentation
            # Use a more reliable approach with temporary files
            local temp_filter=$(mktemp) || {
                log_error "Failed to create temporary file for filter configuration"
                return 1
            }
            TEMP_FILES+=("$temp_filter")
            printf '%s\n' "$filter_block" > "$temp_filter"
            
            if echo "$cleaned_content" | grep -q "</web-app>"; then
                # Use perl for reliable multi-line insertion before closing tag
                if command -v perl > /dev/null 2>&1; then
                    perl -pe "s|</web-app>|$(cat "$temp_filter")\n</web-app>|" <<< "$cleaned_content" > "$output_file"
                else
                    # Fallback: build full content manually
                    local before_tag="${cleaned_content%</web-app>*}"
                    local after_tag="</web-app>${cleaned_content#*</web-app>}"
                    {
                        printf '%s' "$before_tag"
                        cat "$temp_filter"
                        printf '\n%s\n' "$after_tag"
                    } > "$output_file"
                fi
            elif echo "$cleaned_content" | grep -q "</Context>"; then
                if command -v perl > /dev/null 2>&1; then
                    perl -pe "s|</Context>|$(cat "$temp_filter")\n</Context>|" <<< "$cleaned_content" > "$output_file"
                else
                    local before_tag="${cleaned_content%</Context>*}"
                    local after_tag="</Context>${cleaned_content#*</Context>}"
                    {
                        printf '%s' "$before_tag"
                        cat "$temp_filter"
                        printf '\n%s\n' "$after_tag"
                    } > "$output_file"
                fi
            else
                # Fallback: append to end
                {
                    echo "$cleaned_content"
                    cat "$temp_filter"
                } > "$output_file"
            fi
            # Temp file will be cleaned up by trap on exit
            
            # Validate the generated XML
            if ! validate_xml "$output_file" 2>/dev/null; then
                log_error "Generated XML is invalid. Attempting to fix..."
                # Try to fix common issues
                if ! grep -q "<?xml" "$output_file"; then
                    {
                        echo '<?xml version="1.0" encoding="UTF-8"?>'
                        cat "$output_file"
                    } > "${output_file}.tmp" && mv "${output_file}.tmp" "$output_file"
                fi
            fi
        else
            # For server.xml, we might need a different approach
            # For now, add as comment with instructions
            log_message "WARNING: server.xml detected. HSTS should be configured in web.xml or context.xml for best results."
            echo "$cleaned_content" > "$output_file"
        fi
    else
        # Non-XML configuration - append compliant header
        {
            echo "$cleaned_content"
            echo ""
            echo "# HSTS Header Configuration"
            echo "Strict-Transport-Security: $RECOMMENDED_HSTS"
        } > "$output_file"
    fi
    
    return 0
}

# Function: Pre-flight checks before configuration changes
# Parameters: config_path
# Returns: 0 if all checks pass, 1 if any check fails
pre_flight_checks() {
    local config_path="$1"
    local issues=0
    
    # Check if file exists and is readable
    if [[ ! -f "$config_path" ]]; then
        log_error "Configuration file not found: $config_path"
        return 1
    fi
    
    if [[ ! -r "$config_path" ]]; then
        log_error "Configuration file is not readable: $config_path"
        ((issues++))
    fi
    
    # Check if file is writable
    if [[ ! -w "$config_path" ]]; then
        log_error "Configuration file is not writable: $config_path"
        ((issues++))
    fi
    
    # Check if backup directory is writable
    local backup_dir=$(dirname "$config_path")
    if [[ ! -w "$backup_dir" ]]; then
        log_error "Backup directory is not writable: $backup_dir"
        ((issues++))
    fi
    
    # Check available disk space (warn if less than 100MB)
    if command -v df > /dev/null 2>&1; then
        local available_space=$(df -k "$backup_dir" | tail -1 | awk '{print $4}')
        if [[ $available_space -lt 102400 ]]; then  # 100MB in KB
            log_message "WARNING: Low disk space: Only $((available_space / 1024)) MB available"
        fi
    fi
    
    # Check if Tomcat is running (warn only, not an error)
    if ps aux 2>/dev/null | grep -i "[t]omcat\|[c]atalina" > /dev/null 2>&1; then
        log_message "WARNING: Tomcat appears to be running"
        log_message "WARNING: Tomcat restart will be required for changes to take effect"
    fi
    
    # Check for SELinux if enabled
    if command -v getenforce > /dev/null 2>&1; then
        if [[ $(getenforce 2>/dev/null) != "Disabled" ]]; then
            log_message "INFO: SELinux is enabled - context will be preserved"
        fi
    fi
    
    if [[ $issues -gt 0 ]]; then
        log_error "Pre-flight checks failed with $issues issue(s)"
        return 1
    fi
    
    log_message "Pre-flight checks passed"
    return 0
}

# Function: Create backup of configuration file
# Parameters: config_path
# Returns: Path to backup file
backup_config() {
    local config_path="$1"
    local backup_path="${config_path}.backup.$(date +%Y%m%d_%H%M%S)"
    
    if [[ ! -f "$config_path" ]]; then
        log_error "Configuration file not found: $config_path"
        return 1
    fi
    
    if [[ ! -w "$(dirname "$config_path")" ]]; then
        log_error "Permission denied: Cannot write backup to directory: $(dirname "$config_path")"
        return 1
    fi
    
    cp "$config_path" "$backup_path" || {
        log_error "Failed to create backup: $backup_path"
        return 1
    }
    
    log_message "Backup created: $backup_path"
    # Set global backup path
    BACKUP_PATH="$backup_path"
    return 0
}

# Function: Configure HSTS headers
# Parameters: config_content, config_path
# Returns: Exit code 0 for success, 1 for failure
configure_hsts_headers() {
    local config_content="$1"
    local config_path="$2"
    local temp_file=$(mktemp) || {
        log_error "Failed to create temporary file"
        CONFIGURE_RESULT="Failed to create temporary file"
        return 1
    }
    TEMP_FILES+=("$temp_file")
    local success=1
    local message=""
    
    # Apply compliant configuration
    if ! apply_compliant_hsts "$config_content" "$config_path" "$temp_file"; then
        message="Failed to generate compliant HSTS configuration"
        CONFIGURE_RESULT="$message"
        return 1
    fi
    
    # Verify the configuration was applied - check for either filter-based or direct header
    local new_content=$(cat "$temp_file")
    local has_filter_config=false
    local has_direct_header=false
    
    # Check for filter-based configuration (hstsMaxAgeSeconds)
    if echo "$new_content" | grep -qi "hstsMaxAgeSeconds"; then
        # Verify the max-age value is correct
        if echo "$new_content" | grep -q "$MIN_MAX_AGE"; then
            has_filter_config=true
        fi
    fi
    
    # Check for direct header configuration
    if echo "$new_content" | grep -qi "max-age=$MIN_MAX_AGE\\|max-age: *$MIN_MAX_AGE"; then
        has_direct_header=true
    fi
    
    # At least one configuration method must be present
    if [[ "$has_filter_config" == "false" ]] && [[ "$has_direct_header" == "false" ]]; then
        message="Failed to apply compliant HSTS configuration - verification failed (expected max-age=$MIN_MAX_AGE)"
        CONFIGURE_RESULT="$message"
        return 1
    fi
    
    if [[ "$REQUIRE_SUBDOMAINS" == "true" ]]; then
        if ! echo "$new_content" | grep -qi "hstsIncludeSubDomains.*true\|includeSubDomains"; then
            message="Failed to apply compliant HSTS configuration - includeSubDomains not found"
            CONFIGURE_RESULT="$message"
            return 1
        fi
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        message="DRY RUN: Would apply compliant HSTS configuration (see diff below)"
        log_message "$message"
        if command -v diff >/dev/null 2>&1; then
            diff -u "$config_path" "$temp_file" || true
        else
            log_message "Preview of changes (diff command not available):"
            log_message "--- Original file ---"
            head -20 "$config_path" | while IFS= read -r line; do
                log_message "$line"
            done
            log_message "--- Modified file ---"
            head -20 "$temp_file" | while IFS= read -r line; do
                log_message "$line"
            done
        fi
        CONFIGURE_RESULT="$message"
        return 0
    else
        # Validate XML before writing (if it's an XML file)
        if echo "$new_content" | head -1 | grep -q "<?xml"; then
            if ! validate_xml "$temp_file" 2>/dev/null; then
                log_error "Generated XML failed validation. Aborting to prevent corruption."
                CONFIGURE_RESULT="XML validation failed - configuration not applied"
                return 1
            fi
        fi
        
        # Preserve original file permissions, ownership, and SELinux context
        local original_perms=""
        local original_owner=""
        local original_selinux_context=""
        
        # Get original permissions (platform-independent approach)
        if command -v stat > /dev/null 2>&1; then
            # Try GNU stat first (Linux)
            original_perms=$(stat -c '%a' "$config_path" 2>/dev/null) || \
            # Fallback to BSD stat (macOS/BSD)
            original_perms=$(stat -f '%A' "$config_path" 2>/dev/null) || true
            
            # Get original owner
            original_owner=$(stat -c '%U:%G' "$config_path" 2>/dev/null) || \
            original_owner=$(stat -f '%Su:%Sg' "$config_path" 2>/dev/null) || true
        fi
        
        # Get SELinux context if SELinux is enabled
        if command -v getenforce > /dev/null 2>&1 && [[ $(getenforce 2>/dev/null) != "Disabled" ]]; then
            if command -v ls > /dev/null 2>&1; then
                original_selinux_context=$(ls -Z "$config_path" 2>/dev/null | awk '{print $1}')
            fi
        fi
        
        # ATOMIC OPERATION: Use mv for atomic file replacement
        # Create a temp file in the same directory for atomic move
        local temp_atomic="${config_path}.tmp.$$"
        
        if cp "$temp_file" "$temp_atomic" 2>/dev/null; then
            # Restore original permissions before atomic move
            if [[ -n "$original_perms" ]]; then
                chmod "$original_perms" "$temp_atomic" 2>/dev/null || {
                    log_message "WARNING: Could not restore original permissions ($original_perms)"
                }
            fi
            
            # Restore original ownership if we captured it and have permission
            if [[ -n "$original_owner" ]] && [[ $EUID -eq 0 ]]; then
                chown "$original_owner" "$temp_atomic" 2>/dev/null || {
                    log_message "WARNING: Could not restore original ownership ($original_owner)"
                }
            fi
            
            # Restore SELinux context if captured
            if [[ -n "$original_selinux_context" ]] && command -v chcon > /dev/null 2>&1; then
                chcon "$original_selinux_context" "$temp_atomic" 2>/dev/null || {
                    log_message "WARNING: Could not restore SELinux context"
                }
            fi
            
            # ATOMIC MOVE: This is atomic on the same filesystem
            if mv "$temp_atomic" "$config_path" 2>/dev/null; then
                # Verify the file was written correctly
                if [[ -f "$config_path" ]] && [[ -s "$config_path" ]]; then
                    # Final validation
                    if validate_xml "$config_path" 2>/dev/null || [[ ! $(head -1 "$config_path") =~ \<\?xml ]]; then
                        success=0
                        message="Compliant HSTS configuration applied successfully. All duplicate/non-compliant headers removed."
                        # Clean up temp file on success
                        rm -f "$temp_file"
                    else
                        # AUTOMATIC ROLLBACK: Validation failed after write
                        log_error "Post-write validation failed"
                        log_message "ROLLBACK: Restoring original configuration from backup..."
                        if [[ -n "$BACKUP_PATH" ]] && [[ -f "$BACKUP_PATH" ]]; then
                            if cp "$BACKUP_PATH" "$config_path" 2>/dev/null; then
                                log_message "ROLLBACK: Successfully restored original configuration"
                                message="Configuration validation failed - original file restored from backup"
                            else
                                log_error "CRITICAL: Rollback failed! Manual restoration required from: $BACKUP_PATH"
                                message="CRITICAL: Rollback failed - manual restoration required"
                            fi
                        else
                            log_error "CRITICAL: No backup available for rollback"
                            message="CRITICAL: Validation failed and no backup available"
                        fi
                        success=1
                    fi
                else
                    # AUTOMATIC ROLLBACK: File appears corrupted
                    log_error "Configuration file appears to be empty or corrupted after write"
                    log_message "ROLLBACK: Restoring original configuration from backup..."
                    if [[ -n "$BACKUP_PATH" ]] && [[ -f "$BACKUP_PATH" ]]; then
                        if cp "$BACKUP_PATH" "$config_path" 2>/dev/null; then
                            log_message "ROLLBACK: Successfully restored original configuration"
                            message="File corruption detected - original file restored from backup"
                        else
                            log_error "CRITICAL: Rollback failed! Manual restoration required from: $BACKUP_PATH"
                            message="CRITICAL: Rollback failed - manual restoration required"
                        fi
                    fi
                    success=1
                fi
            else
                # AUTOMATIC ROLLBACK: Atomic move failed
                log_error "Atomic move operation failed"
                log_message "ROLLBACK: Restoring original configuration from backup..."
                rm -f "$temp_atomic"  # Clean up failed temp file
                if [[ -n "$BACKUP_PATH" ]] && [[ -f "$BACKUP_PATH" ]]; then
                    if cp "$BACKUP_PATH" "$config_path" 2>/dev/null; then
                        log_message "ROLLBACK: Successfully restored original configuration"
                        message="Write operation failed - original file restored from backup"
                    else
                        log_error "CRITICAL: Rollback failed! Manual restoration required from: $BACKUP_PATH"
                        message="CRITICAL: Rollback failed - manual restoration required"
                    fi
                fi
                success=1
            fi
        else
            message="Failed to create temporary file - check permissions"
            success=1
        fi
    fi
    
    CONFIGURE_RESULT="$message"
    return $success
}

# Function: Log audit results
log_audit_results() {
    local is_correct="$1"
    local details="$2"
    local config_file="${3:-}"  # Optional: specific config file path
    
    if [[ $is_correct -eq 0 ]]; then
        log_message "SUCCESS: $details"
        log_message "HSTS configuration is compliant."
    else
        log_message "FAILURE: $details"
        log_message "HSTS configuration needs to be updated."
        if [[ $AUDIT_HEADER_COUNT -gt 1 ]]; then
            log_message "ACTION REQUIRED: Remove duplicate HSTS definitions. Only one compliant configuration should exist."
        fi
        # Show per-file configure commands if we have a specific config path
        if [[ -n "$config_file" ]]; then
            local conf_dir=$(dirname "$config_file")
            log_message ""
            log_message "To configure THIS installation, run one of:"
            log_message "  Option 1: sudo $0 --mode configure --security-level basic --custom-conf=$conf_dir"
            log_message "  Option 2: sudo $0 --mode configure --security-level high --custom-conf=$conf_dir"
            log_message "  Option 3: sudo $0 --mode configure --security-level veryhigh --custom-conf=$conf_dir"
            log_message "  Option 4: sudo $0 --mode configure --security-level maximum --custom-conf=$conf_dir"
        fi
    fi
}

# Function: Prompt for confirmation
confirm_configure() {
    # Non-interactive: Always proceed.
    # The --dry-run option is the mechanism for safety checks.
    return 0
}

# Function: Load custom paths from file
load_custom_paths_from_file() {
    local paths_file="$1"
    local paths=()
    
    if [[ -z "$paths_file" ]] || [[ ! -f "$paths_file" ]]; then
        echo ""
        return 0
    fi
    
    while IFS= read -r line || [[ -n "$line" ]]; do
        # Trim whitespace
        line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        # Skip empty lines and comments
        if [[ -n "$line" ]] && [[ ! "$line" =~ ^# ]]; then
            paths+=("$line")
        fi
    done < "$paths_file"
    
    if [[ ${#paths[@]} -gt 0 ]]; then
        log_message "Loaded ${#paths[@]} custom configuration path(s) from file: $paths_file"
        printf '%s\n' "${paths[@]}"
    fi
    
    return 0
}

# Function: Detect Tomcat version from installation directory
# Parameters: conf_path
# Returns: Tomcat version string or "Unknown"
get_tomcat_version() {
    local conf_path="$1"
    local tomcat_home
    tomcat_home=$(dirname "$conf_path")
    local version="Unknown"
    
    # Check RELEASE-NOTES
    if [[ -f "$tomcat_home/RELEASE-NOTES" ]]; then
        version=$(grep -i "Apache Tomcat Version" "$tomcat_home/RELEASE-NOTES" | awk '{print $NF}' | sed 's/\r//g')
    fi
    
    # Check version.sh if possible
    if [[ "$version" == "Unknown" ]] && [[ -f "$tomcat_home/bin/version.sh" ]]; then
        if command -v java >/dev/null 2>&1; then
            version=$("$tomcat_home/bin/version.sh" 2>/dev/null | grep "Server version" | cut -d'/' -f2 | sed 's/\r//g')
        fi
    fi
    
    # Check jar manifest if ZIP is available (less likely but possible)
    if [[ "$version" == "Unknown" ]] && [[ -f "$tomcat_home/lib/catalina.jar" ]] && command -v unzip >/dev/null 2>&1; then
        version=$(unzip -p "$tomcat_home/lib/catalina.jar" META-INF/MANIFEST.MF | grep "Implementation-Version" | cut -d: -f2 | tr -d ' \r')
    fi
    
    echo "${version:-Unknown}"
}

# Function: Check if Tomcat version supports HttpHeaderSecurityFilter
# Parameters: version
# Returns: 0 if supported, 1 if not
check_hsts_support() {
    local version="$1"
    if [[ "$version" == "Unknown" ]]; then return 0; fi
    
    # Remove any non-numeric characters from the beginning (e.g., "tomcat-")
    version=$(echo "$version" | sed 's/^[^0-9]*//')
    
    local major=$(echo "$version" | cut -d. -f1)
    local minor=$(echo "$version" | cut -d. -f2 | sed 's/[^0-9].*//')
    local patch=$(echo "$version" | cut -d. -f3 | sed 's/[^0-9].*//')
    
    # Handle empty minor/patch
    minor=${minor:-0}
    patch=${patch:-0}
    
    # Support added in:
    # 9.0.0.M6, 8.5.1, 8.0.35, 7.0.69
    if [[ $major -ge 9 ]]; then return 0; fi
    if [[ $major -eq 8 ]]; then
        if [[ $minor -ge 5 ]]; then
            if [[ $patch -ge 1 ]]; then return 0; fi
        elif [[ $minor -eq 0 ]]; then
            if [[ $patch -ge 35 ]]; then return 0; fi
        fi
    fi
    if [[ $major -eq 7 ]] && [[ $patch -ge 69 ]]; then return 0; fi
    
    return 1
}

# Function: Auto-detect Tomcat configuration directories
# Returns: Newline-separated list of conf directory paths
get_tomcat_conf_paths() {
    local custom_conf_paths=("$@")
    local conf_paths=()
    local conf_path=""
    
    # Check custom paths provided as arguments (deduplicate)
    local seen_paths=()
    for custom_path in ${custom_conf_paths[@]+"${custom_conf_paths[@]}"}; do
        if [[ -n "$custom_path" ]]; then
            local seen=0
            if [[ ${#seen_paths[@]} -gt 0 ]]; then
                for seen_path in "${seen_paths[@]}"; do
                    if [[ "$seen_path" == "$custom_path" ]]; then
                        seen=1
                        break
                    fi
                done
            fi
            
            if [[ $seen -eq 0 ]]; then
                seen_paths+=("$custom_path")
                log_message "Checking custom configuration path: $custom_path"
                if [[ -d "$custom_path" ]] && [[ -f "$custom_path/server.xml" ]]; then
                    conf_paths+=("$custom_path")
                    log_message "Found valid Tomcat configuration at custom path: $custom_path"
                else
                    log_error "Invalid custom configuration path: $custom_path"
                    log_error "  - Missing server.xml or directory does not exist"
                fi
            fi
        fi
    done
    
    # If custom paths were found, return them
    if [[ ${#conf_paths[@]} -gt 0 ]]; then
        printf '%s\n' "${conf_paths[@]}"
        return 0
    fi
    
    # Check CATALINA_BASE
    if [[ -n "${CATALINA_BASE:-}" ]] && [[ -d "${CATALINA_BASE:-}/conf" ]] && [[ -f "${CATALINA_BASE:-}/conf/server.xml" ]]; then
        local cb_conf="${CATALINA_BASE}/conf"
        # Add to conf_paths if not already there
        local found_cb=0
        for p in "${conf_paths[@]}"; do
            if [[ "$p" == "$cb_conf" ]]; then found_cb=1; break; fi
        done
        if [[ $found_cb -eq 0 ]]; then
            conf_paths+=("$cb_conf")
            log_message "Found Tomcat configuration at CATALINA_BASE: $cb_conf"
        fi
    fi
    
    # Check CATALINA_HOME
    if [[ -n "${CATALINA_HOME:-}" ]] && [[ -d "${CATALINA_HOME:-}/conf" ]] && [[ -f "${CATALINA_HOME:-}/conf/server.xml" ]]; then
        local ch_conf="${CATALINA_HOME}/conf"
        local found_ch=0
        for p in "${conf_paths[@]}"; do
            if [[ "$p" == "$ch_conf" ]]; then found_ch=1; break; fi
        done
        if [[ $found_ch -eq 0 ]]; then
            conf_paths+=("$ch_conf")
            log_message "Found Tomcat configuration at CATALINA_HOME: $ch_conf"
        fi
    fi
    
    # Check systemd service files
    if [[ -d "/etc/systemd/system" ]]; then
        while IFS= read -r service_file; do
            if [[ -f "$service_file" ]] && grep -qi "tomcat\|catalina" "$service_file"; then
                local service_path=$(grep -i "ExecStart\|WorkingDirectory" "$service_file" | head -1 | sed 's/.*=//' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sed 's/\/bin\/.*//' | sed 's/\/catalina.*//')
                if [[ -n "$service_path" ]] && [[ -d "$service_path/conf" ]] && [[ -f "$service_path/conf/server.xml" ]]; then
                    local s_conf="$service_path/conf"
                    local found_s=0
                    for p in "${conf_paths[@]}"; do
                        if [[ "$p" == "$s_conf" ]]; then found_s=1; break; fi
                    done
                    if [[ $found_s -eq 0 ]]; then
                        conf_paths+=("$s_conf")
                        log_message "Found Tomcat via systemd: $s_conf"
                    fi
                fi
            fi
        done < <(find /etc/systemd/system -name "*.service" -type f 2>/dev/null | head -50)
    fi
    
    # Check init.d scripts
    if [[ -d "/etc/init.d" ]]; then
        while IFS= read -r init_script; do
            if [[ -f "$init_script" ]] && grep -qi "tomcat\|catalina" "$init_script"; then
                local script_path=$(grep -i "CATALINA_HOME\|CATALINA_BASE\|TOMCAT_HOME" "$init_script" | head -1 | sed 's/.*=//' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sed 's/"//g' | sed "s/'//g")
                if [[ -n "$script_path" ]] && [[ -d "$script_path/conf" ]] && [[ -f "$script_path/conf/server.xml" ]]; then
                    local i_conf="$script_path/conf"
                    local found_i=0
                    for p in "${conf_paths[@]}"; do
                        if [[ "$p" == "$i_conf" ]]; then found_i=1; break; fi
                    done
                    if [[ $found_i -eq 0 ]]; then
                        conf_paths+=("$i_conf")
                        log_message "Found Tomcat via init.d: $i_conf"
                    fi
                fi
            fi
        done < <(find /etc/init.d -name "*tomcat*" -type f 2>/dev/null | head -20)
    fi
    
    # Check running processes
    while read -r tomcat_process; do
        if [[ -n "$tomcat_process" ]]; then
            local proc_path=$(echo "$tomcat_process" | awk '{for(i=1;i<=NF;i++) if($i ~ /-Dcatalina\.home=|catalina\.base=/) {print $i; exit}}' | sed 's/.*=//')
            if [[ -n "$proc_path" ]] && [[ -d "$proc_path/conf" ]] && [[ -f "$proc_path/conf/server.xml" ]]; then
                local p_conf="$proc_path/conf"
                local found_p=0
                for p in "${conf_paths[@]}"; do
                    if [[ "$p" == "$p_conf" ]]; then found_p=1; break; fi
                done
                if [[ $found_p -eq 0 ]]; then
                    conf_paths+=("$p_conf")
                    log_message "Found Tomcat via running process: $p_conf"
                fi
            fi
        fi
    done < <(ps aux 2>/dev/null | grep -i "[t]omcat\|[c]atalina")
    
    # Check package managers for Tomcat installations
    log_message "Checking package managers for Tomcat installations..."
    
    # Debian/Ubuntu (dpkg/apt)
    if command -v dpkg > /dev/null 2>&1; then
        log_message "Checking dpkg for Tomcat packages..."
        tomcat_packages=$(dpkg -l 2>/dev/null | grep -i tomcat | awk '{print $2}')
        for package in $tomcat_packages; do
            if [[ -n "$package" ]]; then
                # Get package files and find conf/server.xml
                conf_path=$(dpkg -L "$package" 2>/dev/null | grep "conf/server.xml" | sed 's|/server.xml||')
                if [[ -n "$conf_path" ]] && [[ -f "$conf_path/server.xml" ]]; then
                    # Check if not already in list
                    local found_pkg=0
                    for p in "${conf_paths[@]}"; do
                        if [[ "$p" == "$conf_path" ]]; then found_pkg=1; break; fi
                    done
                    if [[ $found_pkg -eq 0 ]]; then
                        conf_paths+=("$conf_path")
                        log_message "Found Tomcat via dpkg package '$package': $conf_path"
                    fi
                fi
            fi
        done
    fi
    
    # Red Hat/CentOS/Fedora (rpm/yum)
    if command -v rpm > /dev/null 2>&1; then
        log_message "Checking rpm for Tomcat packages..."
        tomcat_packages=$(rpm -qa 2>/dev/null | grep -i tomcat)
        for package in $tomcat_packages; do
            if [[ -n "$package" ]]; then
                # Get package files and find conf/server.xml
                conf_path=$(rpm -ql "$package" 2>/dev/null | grep "conf/server.xml" | sed 's|/server.xml||')
                if [[ -n "$conf_path" ]] && [[ -f "$conf_path/server.xml" ]]; then
                    local found_rpm=0
                    for p in "${conf_paths[@]}"; do
                        if [[ "$p" == "$conf_path" ]]; then found_rpm=1; break; fi
                    done
                    if [[ $found_rpm -eq 0 ]]; then
                        conf_paths+=("$conf_path")
                        log_message "Found Tomcat via rpm package '$package': $conf_path"
                    fi
                fi
            fi
        done
    fi
    
    # Arch Linux (pacman)
    if command -v pacman > /dev/null 2>&1; then
        log_message "Checking pacman for Tomcat packages..."
        tomcat_packages=$(pacman -Q 2>/dev/null | grep -i tomcat | awk '{print $1}')
        for package in $tomcat_packages; do
            if [[ -n "$package" ]]; then
                # Get package files and find conf/server.xml
                conf_path=$(pacman -Ql "$package" 2>/dev/null | grep "conf/server.xml" | awk '{print $2}' | sed 's|/server.xml||')
                if [[ -n "$conf_path" ]] && [[ -f "$conf_path/server.xml" ]]; then
                    local found_pac=0
                    for p in "${conf_paths[@]}"; do
                        if [[ "$p" == "$conf_path" ]]; then found_pac=1; break; fi
                    done
                    if [[ $found_pac -eq 0 ]]; then
                        conf_paths+=("$conf_path")
                        log_message "Found Tomcat via pacman package '$package': $conf_path"
                    fi
                fi
            fi
        done
    fi
    
    # Search common paths
    log_message "Checking standard locations for Tomcat configurations..."
    for path in \
            "/opt/tomcat/conf" \
            "/opt/tomcat7/conf" \
            "/opt/tomcat8/conf" \
            "/opt/tomcat9/conf" \
            "/opt/tomcat10/conf" \
            "/usr/local/tomcat/conf" \
            "/usr/local/tomcat7/conf" \
            "/usr/local/tomcat8/conf" \
            "/usr/local/tomcat9/conf" \
            "/usr/local/tomcat10/conf" \
            "/var/lib/tomcat7/conf" \
            "/var/lib/tomcat8/conf" \
            "/var/lib/tomcat9/conf" \
            "/var/lib/tomcat10/conf" \
            "/etc/tomcat7" \
            "/etc/tomcat8" \
            "/etc/tomcat9" \
            "/etc/tomcat10" \
            "/etc/tomcat11" \
            "/etc/tomcat7/conf" \
            "/etc/tomcat8/conf" \
            "/etc/tomcat9/conf" \
            "/etc/tomcat10/conf" \
            "/etc/tomcat11/conf" \
            "/opt/tomcat11/conf" \
            "/usr/local/tomcat11/conf" \
            "/var/lib/tomcat11/conf" \
            "/etc/tomcat/conf" \
            "/srv/tomcat/conf" \
            "/srv/tomcat7/conf" \
            "/srv/tomcat8/conf" \
            "/srv/tomcat9/conf" \
            "/srv/tomcat10/conf" \
            "/srv/tomcat11/conf" \
            "/srv/www/tomcat/conf" \
            "/app/tomcat/conf" \
            "/app/tomcat7/conf" \
            "/app/tomcat8/conf" \
            "/app/tomcat9/conf" \
            "/app/tomcat10/conf" \
            "/app/tomcat11/conf" \
            "/applications/tomcat/conf"; do
            if [[ -d "${path}" ]] && [[ -f "${path}/server.xml" ]]; then
                log_message "Found Tomcat configuration at: ${path}"
                # Add to conf_paths if not already there
                local found_standard=0
                for p in "${conf_paths[@]}"; do
                    if [[ "$p" == "${path}" ]]; then
                        found_standard=1
                        break
                    fi
                done
                if [[ $found_standard -eq 0 ]]; then
                    conf_paths+=("${path}")
                    conf_path="${path}" # Keep for logic below, but we use the array now
                fi
            fi
        done
    
    # Search alternative installation directories
    for root in "/srv" "/app" "/applications"; do
        if [[ -d "$root" ]]; then
            log_message "Searching for Tomcat in: $root"
            while IFS= read -r tomcat_dir; do
                if [[ -f "$tomcat_dir/conf/server.xml" ]]; then
                    local srv_conf="$tomcat_dir/conf"
                    local found_srv=0
                    for p in "${conf_paths[@]}"; do
                        if [[ "$p" == "$srv_conf" ]]; then found_srv=1; break; fi
                    done
                    if [[ $found_srv -eq 0 ]]; then
                        conf_paths+=("$srv_conf")
                        log_message "Found Tomcat in $root: $srv_conf"
                    fi
                fi
            done < <(find "$root" -maxdepth 2 -type d -name "*tomcat*" 2>/dev/null)
        fi
    done
    
    # Fallback to find command (Linux/Unix servers only)
    # Search for all server.xml files in common locations
    log_message "Searching common paths for additional Tomcat configurations..."
    while IFS= read -r found_xml; do
        if [[ -n "$found_xml" ]]; then
            local found_dir=$(dirname "$found_xml")
            if [[ -f "$found_dir/server.xml" ]]; then
                # Add to conf_paths if not already there
                local already_found=0
                for p in "${conf_paths[@]}"; do
                    if [[ "$p" == "${found_dir}" ]]; then
                        already_found=1
                        break
                    fi
                done
                if [[ $already_found -eq 0 ]]; then
                    conf_paths+=("${found_dir}")
                    log_message "Found Tomcat configuration via search: ${found_dir}"
                fi
            fi
        fi
    done < <(find /opt /usr/local /var/lib /usr/share /etc -type f -name "server.xml" -path "*/conf/server.xml" 2>/dev/null)
    
    # Check CATALINA_BASE and CATALINA_HOME
    if [[ -n "${CATALINA_BASE:-}" ]] && [[ -d "${CATALINA_BASE}/conf" ]]; then
        local cb_conf="$CATALINA_BASE/conf"
        if [[ -f "$cb_conf/server.xml" ]]; then
            local already_cb=0
            for p in "${conf_paths[@]}"; do
                if [[ "$p" == "${cb_conf}" ]]; then
                    already_cb=1
                    break
                fi
            done
            if [[ $already_cb -eq 0 ]]; then
                conf_paths+=("${cb_conf}")
                log_message "Found Tomcat via CATALINA_BASE: ${cb_conf}"
            fi
        fi
    fi
    
    if [[ -n "${CATALINA_HOME:-}" ]] && [[ -d "${CATALINA_HOME}/conf" ]]; then
        local ch_conf="${CATALINA_HOME}/conf"
        if [[ -f "$ch_conf/server.xml" ]]; then
            local already_ch=0
            for p in "${conf_paths[@]}"; do
                if [[ "$p" == "${ch_conf}" ]]; then
                    already_ch=1
                    break
                fi
            done
            if [[ $already_ch -eq 0 ]]; then
                conf_paths+=("${ch_conf}")
                log_message "Found Tomcat via CATALINA_HOME: ${ch_conf}"
            fi
        fi
    fi
    
    if [[ ${#conf_paths[@]} -eq 0 ]]; then
        log_error "Could not locate Tomcat configuration directory."
        log_error "  - Ensure Tomcat is installed on this Linux/Unix server"
        log_error "  - Check for server.xml: sudo find /opt /usr/local /var/lib -name server.xml"
        log_error "  - Set CATALINA_HOME or CATALINA_BASE environment variables"
        log_error "  - Or specify a custom path: $SCRIPT_NAME --custom-conf=/path/to/conf"
        log_error "  - Or specify multiple paths: $SCRIPT_NAME --custom-conf=/path1 --custom-conf=/path2"
        log_error "  - Or specify a paths file: $SCRIPT_NAME --custom-paths-file=/path/to/file"
        return 1
    fi
    
    # Return all found paths as newline-separated list
    printf '%s\n' "${conf_paths[@]}"
    return 0
}

# Function: Find web.xml files in Tomcat installation
# Parameters: conf_path
# Returns: Array of web.xml file paths
find_web_xml_files() {
    local conf_path="$1"
    local tomcat_home=$(dirname "$conf_path")
    local web_xml_files=()
    
    log_message "Searching for web.xml files..."
    
    # Check global web.xml in conf directory
    if [[ -f "$conf_path/web.xml" ]]; then
        web_xml_files+=("$conf_path/web.xml")
        log_message "  Found: $conf_path/web.xml (global configuration)"
    fi
    
    # Check context.xml in conf directory
    if [[ -f "$conf_path/context.xml" ]]; then
        web_xml_files+=("$conf_path/context.xml")
        log_message "  Found: $conf_path/context.xml (context configuration)"
    fi
    
    # Search webapps directories for application-specific web.xml files
    if [[ -d "$tomcat_home/webapps" ]]; then
        while IFS= read -r webxml; do
            if [[ -f "$webxml" ]]; then
                web_xml_files+=("$webxml")
                log_message "  Found: $webxml (application-specific)"
            fi
        done < <(find "$tomcat_home/webapps" -type f -name "web.xml" -path "*/WEB-INF/web.xml" 2>/dev/null)
    fi
    
    if [[ ${#web_xml_files[@]} -eq 0 ]]; then
        log_message "  No web.xml files found"
    else
        log_message "Found ${#web_xml_files[@]} web.xml file(s) to process"
    fi
    
    # Return array (newline-separated for safer handling of paths with spaces)
    printf '%s\n' "${web_xml_files[@]}"
}

# Function: Process a single web.xml file
process_web_xml() {
    local web_xml_path="$1"
    local overall_success=0
    
    # Only show processing header if not in quiet mode
    if [[ "$QUIET_MODE" != "true" ]]; then
        log_message ""
        log_message "========================================="
        log_message "Processing: $web_xml_path"
        log_message "========================================="
    fi
    
    # Load configuration
    local config_content
    if ! config_content=$(load_config "$web_xml_path"); then
        log_error "Failed to load configuration file: $web_xml_path"
        return 1
    fi
    
    if [[ "$MODE" == "audit" ]]; then
        # Audit mode - Analyze and add to table
        local audit_result=""
        if ! audit_hsts_headers "$config_content"; then
            local is_correct=1
        else
            local is_correct=0
        fi
        
        # Determine status and details for table
        local status=""
        local details=""
        
        if [[ $is_correct -eq 0 ]]; then
            status="Compliant"
            details="max-age=$MIN_MAX_AGE"
            [[ "$REQUIRE_SUBDOMAINS" == "true" ]] && details="$details, includeSubDomains=true"
            [[ "$REQUIRE_PRELOAD" == "true" ]] && details="$details, preload=true"
        elif [[ $AUDIT_HEADER_COUNT -eq 0 ]]; then
            status="Not Configured"
            details="No HSTS filters found"
        else
            status="Non-Compliant"
            # Extract current values for details
            if [[ -n "$AUDIT_CURRENT_MAX_AGE" ]]; then
                details="max-age=$AUDIT_CURRENT_MAX_AGE"
                [[ "$AUDIT_CURRENT_SUBDOMAINS" == "true" ]] && details="$details, includeSubDomains=true" || details="$details, includeSubDomains=false"
            else
                details="Weak or incorrect configuration"
            fi
        fi
        
        # Add row to table
        add_table_row "$web_xml_path" "$status" "$details"
        
        # Log results if not in quiet mode OR if a log file is configured for traceability
        if [[ "$QUIET_MODE" != "true" ]] || [[ -n "$LOG_FILE" ]]; then
            log_audit_results "$is_correct" "$AUDIT_RESULT" ""
        fi
        
        return $is_correct
        
    elif [[ "$MODE" == "configure" ]]; then
        # Configure mode
        if [[ "$DRY_RUN" == "true" ]]; then
            log_message "DRY RUN mode: No changes will be made"
        fi
        
        # First audit to see current state
        audit_hsts_headers "$config_content" || true
        log_message "Current state: $AUDIT_RESULT"
        
        # Check if already compliant
        if [[ $AUDIT_COMPLIANT_COUNT -eq 1 ]] && [[ $AUDIT_NON_COMPLIANT_COUNT -eq 0 ]] && [[ $AUDIT_HEADER_COUNT -eq 1 ]]; then
            log_message "SUCCESS: HSTS is already correctly configured with exactly one compliant definition"
            return 0
        fi
        
        log_message "Configuration required: Ensuring exactly one compliant HSTS definition exists"
        
        # Set CONFIG_PATH for confirm_configure function
        CONFIG_PATH="$web_xml_path"
        
        # Confirm before configuring (only once for all files)
        if [[ "$DRY_RUN" != "true" ]] && [[ -z "${CONFIRMED:-}" ]]; then
            if ! confirm_configure; then
                return 2
            fi
            CONFIRMED=1
        fi
        
        # PRE-FLIGHT: Check system state before making changes
        if [[ "$DRY_RUN" != "true" ]]; then
            log_message "Running pre-flight checks..."
            if ! pre_flight_checks "$web_xml_path"; then
                log_error "Pre-flight checks failed - skipping: $web_xml_path"
                return 2
            fi
        fi
        
        # Create backup
        local backup_path=""
        if ! backup_config "$web_xml_path"; then
            log_error "Failed to create backup - skipping: $web_xml_path"
            return 1
        fi
        
        # Apply configuration
        local configure_result=""
        if ! configure_hsts_headers "$config_content" "$web_xml_path"; then
            log_error "Failed to configure HSTS: $CONFIGURE_RESULT"
            log_message "Backup available at: $BACKUP_PATH"
            return 1
        fi
        
        log_message "SUCCESS: $CONFIGURE_RESULT"
        log_message "Backup available at: $BACKUP_PATH"
        
        return 0
    fi
}

# Function: Main entry point
main() {
    local args=("$@")
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --mode)
                if [[ $# -lt 2 ]]; then
                    log_error "Missing value for --mode"
                    usage
                fi
                MODE="$2"
                shift 2
                ;;
            --json)
                JSON_OUTPUT=true
                shift
                ;;
            --report-file|--report_file)
                if [[ $# -lt 2 ]]; then
                    log_error "Missing value for --report-file"
                    usage
                fi
                REPORT_FILE="$2"
                shift 2
                ;;
            --report-file=*|--report_file=*)
                REPORT_FILE="${1#*=}"
                shift
                ;;
            --custom-conf)
                if [[ $# -lt 2 ]]; then
                    log_error "Missing value for --custom-conf"
                    usage
                fi
                CUSTOM_CONF_PATHS+=("$2")
                shift 2
                ;;
            --custom-conf=*)
                CUSTOM_CONF_PATHS+=("${1#*=}")
                shift
                ;;
            --custom-paths-file)
                if [[ $# -lt 2 ]]; then
                    log_error "Missing value for --custom-paths-file"
                    usage
                fi
                CUSTOM_PATHS_FILE="$2"
                shift 2
                ;;
            --custom-paths-file=*)
                CUSTOM_PATHS_FILE="${1#*=}"
                shift
                ;;
            --log-file)
                if [[ $# -lt 2 ]]; then
                    log_error "Missing value for --log-file"
                    usage
                fi
                LOG_FILE="$2"
                shift 2
                ;;
            --log-file=*)
                LOG_FILE="${1#*=}"
                shift
                ;;
            --non-interactive|--non_interactive)
                NON_INTERACTIVE=true
                shift
                ;;
            --dry-run|--dry_run)
                DRY_RUN=true
                shift
                ;;
            --all)
                # Explicit flag to configure all found paths (default behavior, but explicit)
                shift
                ;;
            --security-level|--security_level)
                if [[ $# -lt 2 ]]; then
                    log_error "Missing value for --security-level"
                    usage
                fi
                SECURITY_LEVEL=$(echo "$2" | tr '[:upper:]' '[:lower:]')
                shift 2
                ;;
            --security-level=*|--security_level=*)
                SECURITY_LEVEL=$(echo "${1#*=}" | tr '[:upper:]' '[:lower:]')
                shift
                ;;
            --help|-h)
                usage
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                ;;
        esac
    done
    
    # Validate security level and set target values
    case "$SECURITY_LEVEL" in
        basic|1)
            SECURITY_LEVEL="basic"
            MIN_MAX_AGE=31536000
            REQUIRE_SUBDOMAINS=false
            REQUIRE_PRELOAD=false
            ;;
        high|2)
            SECURITY_LEVEL="high"
            MIN_MAX_AGE=31536000
            REQUIRE_SUBDOMAINS=true
            REQUIRE_PRELOAD=false
            ;;
        veryhigh|3)
            SECURITY_LEVEL="veryhigh"
            MIN_MAX_AGE=31536000
            REQUIRE_SUBDOMAINS=true
            REQUIRE_PRELOAD=true
            ;;
        maximum|4)
            SECURITY_LEVEL="maximum"
            MIN_MAX_AGE=63072000
            REQUIRE_SUBDOMAINS=true
            REQUIRE_PRELOAD=true
            ;;
        *)
            log_error "Invalid security level: $SECURITY_LEVEL. Must be 'basic', 'high', 'veryhigh', or 'maximum'."
            usage
            ;;
    esac
    
    # Update recommended strings based on level
    RECOMMENDED_HSTS="max-age=$MIN_MAX_AGE"
    [[ "$REQUIRE_SUBDOMAINS" == "true" ]] && RECOMMENDED_HSTS="$RECOMMENDED_HSTS; includeSubDomains"
    [[ "$REQUIRE_PRELOAD" == "true" ]] && RECOMMENDED_HSTS="$RECOMMENDED_HSTS; preload"
    RECOMMENDED_HSTS_FULL="Strict-Transport-Security: $RECOMMENDED_HSTS"
    
    # Enable quiet mode for audit mode to get clean table output
    if [[ "$MODE" == "audit" ]] && [[ "$JSON_OUTPUT" != "true" ]]; then
        QUIET_MODE=true
    fi
    
    # Validate mode
    if [[ -n "$LOG_FILE" ]]; then
        # Check if we can write to the log file or its directory
        if ! touch "$LOG_FILE" 2>/dev/null; then
            log_error "Cannot create log file in /var/log. Attempting fallback to /tmp..."
            LOG_FILE="/tmp/tomcat-hsts-$(date +%Y%m%d_%H%M%S).log"
            if ! touch "$LOG_FILE" 2>/dev/null; then
                log_error "Cannot create log file in /tmp either. Continuing without file logging."
                LOG_FILE=""
            else
                log_message "Logging to fallback location: $LOG_FILE" true
            fi
        fi
    fi
    
    # Print clean header if in quiet (audit) mode
    if [[ "$QUIET_MODE" == "true" ]]; then
        print_header
    else
        # Log start (verbose mode)
        log_message "========================================="
        log_message "Tomcat HSTS Configuration Tool"
        log_message "Hostname: $HOSTNAME"
        log_message "Execution Time: $TIMESTAMP"
        log_message "Mode: $MODE"
        log_message "========================================="
    fi
    
    # Collect all custom paths
    local all_custom_paths=(${CUSTOM_CONF_PATHS[@]+"${CUSTOM_CONF_PATHS[@]}"})
    
    # Add legacy single custom path if set
    if [[ -n "$CUSTOM_CONF_PATH" ]]; then
        all_custom_paths+=("$CUSTOM_CONF_PATH")
    fi
    
    # Load paths from file if specified
    if [[ -n "$CUSTOM_PATHS_FILE" ]]; then
        local file_paths
        file_paths=$(load_custom_paths_from_file "$CUSTOM_PATHS_FILE")
        if [[ -n "$file_paths" ]]; then
            while IFS= read -r path; do
                if [[ -n "$path" ]]; then
                    all_custom_paths+=("$path")
                fi
            done <<< "$file_paths"
        fi
    fi
    
    # Auto-detect Tomcat configuration directories
    local conf_paths_output
    if ! conf_paths_output=$(get_tomcat_conf_paths ${all_custom_paths[@]+"${all_custom_paths[@]}"}); then
        log_error "Failed to locate Tomcat configuration"
        exit 2
    fi
    
    # Convert output to array
    local conf_paths=()
    while IFS= read -r path; do
        if [[ -n "$path" ]]; then
            conf_paths+=("$path")
        fi
    done <<< "$conf_paths_output"
    
    if [[ ${#conf_paths[@]} -eq 0 ]]; then
        log_error "No Tomcat configuration directories found"
        exit 2
    fi
    
    # Find all web.xml files from all configuration directories
    local web_xml_files=()
    for conf_path in "${conf_paths[@]}"; do
        local tomcat_version
        tomcat_version=$(get_tomcat_version "$conf_path")
        log_message "Found Tomcat Configuration: $conf_path (Version: $tomcat_version)"
        
        if ! check_hsts_support "$tomcat_version"; then
            log_message "WARNING: Tomcat version $tomcat_version may not natively support HttpHeaderSecurityFilter."
            log_message "  - Supported versions: 7.0.69+, 8.0.35+, 8.5.1+, 9.0.0.M6+"
            log_message "  - If this is an older version, HSTS configuration may not take effect."
        fi
        while IFS= read -r file; do
            if [[ -n "$file" ]]; then
                local found=0
                if [[ ${#web_xml_files[@]} -gt 0 ]]; then
                    for existing in "${web_xml_files[@]}"; do
                        if [[ "$existing" == "$file" ]]; then
                            found=1
                            break
                        fi
                    done
                fi
                if [[ $found -eq 0 ]]; then
                    web_xml_files+=("$file")
                fi
            fi
        done <<< "$(find_web_xml_files "$conf_path")"
    done
    
    if [[ ${#web_xml_files[@]} -eq 0 ]]; then
        log_error "No web.xml files found to process"
        exit 1
    fi
    
    # Process each web.xml file
    local overall_success=0
    local processed_count=0
    local success_count=0
    local failure_count=0
    local failed_paths=()
    local success_paths=()
    
    for web_xml in "${web_xml_files[@]}"; do
        if process_web_xml "$web_xml"; then
            success_count=$((success_count + 1))
            success_paths+=("$web_xml")
        else
            failure_count=$((failure_count + 1))
            overall_success=1
            failed_paths+=("$web_xml")
        fi
        processed_count=$((processed_count + 1))
    done
    
    # Summary
    if [[ "$JSON_OUTPUT" == "false" ]]; then
        if [[ "$QUIET_MODE" == "true" ]]; then
            # Print compliance table for audit mode
            print_compliance_table
            
            # Simple overall status
            local total=$((COMPLIANT_COUNT + NON_COMPLIANT_COUNT + NOT_CONFIGURED_COUNT))
            if [[ $COMPLIANT_COUNT -eq $total ]] && [[ $total -gt 0 ]]; then
                echo "Overall Status: Compliant ($COMPLIANT_COUNT Compliant)"
            else
                echo "Overall Status: Non-Compliant ($COMPLIANT_COUNT Compliant, $NON_COMPLIANT_COUNT Non-Compliant, $NOT_CONFIGURED_COUNT Not Configured)"
            fi
            
            echo "Audit completed. Log: ${LOG_FILE:-None}"
        else
            # Verbose mode (configure mode)
            log_message ""
            log_message "========================================="
            log_message "Summary"
            log_message "========================================="
            log_message "Total files processed: $processed_count"
            log_message "Successful: $success_count"
            log_message "Failed: $failure_count"
            
            if [[ $overall_success -eq 0 ]]; then
                log_message "Overall Status: SUCCESS"
            else
                log_message "Overall Status: FAILURE (some files failed)"
            fi
            
            if [[ -n "$LOG_FILE" ]]; then
                log_message "Log file: $LOG_FILE"
            fi
        fi
    fi

    # Build JSON Report
    local json_report="{"
    json_report+="\"hostname\":\"$HOSTNAME\","
    json_report+="\"os\":\"$OS_INFO\","
    json_report+="\"timestamp\":\"$TIMESTAMP\","
    json_report+="\"mode\":\"$MODE\","
    json_report+="\"total_processed\":$processed_count,"
    json_report+="\"success_count\":$success_count,"
    json_report+="\"failure_count\":$failure_count,"
    json_report+="\"overall_status\":\"$( [[ $overall_success -eq 0 ]] && echo "SUCCESS" || echo "FAILURE" )\""
    json_report+="}"

    if [[ "$JSON_OUTPUT" == "true" ]]; then
        echo "$json_report"
    fi

    if [[ -n "$REPORT_FILE" ]]; then
        echo "$json_report" > "$REPORT_FILE" 2>/dev/null || log_error "Failed to write report to $REPORT_FILE"
    fi
    
    exit $overall_success
}

# Execute main function with all arguments
main "$@"

