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
DRY_RUN=false
SCRIPT_NAME=$(basename "$0")
RECOMMENDED_HSTS="max-age=31536000; includeSubDomains"
RECOMMENDED_HSTS_FULL="Strict-Transport-Security: max-age=31536000; includeSubDomains"
HOSTNAME=$(hostname)
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

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
    echo "Usage: sudo $SCRIPT_NAME [--mode audit|configure] [--custom-conf=/path/to/conf] [--custom-paths-file=/path/to/file] [--dry-run]"
    echo ""
    echo "Options:"
    echo "  --mode <audit|configure>     Operation mode (default: configure)"
    echo "                               audit: Check HSTS configuration compliance"
    echo "                               configure: Fix HSTS configuration to be compliant"
    echo "  --custom-conf <path>         Optional: Custom Tomcat conf directory path (can be specified multiple times)"
    echo "                               If not provided, script will auto-detect Tomcat installation"
    echo "  --custom-paths-file <file>   Optional: File containing custom paths (one path per line)"
    echo "                               Lines starting with # are treated as comments"
    echo "  --dry-run                    Show what would be changed without making changes (configure mode only)"
    echo ""
    echo "Examples:"
    echo "  sudo $SCRIPT_NAME                                    # Auto-detect and configure"
    echo "  sudo $SCRIPT_NAME --mode audit                       # Auto-detect and audit only"
    echo "  sudo $SCRIPT_NAME --custom-conf=/opt/tomcat/conf     # Use custom path"
    echo "  sudo $SCRIPT_NAME --custom-conf=/opt/tomcat1/conf --custom-conf=/opt/tomcat2/conf  # Multiple paths"
    echo "  sudo $SCRIPT_NAME --custom-paths-file=/etc/tomcat-paths.txt  # Use paths file"
    echo "  sudo $SCRIPT_NAME --mode configure --dry-run         # Preview changes"
    exit 2
}

# Function: Log message to console and optionally to file
log_message() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local log_entry="[$timestamp] $message"
    
    echo "$log_entry" >&2
    
    if [[ -n "$LOG_FILE" ]]; then
        echo "$log_entry" >> "$LOG_FILE" 2>/dev/null || true
    fi
}

# Function: Log error message
log_error() {
    log_message "ERROR: $1" >&2
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
    
    # Check for null bytes
    if [[ "$file_path" =~ $'\0' ]]; then
        log_error "Invalid path: contains null byte"
        return 1
    fi
    
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
    
    # Check for max-age=31536000 (required per OWASP recommendation)
    if ! echo "$header_value" | grep -qi "max-age=31536000"; then
        return 1
    fi
    
    # Check for includeSubDomains (required per OWASP recommendation)
    if ! echo "$header_value" | grep -qi "includeSubDomains"; then
        return 1
    fi
    
    # Note: preload directive is optional and allowed but not required for compliance
    # per OWASP HSTS Cheat Sheet recommendations
    
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
        AUDIT_RESULT="$details"
        AUDIT_HEADER_COUNT=0
        AUDIT_COMPLIANT_COUNT=0
        AUDIT_NON_COMPLIANT_COUNT=0
        return 1
    fi
    
    log_message "Found $header_count HSTS header definition(s)"
    
    # Check each header for compliance
    local compliant_headers=()
    local non_compliant_headers=()
    
    # Check for filter-based HSTS configuration (Tomcat specific)
    if echo "$config_content" | grep -qi "hstsMaxAgeSeconds"; then
        # Extract the value of hstsMaxAgeSeconds even if it's on the next line
        local max_age_val=$(echo "$config_content" | sed -n '/hstsMaxAgeSeconds/{n;p;}' | grep -o '[0-9]\+')
        # Fallback if it's on the same line
        if [[ -z "$max_age_val" ]]; then
            max_age_val=$(echo "$config_content" | grep "hstsMaxAgeSeconds" | sed 's/.*hstsMaxAgeSeconds.*>\([0-9]\+\)<.*/\1/' | grep -o '^[0-9]\+$')
        fi
        
        local include_subdomains=$(echo "$config_content" | sed -n '/hstsIncludeSubDomains/{n;p;}' | grep -i "true" | wc -l | tr -d ' ')
        
        if [[ -n "$max_age_val" ]] && [[ "$max_age_val" == "31536000" ]]; then
            if [[ $include_subdomains -gt 0 ]]; then
                compliant_count=$((compliant_count + 1))
                compliant_headers+=("Filter-based HSTS configuration")
            else
                non_compliant_count=$((non_compliant_count + 1))
                non_compliant_headers+=("Filter-based HSTS: max-age correct but includeSubDomains missing or false")
            fi
        else
            non_compliant_count=$((non_compliant_count + 1))
            non_compliant_headers+=("Filter-based HSTS: max-age is not 31536000 (found: ${max_age_val:-none})")
        fi
    fi
    
    # Check for direct header definitions (Strict-Transport-Security)
    # Only count direct headers that are NOT part of filter configuration
    local direct_headers=$(echo "$config_content" | grep -i "Strict-Transport-Security" | grep -v "^#" | grep -v "^[[:space:]]*#" | grep -v "hstsMaxAgeSeconds\|hstsIncludeSubDomains\|HttpHeaderSecurityFilter\|HstsHeaderFilter" || true)
    if [[ -n "$direct_headers" ]]; then
        local direct_count=$(echo "$direct_headers" | wc -l | tr -d ' ')
        # Count direct headers separately from filter-based config
        header_count=$((header_count + direct_count))
        
        while IFS= read -r header_line; do
            if is_compliant_header "$header_line"; then
                compliant_count=$((compliant_count + 1))
                compliant_headers+=("Direct header: $header_line")
            else
                non_compliant_count=$((non_compliant_count + 1))
                non_compliant_headers+=("Direct header (non-compliant): $header_line")
            fi
        done <<< "$direct_headers"
    fi
    
    # Determine overall status
    local total_configs=$((compliant_count + non_compliant_count))
    
    if [[ $total_configs -gt 1 ]]; then
        details="Multiple HSTS configurations found ($total_configs total). Only one compliant configuration should exist."
        is_correct=1
    elif [[ $compliant_count -eq 1 ]] && [[ $non_compliant_count -eq 0 ]]; then
        details="HSTS is correctly configured with exactly one compliant definition: max-age=31536000; includeSubDomains"
        is_correct=0
    elif [[ $compliant_count -eq 0 ]] && [[ $non_compliant_count -gt 0 ]]; then
        details="HSTS header(s) found but none are compliant. Found $non_compliant_count non-compliant definition(s)."
        is_correct=1
    elif [[ $compliant_count -gt 0 ]] && [[ $non_compliant_count -gt 0 ]]; then
        details="Mixed configuration: $compliant_count compliant and $non_compliant_count non-compliant HSTS definition(s) found."
        is_correct=1
    else
        details="HSTS configuration issue detected"
        is_correct=1
    fi
    
    # Log detailed findings
    if [[ ${#compliant_headers[@]} -gt 0 ]]; then
        log_message "Compliant headers found:"
        for header in "${compliant_headers[@]}"; do
            log_message "  - $header"
        done
    fi
    
    if [[ ${#non_compliant_headers[@]} -gt 0 ]]; then
        log_message "Non-compliant headers found:"
        for header in "${non_compliant_headers[@]}"; do
            log_message "  - $header"
        done
    fi
    
    AUDIT_RESULT="$details"
    AUDIT_HEADER_COUNT=$header_count
    AUDIT_COMPLIANT_COUNT=$compliant_count
    AUDIT_NON_COMPLIANT_COUNT=$non_compliant_count
    return $is_correct
}

# Function: Remove all existing HSTS configurations
# Parameters: config_content, output_file
# Returns: 0 on success, 1 on failure
remove_all_hsts_configs() {
    local config_content="$1"
    local output_file="$2"
    local temp_content="$config_content"
    
    # Remove filter-based HSTS configurations
    # Remove HttpHeaderSecurityFilter or HstsHeaderFilter blocks (more precise pattern)
    temp_content=$(echo "$temp_content" | sed '/<filter-name>.*[Hh]sts.*Header.*Filter<\/filter-name>/,/<\/filter>/d')
    temp_content=$(echo "$temp_content" | sed '/<filter-name>.*[Hh]ttpHeaderSecurity<\/filter-name>/,/<\/filter>/d')
    
    # Remove filter-mapping for HSTS filters (only if it references our filter)
    temp_content=$(echo "$temp_content" | sed '/<filter-mapping>/,/<\/filter-mapping>/{
        /<filter-name>.*[Hh]sts.*Header.*Filter\|[Hh]ttpHeaderSecurity<\/filter-name>/d
        /HstsHeaderFilter\|httpHeaderSecurity/d
    }')
    
    # Remove hstsMaxAgeSeconds and hstsIncludeSubDomains init-params (only within filter blocks)
    # This is safer - only remove if they're in the context of a filter
    temp_content=$(echo "$temp_content" | sed '/<filter>/,/<\/filter>/{
        /<param-name>hstsMaxAgeSeconds<\/param-name>/,/<\/init-param>/d
        /<param-name>hstsIncludeSubDomains<\/param-name>/,/<\/init-param>/d
    }')
    
    # Remove direct Strict-Transport-Security header definitions (but not in comments)
    temp_content=$(echo "$temp_content" | sed '/^[[:space:]]*[^#]*Strict-Transport-Security/Id')
    
    echo "$temp_content" > "$output_file"
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
            local filter_block='    <filter>
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
    </filter-mapping>'
            
            # Insert before closing tag with proper indentation
            # Use a more reliable approach with temporary files
            local temp_filter=$(mktemp) || {
                log_error "Failed to create temporary file for filter configuration"
                return 1
            }
            TEMP_FILES+=("$temp_filter")
            printf '%s\n' "$filter_block" > "$temp_filter"
            
            if echo "$cleaned_content" | grep -q "</web-app>"; then
                # Use sed to insert before closing tag (more reliable than awk with multi-line)
                {
                    # Print everything up to (but not including) the closing tag
                    echo "$cleaned_content" | sed '/<\/web-app>/,$d' || echo "$cleaned_content"
                    # Insert the filter block
                    cat "$temp_filter"
                    # Print the closing tag and everything after
                    echo "$cleaned_content" | sed -n '/<\/web-app>/,$p' || echo "</web-app>"
                } > "$output_file"
            elif echo "$cleaned_content" | grep -q "</Context>"; then
                {
                    # Print everything up to (but not including) the closing tag
                    echo "$cleaned_content" | sed '/<\/Context>/,$d' || echo "$cleaned_content"
                    # Insert the filter block
                    cat "$temp_filter"
                    # Print the closing tag and everything after
                    echo "$cleaned_content" | sed -n '/<\/Context>/,$p' || echo "</Context>"
                } > "$output_file"
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
    
    # Verify the configuration was applied
    local new_content=$(cat "$temp_file")
    if ! echo "$new_content" | grep -qi "hstsMaxAgeSeconds" || ! echo "$new_content" | grep -qi "31536000"; then
        if ! echo "$new_content" | grep -qi "max-age=31536000"; then
            message="Failed to apply compliant HSTS configuration - verification failed"
            CONFIGURE_RESULT="$message"
            return 1
        fi
    fi
    
    if ! echo "$new_content" | grep -qi "hstsIncludeSubDomains.*true\|includeSubDomains"; then
        message="Failed to apply compliant HSTS configuration - includeSubDomains not found"
        CONFIGURE_RESULT="$message"
        return 1
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
        
        # Preserve original file permissions and ownership
        local original_perms=""
        local original_owner=""
        
        # Get original permissions (platform-independent approach)
        if command -v stat >/dev/null 2>&1; then
            # Try GNU stat first (Linux)
            original_perms=$(stat -c '%a' "$config_path" 2>/dev/null) || \
            # Fallback to BSD stat (macOS/BSD)
            original_perms=$(stat -f '%A' "$config_path" 2>/dev/null) || true
            
            # Get original owner
            original_owner=$(stat -c '%U:%G' "$config_path" 2>/dev/null) || \
            original_owner=$(stat -f '%Su:%Sg' "$config_path" 2>/dev/null) || true
        fi
        
        # Write back to original file
        if cp "$temp_file" "$config_path" 2>/dev/null; then
            # Restore original permissions if we captured them
            if [[ -n "$original_perms" ]]; then
                chmod "$original_perms" "$config_path" 2>/dev/null || {
                    log_message "WARNING: Could not restore original permissions ($original_perms)"
                }
            fi
            
            # Restore original ownership if we captured it and have permission
            if [[ -n "$original_owner" ]] && [[ $EUID -eq 0 ]]; then
                chown "$original_owner" "$config_path" 2>/dev/null || {
                    log_message "WARNING: Could not restore original ownership ($original_owner)"
                }
            fi
            
            # Verify the file was written correctly
            if [[ -f "$config_path" ]] && [[ -s "$config_path" ]]; then
                success=0
                message="Compliant HSTS configuration applied successfully. All duplicate/non-compliant headers removed."
                # Clean up temp file on success
                rm -f "$temp_file"
            else
                message="Configuration file appears to be empty or corrupted after write"
                success=1
            fi
        else
            message="Failed to write configured file - check permissions"
        fi
    fi
    
    CONFIGURE_RESULT="$message"
    return $success
}

# Function: Log audit results
log_audit_results() {
    local is_correct="$1"
    local details="$2"
    
    if [[ $is_correct -eq 0 ]]; then
        log_message "SUCCESS: $details"
        log_message "HSTS configuration is compliant."
    else
        log_message "FAILURE: $details"
        log_message "HSTS configuration needs to be updated."
        if [[ $AUDIT_HEADER_COUNT -gt 1 ]]; then
            log_message "ACTION REQUIRED: Remove duplicate HSTS definitions. Only one compliant configuration should exist."
        fi
    fi
}

# Function: Prompt for confirmation
confirm_configure() {
    if [[ "$DRY_RUN" == "true" ]]; then
        return 0
    fi
    
    echo ""
    echo "WARNING: This will modify the configuration file: $CONFIG_PATH"
    echo "All existing HSTS configurations will be removed and replaced with one compliant version."
    echo "A backup will be created before making changes."
    echo ""
    read -p "Do you want to continue? (yes/no): " response
    
    case "$response" in
        yes|y|YES|Y)
            return 0
            ;;
        *)
            log_message "Configuration operation cancelled by user"
            return 1
            ;;
    esac
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
        log_message "Loaded ${#paths[@]} custom path(s) from file: $paths_file"
    if [ ${#paths[@]} -gt 0 ]; then
        printf '%s\n' "${paths[@]}"
    fi
    fi
    
    return 0
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
    if [[ -z "$conf_path" ]] && [[ -n "${CATALINA_BASE}" ]] && [[ -d "${CATALINA_BASE}/conf" ]] && [[ -f "${CATALINA_BASE}/conf/server.xml" ]]; then
        log_message "Found Tomcat configuration at CATALINA_BASE: ${CATALINA_BASE}/conf"
        conf_path="${CATALINA_BASE}/conf"
    fi
    
    # Check CATALINA_HOME
    if [[ -z "$conf_path" ]] && [[ -n "${CATALINA_HOME}" ]] && [[ -d "${CATALINA_HOME}/conf" ]] && [[ -f "${CATALINA_HOME}/conf/server.xml" ]]; then
        log_message "Found Tomcat configuration at CATALINA_HOME: ${CATALINA_HOME}/conf"
        conf_path="${CATALINA_HOME}/conf"
    fi
    
    # Check systemd service files for Tomcat paths
    if [[ -z "$conf_path" ]]; then
        local systemd_services=()
        if [[ -d "/etc/systemd/system" ]]; then
            while IFS= read -r service_file; do
                if [[ -f "$service_file" ]] && grep -qi "tomcat\|catalina" "$service_file"; then
                    local service_path=$(grep -i "ExecStart\|WorkingDirectory" "$service_file" | head -1 | sed 's/.*=//' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sed 's/\/bin\/.*//' | sed 's/\/catalina.*//')
                    if [[ -n "$service_path" ]] && [[ -d "$service_path/conf" ]] && [[ -f "$service_path/conf/server.xml" ]]; then
                        log_message "Found Tomcat configuration via systemd service: $service_path/conf"
                        conf_path="$service_path/conf"
                        break
                    fi
                fi
            done < <(find /etc/systemd/system -name "*.service" -type f 2>/dev/null | head -20)
        fi
    fi
    
    # Check init.d scripts for Tomcat paths
    if [[ -z "$conf_path" ]] && [[ -d "/etc/init.d" ]]; then
        while IFS= read -r init_script; do
            if [[ -f "$init_script" ]] && grep -qi "tomcat\|catalina" "$init_script"; then
                local script_path=$(grep -i "CATALINA_HOME\|CATALINA_BASE\|TOMCAT_HOME" "$init_script" | head -1 | sed 's/.*=//' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sed 's/"//g' | sed "s/'//g")
                if [[ -n "$script_path" ]] && [[ -d "$script_path/conf" ]] && [[ -f "$script_path/conf/server.xml" ]]; then
                    log_message "Found Tomcat configuration via init.d script: $script_path/conf"
                    conf_path="$script_path/conf"
                    break
                fi
            fi
        done < <(find /etc/init.d -name "*tomcat*" -type f 2>/dev/null | head -10)
    fi
    
    # Check running Tomcat processes for paths
    if [[ -z "$conf_path" ]]; then
        local tomcat_process=$(ps aux 2>/dev/null | grep -i "[t]omcat\|[c]atalina" | head -1)
        if [[ -n "$tomcat_process" ]]; then
            local proc_path=$(echo "$tomcat_process" | awk '{for(i=1;i<=NF;i++) if($i ~ /-Dcatalina\.home=|catalina\.base=/) {print $i; exit}}' | sed 's/.*=//')
            if [[ -n "$proc_path" ]] && [[ -d "$proc_path/conf" ]] && [[ -f "$proc_path/conf/server.xml" ]]; then
                log_message "Found Tomcat configuration via running process: $proc_path/conf"
                conf_path="$proc_path/conf"
            fi
        fi
    fi
    
    # Search common Linux/Unix server paths (not macOS)
    if [[ -z "$conf_path" ]]; then
        log_message "Searching common Tomcat configuration paths..."
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
            "/usr/share/tomcat/conf" \
            "/usr/share/tomcat7/conf" \
            "/usr/share/tomcat8/conf" \
            "/usr/share/tomcat9/conf" \
            "/usr/share/tomcat10/conf" \
            "/etc/tomcat/conf" \
            "/etc/tomcat7/conf" \
            "/etc/tomcat8/conf" \
            "/etc/tomcat9/conf" \
            "/etc/tomcat10/conf"; do
            if [[ -d "${path}" ]] && [[ -f "${path}/server.xml" ]]; then
                log_message "Found Tomcat configuration at: ${path}"
                conf_path="${path}"
                break
            fi
        done
    fi
    
    # Fallback to find command (Linux/Unix servers only)
    if [[ -z "$conf_path" ]]; then
        log_message "No Tomcat configuration found in common paths, attempting to locate server.xml..."
        local found_path
        found_path=$(find /opt /usr/local /var/lib /usr/share /etc -type f -name "server.xml" -path "*/conf/server.xml" 2>/dev/null | head -n 1)
        if [[ -n "$found_path" ]]; then
            conf_path=$(dirname "$found_path")
            if [[ -f "$conf_path/server.xml" ]]; then
                log_message "Found Tomcat configuration via find: ${conf_path}"
            else
                log_error "Found server.xml but path is invalid: ${conf_path}"
                conf_path=""
            fi
        fi
    fi
    
    # If auto-detection found a path, add it to conf_paths array (if not already present)
    if [[ -n "$conf_path" ]]; then
        # Validate the path
        if [[ -d "$conf_path" ]] && [[ -f "$conf_path/server.xml" ]]; then
            # Check if this path is already in conf_paths (avoid duplicates)
            local already_exists=0
            for existing_path in "${conf_paths[@]}"; do
                if [[ "$existing_path" == "$conf_path" ]]; then
                    already_exists=1
                    break
                fi
            done
            
            if [[ $already_exists -eq 0 ]]; then
                conf_paths+=("$conf_path")
            fi
        else
            log_error "Invalid configuration directory: $conf_path"
            log_error "  - Missing server.xml"
            conf_path=""
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
    
    log_message ""
    log_message "========================================="
    log_message "Processing: $web_xml_path"
    log_message "========================================="
    
    # Load configuration
    local config_content
    if ! config_content=$(load_config "$web_xml_path"); then
        log_error "Failed to load configuration file: $web_xml_path"
        return 1
    fi
    
    if [[ "$MODE" == "audit" ]]; then
        # Audit mode
        local audit_result=""
        if ! audit_hsts_headers "$config_content"; then
            local is_correct=1
        else
            local is_correct=0
        fi
        
        log_audit_results "$is_correct" "$AUDIT_RESULT"
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
            --dry-run|--dry_run)
                DRY_RUN=true
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
    
    # Validate mode
    if [[ "$MODE" != "audit" ]] && [[ "$MODE" != "configure" ]]; then
        log_error "Invalid mode: $MODE. Must be 'audit' or 'configure'"
        usage
    fi
    
    # Initialize log file
    if [[ -n "$LOG_FILE" ]]; then
        touch "$LOG_FILE" 2>/dev/null || {
            log_error "Cannot create log file: $LOG_FILE"
            exit 2
        }
    fi
    
    # Log start
    log_message "========================================="
    log_message "Tomcat HSTS Configuration Tool"
    log_message "Hostname: $HOSTNAME"
    log_message "Execution Time: $TIMESTAMP"
    log_message "Mode: $MODE"
    log_message "========================================="
    
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
        log_message "Tomcat Configuration Directory: $conf_path"
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
    
    for web_xml in "${web_xml_files[@]}"; do
        if process_web_xml "$web_xml"; then
            success_count=$((success_count + 1))
        else
            failure_count=$((failure_count + 1))
            overall_success=1
        fi
        processed_count=$((processed_count + 1))
    done
    
    # Summary
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
    
    exit $overall_success
}

# Execute main function with all arguments
main "$@"

