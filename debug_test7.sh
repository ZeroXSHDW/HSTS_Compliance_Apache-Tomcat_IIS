#!/bin/bash
set -e

PROJECT_ROOT="/Users/admin/Documents/HSTS_Compliance_Apache-Tomcat_IIS"
TEST_TEMP_DIR=$(mktemp -d)
TEST_CONF_DIR="$TEST_TEMP_DIR/conf"
mkdir -p "$TEST_CONF_DIR"

cat > "$TEST_CONF_DIR/web.xml" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee" version="4.0">
    <display-name>Test</display-name>
</web-app>
EOF

touch "$TEST_CONF_DIR/server.xml"

echo "--- RUNNING AUDIT ---"
# Run with bash -x to see execution trace
bash -x "$PROJECT_ROOT/src/unix/UpdateTomcatHstsUnix.sh" --mode audit --custom-conf="$TEST_CONF_DIR"
EXIT_CODE=$?
echo "--- AUDIT FINISHED ---"
echo "Exit Code: $EXIT_CODE"

rm -rf "$TEST_TEMP_DIR"
