# API & SIEM Integration Guide

This guide details how to integrate the HSTS Compliance Tools with third-party systems, Security Information and Event Management (SIEM) platforms, and monitoring dashboards.

## JSON Output Structure

All scripts assume a structured JSON output when the `--json` or `-OutputFormat json` flag is used.
See [JSON_SCHEMA.md](JSON_SCHEMA.md) for the formal schema.

## SIEM Integration Scenarios

### 1. Splunk Integration

**Method:** File Monitoring
The easiest way to ingest compliance data is via the Splunk Universal Forwarder monitoring the log/report directory.

**Configuration:**
On the target server, configure `inputs.conf`:

```ini
[monitor:///var/log/hsts-compliance/reports/*.json]
index = compliance
sourcetype = hsts:compliance:json
crcSalt = <SOURCE>
```

**Search Example:**
```splunk
index=compliance status=NON_COMPLIANT | stats count by hostname
```

### 2. ELK Stack (Elasticsearch, Logstash, Kibana)

**Method:** Filebeat
Deploy Filebeat to ship JSON reports to Logstash or directly to Elasticsearch.

**Filebeat Config:**
```yaml
filebeat.inputs:
- type: filestream
  id: hsts-reports
  paths:
    - /var/log/hsts-compliance/reports/*.json
  parsers:
    - ndjson:
        target: ""
        overwrite_keys: true
```

### 3. Webhook Integration (Custom)

To satisfy the requirement for "Webhook" integration, you can use a wrapper script to post results to a Slack/Discord/Teams webhook.

**Wrapper Example (Bash):**

```bash
#!/bin/bash
# Wrapper to run audit and post to Slack
WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

# Run Audit
./UpdateTomcatHstsUnix.sh --mode audit --json > result.json

# Parse Status (requires jq)
STATUS=$(jq -r '.summary.status' result.json)

if [ "$STATUS" != "COMPLIANT" ]; then
    curl -X POST -H 'Content-type: application/json' --data "{
        \"text\": \"⚠️ HSTS Compliance Alert: Server $(hostname) is $STATUS\"
    }" "$WEBHOOK_URL"
fi
```

## Enterprise Automation

### Ansible Integration

You can easily wrap these scripts in an Ansible Playbook.

```yaml
- name: Audit HSTS Compliance
  hosts: webservers
  tasks:
    - name: Run HSTS Audit Script
      script: src/unix/UpdateTomcatHstsUnix.sh --mode audit --json
      register: hsts_result
      failed_when: false
      changed_when: false

    - name: Parse Result
      set_fact:
        compliance_status: "{{ (hsts_result.stdout | from_json).summary.status }}"

    - name: Alert if Non-Compliant
      debug:
        msg: "Server is Non-Compliant!"
      when: compliance_status != "COMPLIANT"
```

## Dashboarding

The common JSON format allows you to build a unified dashboard showing:
- **Compliance % across fleet**
- **Top non-compliant servers**
- **Trend of compliance over time**
