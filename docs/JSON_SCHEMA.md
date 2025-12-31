# HSTS Compliance Tools - JSON Report Schema

This document describes the JSON schema for the enterprise reporting features in the HSTS Compliance Tools.

## schema.json

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "HSTS Compliance Report",
  "description": "Output format for HSTS audit and configuration results",
  "type": "object",
  "properties": {
    "timestamp": {
      "type": "string",
      "format": "date-time",
      "description": "ISO 8601 timestamp of when the operation was performed"
    },
    "hostname": {
      "type": "string",
      "description": "Name of the server where the script ran"
    },
    "platform": {
      "type": "string",
      "enum": ["Windows", "Unix/Linux"],
      "description": "Operating system platform"
    },
    "script": {
      "type": "string",
      "description": "Name of the script that generated the report"
    },
    "mode": {
      "type": "string",
      "enum": ["audit", "configure"],
      "description": "Operation mode"
    },
    "summary": {
      "type": "object",
      "properties": {
        "total_files": { "type": "integer" },
        "compliant_files": { "type": "integer" },
        "non_compliant_files": { "type": "integer" },
        "status": {
          "type": "string",
          "enum": ["COMPLIANT", "NON_COMPLIANT", "PARTIAL"]
        }
      }
    },
    "results": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "file_path": { "type": "string" },
          "server_type": { "type": "string", "enum": ["Tomcat", "IIS"] },
          "status": { "type": "string", "enum": ["COMPLIANT", "NON_COMPLIANT", "MISSING"] },
          "details": { "type": "string" },
          "headers_found": {
            "type": "array",
            "items": {
              "type": "object",
              "properties": {
                "max_age": { "type": "string" },
                "include_subdomains": { "type": "boolean" },
                "preload": { "type": "boolean" },
                "raw_value": { "type": "string" }
              }
            }
          }
        }
      }
    }
  }
}
```

## Example Output

```json
{
  "timestamp": "2025-01-15T14:30:00Z",
  "hostname": "webserver01",
  "platform": "Unix/Linux",
  "script": "UpdateTomcatHstsUnix.sh",
  "mode": "audit",
  "summary": {
    "total_files": 2,
    "compliant_files": 1,
    "non_compliant_files": 1,
    "status": "PARTIAL"
  },
  "results": [
    {
      "file_path": "/opt/tomcat1/conf/web.xml",
      "server_type": "Tomcat",
      "status": "COMPLIANT",
      "details": "Correctly configured",
      "headers_found": [
        {
          "max_age": "31536000",
          "include_subdomains": true,
          "preload": false,
          "raw_value": "max-age=31536000; includeSubDomains"
        }
      ]
    },
    {
      "file_path": "/opt/tomcat2/conf/web.xml",
      "server_type": "Tomcat",
      "status": "NON_COMPLIANT",
      "details": "Max-age too low",
      "headers_found": [
        {
          "max_age": "3600",
          "include_subdomains": true,
          "preload": false,
          "raw_value": "max-age=3600; includeSubDomains"
        }
      ]
    }
  ]
}
```

## Integration Guide

### SIEM Integration via Splunk

1. Configure Splunk Universal Forwarder to monitor report directories.
2. In `inputs.conf`:
   ```ini
   [monitor:///var/log/hsts-compliance/*.json]
   sourcetype = hsts:compliance:json
   index = security
   ```

### ELK Stack Integration

1. Use Filebeat to ship logs to Logstash/Elasticsearch.
2. Filebeat configuration:
   ```yaml
   filebeat.inputs:
   - type: log
     paths:
       - /var/log/hsts-compliance/*.json
     json.keys_under_root: true
     json.add_error_key: true
   ```
