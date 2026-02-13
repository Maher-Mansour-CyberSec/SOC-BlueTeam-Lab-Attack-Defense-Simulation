# Production Readiness

## Overview

This document defines the production readiness criteria for the Attack Simulation and SOC Validation program. It establishes measurable standards for alert accuracy, telemetry stability, operational repeatability, and supportability required for enterprise deployment.

---

## Production Readiness Criteria

### 1. Alert Accuracy Metrics

#### True Positive Rate (TPR)

| Metric | Definition | Target | Measurement |
|--------|------------|--------|-------------|
| **TPR** | True Positives / (True Positives + False Negatives) | ≥95% | Weekly analysis |
| **Precision** | True Positives / (True Positives + False Positives) | ≥90% | Weekly analysis |
| **F1 Score** | 2 * (Precision * TPR) / (Precision + TPR) | ≥92% | Weekly analysis |

#### Alert Quality Standards

| Quality Dimension | Requirement | Validation Method |
|-------------------|-------------|-------------------|
| **Completeness** | All required fields populated | Automated field validation |
| **Timeliness** | Alert generated within 5 minutes of event | Timestamp comparison |
| **Context Richness** | Process tree, parent/child, command line included | Alert content review |
| **Actionability** | Clear next steps or runbook reference | Analyst feedback |
| **Accuracy** | Correct severity assignment | Incident review |

#### Alert Tuning Requirements

```yaml
Alert_Tuning_Thresholds:
  False_Positive_Rate:
    target: "<5%"
    action_at_threshold: "Review and tune within 48 hours"
    
  Alert_Volume:
    baseline_deviation: "<20%"
    action_at_spike: "Investigate root cause within 4 hours"
    
  Severity_Accuracy:
    critical_validation: "100% confirmed incidents"
    high_validation: ">80% confirmed incidents"
    medium_validation: ">50% confirmed incidents"
```

### 2. Telemetry Stability

#### Log Source Health

| Source | Expected EPS | Max Latency | Availability Target |
|--------|--------------|-------------|---------------------|
| Sysmon (DC) | 50-100 | 60s | 99.9% |
| Sysmon (Endpoint) | 20-50 | 60s | 99.5% |
| Windows Security | 30-80 | 30s | 99.9% |
| PowerShell | 5-15 | 60s | 99.5% |
| Suricata | 100-500 | 10s | 99.9% |

#### Log Source Monitoring

```python
# log_source_monitor.py
import requests
from elasticsearch import Elasticsearch
import smtplib
from datetime import datetime, timedelta

class LogSourceMonitor:
    def __init__(self, es_host, alert_email):
        self.es = Elasticsearch([es_host])
        self.alert_email = alert_email
        
    def check_source_health(self, source_name, index_pattern, min_events=100):
        """Check if log source is sending events"""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": "now-5m"}}},
                        {"term": {"agent.name": source_name}}
                    ]
                }
            },
            "aggs": {
                "event_count": {"value_count": {"field": "@timestamp"}}
            }
        }
        
        response = self.es.search(index=index_pattern, body=query)
        event_count = response['aggregations']['event_count']['value']
        
        if event_count < min_events:
            self.send_alert(
                f"Log Source Alert: {source_name}",
                f"Event count ({event_count}) below threshold ({min_events}) in last 5 minutes"
            )
            return False
        
        return True
    
    def check_latency(self, source_name, max_latency_seconds=60):
        """Check event ingestion latency"""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": "now-5m"}}},
                        {"term": {"agent.name": source_name}}
                    ]
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
            "size": 1
        }
        
        response = self.es.search(index="winlogbeat-*", body=query)
        
        if response['hits']['hits']:
            last_event_time = datetime.fromisoformat(
                response['hits']['hits'][0]['_source']['@timestamp'].replace('Z', '+00:00')
            )
            latency = (datetime.utcnow() - last_event_time.replace(tzinfo=None)).total_seconds()
            
            if latency > max_latency_seconds:
                self.send_alert(
                    f"Latency Alert: {source_name}",
                    f"Ingestion latency ({latency}s) exceeds threshold ({max_latency_seconds}s)"
                )
                return False
        
        return True
    
    def send_alert(self, subject, body):
        """Send alert notification"""
        # Implementation for email/SMS/Slack notification
        pass

# Scheduled execution
monitor = LogSourceMonitor("10.0.0.100:9200", "soc@company.com")
monitor.check_source_health("windows-dc", "winlogbeat-*")
monitor.check_source_health("windows-endpoint", "winlogbeat-*")
monitor.check_latency("windows-dc")
```

#### Field Population Requirements

| Event Type | Required Fields | Population Target |
|------------|-----------------|-------------------|
| Process Create | Image, CommandLine, ParentImage, User, ProcessGuid | 100% |
| Network Connect | SourceIP, DestinationIP, DestinationPort, Image | 100% |
| Process Access | SourceImage, TargetImage, GrantedAccess, CallTrace | 100% |
| File Create | TargetFilename, Image, CreationUtcTime | 100% |
| Registry Set | EventType, TargetObject, Details | 100% |
| DNS Query | QueryName, QueryStatus, Image | 100% |

### 3. Operational Repeatability

#### Scenario Execution Standards

| Requirement | Standard | Verification |
|-------------|----------|------------|
| **Documentation** | All scenarios documented with exact commands | Quarterly review |
| **Version Control** | Scenarios versioned in Git | Automated check |
| **Pre-execution Checklist** | Mandatory checklist completion | Signed confirmation |
| **Execution Logging** | All actions timestamped and logged | Log review |
| **Result Capture** | Telemetry and alerts automatically collected | Automated collection |
| **Post-execution Cleanup** | Systems restored to baseline | Verification script |

#### Automated Testing Framework

```yaml
# automated_test_pipeline.yml
name: Attack Simulation Test Pipeline

on:
  schedule:
    - cron: '0 2 * * 1'  # Weekly on Monday at 2 AM
  workflow_dispatch:

jobs:
  pre_check:
    runs-on: ubuntu-latest
    steps:
      - name: Verify Lab Environment
        run: |
          python3 scripts/verify_environment.py
      
      - name: Check Log Source Health
        run: |
          python3 scripts/check_telemetry.py --all-sources
      
      - name: Capture Baseline
        run: |
          python3 scripts/capture_baseline.py --duration 300

  execute_scenarios:
    needs: pre_check
    runs-on: kali-linux
    strategy:
      matrix:
        scenario: [AS-001, AS-002, AS-003, AS-004]
    steps:
      - name: Execute Scenario
        run: |
          python3 scripts/execute_scenario.py --scenario ${{ matrix.scenario }}
      
      - name: Collect Telemetry
        run: |
          python3 scripts/collect_telemetry.py --scenario ${{ matrix.scenario }}
      
      - name: Verify Detections
        run: |
          python3 scripts/verify_detections.py --scenario ${{ matrix.scenario }}

  generate_report:
    needs: execute_scenarios
    runs-on: ubuntu-latest
    steps:
      - name: Aggregate Results
        run: |
          python3 scripts/aggregate_results.py
      
      - name: Generate Coverage Map
        run: |
          python3 scripts/generate_coverage.py --format navigator
      
      - name: Publish Report
        run: |
          python3 scripts/publish_report.py --destination confluence
```

#### Test Result Retention

| Data Type | Retention Period | Storage Location |
|-----------|------------------|------------------|
| Execution logs | 2 years | SIEM + Archive |
| Raw telemetry | 1 year | Cold storage |
| Test reports | 3 years | Document repository |
| Coverage maps | Indefinite | Version control |
| Detection gaps | Until resolved | Issue tracker |

### 4. Operational Support

#### Support Model

| Level | Responsibility | Response Time | Escalation Path |
|-------|----------------|---------------|-----------------|
| **L1** | Alert triage, basic investigation | 15 minutes | L2 |
| **L2** | Deep investigation, containment | 30 minutes | L3 |
| **L3** | Forensics, malware analysis | 4 hours | Management |
| **Detection Engineering** | Rule tuning, gap remediation | 24 hours | N/A |
| **Red Team** | Scenario execution, attack simulation | 48 hours | N/A |

#### On-Call Requirements

| Requirement | Specification |
|-------------|---------------|
| Coverage | 24x7x365 |
| Response SLA | 15 minutes for Critical, 1 hour for High |
| Escalation | Automatic after SLA breach |
| Handoff | Documented shift turnover |
| Training | Quarterly tabletop exercises |

#### Documentation Standards

| Document Type | Update Frequency | Owner | Review Process |
|---------------|------------------|-------|----------------|
| Runbooks | Quarterly | SOC Manager | Peer review |
| Playbooks | After each major incident | L2 Lead | Lessons learned |
| Detection rules | With each change | Detection Engineering | Code review |
| Architecture diagrams | With infrastructure changes | Platform Engineering | Technical review |
| Training materials | Quarterly | Training Lead | Content review |

### 5. Performance Metrics

#### Key Performance Indicators

| KPI | Target | Measurement Frequency | Owner |
|-----|--------|----------------------|-------|
| **Mean Time to Detect (MTTD)** | <5 minutes | Daily | Detection Engineering |
| **Mean Time to Investigate (MTTI)** | <30 minutes | Weekly | SOC Manager |
| **Mean Time to Contain (MTTC)** | <15 minutes | Weekly | SOC Manager |
| **Mean Time to Respond (MTTR)** | <1 hour | Weekly | SOC Manager |
| **Alert True Positive Rate** | >95% | Weekly | Detection Engineering |
| **Detection Coverage (Critical)** | >95% | Monthly | Detection Engineering |
| **Scenario Execution Success** | 100% | Per execution | Red Team |
| **Telemetry Availability** | >99.5% | Daily | Platform Engineering |

#### Performance Dashboard

```json
{
  "dashboard": {
    "title": "SOC Validation Program Metrics",
    "panels": [
      {
        "title": "Detection Coverage",
        "type": "gauge",
        "query": "mitre_coverage_percent",
        "thresholds": [80, 90, 95]
      },
      {
        "title": "MTTD Trend",
        "type": "graph",
        "query": "avg(mttd) by day",
        "target": 300
      },
      {
        "title": "Alert Quality",
        "type": "pie",
        "query": "count(alerts) by disposition",
        "labels": ["True Positive", "False Positive", "Benign"]
      },
      {
        "title": "Log Source Health",
        "type": "table",
        "query": "log_source_availability",
        "columns": ["Source", "Availability", "EPS", "Latency"]
      }
    ]
  }
}
```

### 6. Change Management

#### Detection Rule Changes

| Change Type | Approval Required | Testing Required | Rollback Plan |
|-------------|-------------------|------------------|---------------|
| New rule | Detection Lead | Yes - 48 hours | Automatic |
| Rule modification | Peer review | Yes - 24 hours | Manual |
| Rule deletion | Detection Lead + SOC Manager | N/A | Restore from backup |
| Threshold change | Peer review | Yes - 24 hours | Automatic |

#### Change Request Template

```yaml
change_request:
  id: CR-YYYY-###
  title: "[Brief description]"
  type: [new_rule|modification|deletion|threshold_change]
  
  detection:
    name: "[Detection Name]"
    technique: "T####.###"
    data_source: "[Sysmon/Windows/Suricata]"
    
  rationale:
    gap_description: "[What gap does this address]"
    threat_context: "[Threat intelligence driving this]"
    
  testing:
    test_scenario: "[AS-###]"
    expected_result: "[What alert should fire]"
    test_duration: "[Hours]"
    
  rollback:
    method: "[Automatic/Manual]"
    trigger: "[False positive rate > X%]"
    
  approvals:
    detection_engineer: "[Name]"
    soc_manager: "[Name]"
    submitted_date: "[YYYY-MM-DD]"
```

### 7. Disaster Recovery

#### Backup Requirements

| Component | Backup Frequency | Retention | Storage |
|-----------|------------------|-----------|---------|
| SIEM configuration | Daily | 30 days | Offsite |
| Detection rules | On change | 90 days | Git + Offsite |
| Sysmon configuration | On change | 90 days | Git + Offsite |
| Log data | Continuous | 1 year | Hot + Cold |
| Test results | After each test | 2 years | Archive |

#### Recovery Procedures

```bash
#!/bin/bash
# siem_recovery.sh

# Restore Elasticsearch indices
elasticdump \
  --input=s3://backup-bucket/elasticsearch/detections.json \
  --output=http://10.0.0.100:9200/detections \
  --type=data

# Restore Kibana dashboards
elasticdump \
  --input=s3://backup-bucket/elasticsearch/kibana.json \
  --output=http://10.0.0.100:9200/.kibana \
  --type=data

# Restore detection rules from Git
cd /opt/detection-rules
git checkout [last-known-good-commit]
python3 deploy_rules.py --environment production
```

### 8. Compliance and Audit

#### Audit Trail Requirements

| Action | Logged Data | Retention |
|--------|-------------|-----------|
| Alert acknowledged | Analyst, timestamp, alert ID | 2 years |
| Investigation started | Analyst, case ID, timestamp | 2 years |
| Containment action | Action, target, analyst, result | 3 years |
| Detection rule change | Change details, approver, timestamp | 3 years |
| Scenario execution | Operator, scenario, timestamp, results | 2 years |

#### Compliance Mapping

| Framework | Control | Implementation |
|-----------|---------|----------------|
| **NIST 800-53** | SI-4 (Information System Monitoring) | Continuous monitoring with Suricata, Sysmon |
| **NIST 800-53** | IR-4 (Incident Handling) | Documented runbooks and playbooks |
| **ISO 27001** | A.12.4 (Logging and Monitoring) | Centralized logging to SIEM |
| **PCI DSS** | 10.1-10.7 (Logging) | Comprehensive audit logging |
| **SOC 2** | CC7.2 (System Monitoring) | Alert coverage and response metrics |

---

*Production readiness is validated quarterly through formal assessment. Any deficiencies must be remediated within 30 days.*
