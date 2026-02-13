# SOC Investigation Workflow

## Overview

This document defines standardized investigation workflows for SOC L1 and L2 analysts responding to alerts generated from attack simulation activities. The workflows ensure consistent, thorough, and efficient incident handling.

---

## Alert Severity Classification

| Severity | Criteria | Response Time | Analyst Level |
|----------|----------|---------------|---------------|
| **Critical** | Confirmed compromise, lateral movement, credential theft | 15 minutes | L2 + L1 |
| **High** | Suspicious behavior with high confidence, known bad TTPs | 30 minutes | L2 |
| **Medium** | Anomalous activity requiring investigation | 2 hours | L1 |
| **Low** | Informational, baseline deviation | 4 hours | L1 |

---

## L1 Analyst Workflow

### Alert Triage Process

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    L1 ALERT TRIAGE WORKFLOW                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────┐                                                        │
│  │ Alert Received│                                                       │
│  │   in SIEM    │                                                       │
│  └──────┬───────┘                                                        │
│         │                                                                │
│         ▼                                                                │
│  ┌──────────────┐     ┌─────────────────────────────────────────────┐   │
│  │  Initial     │────▶│ 1. Review alert title and description      │   │
│  │  Assessment  │     │ 2. Check alert severity and source system  │   │
│  └──────┬───────┘     │ 3. Note timestamp and affected assets      │   │
│         │             └─────────────────────────────────────────────┘   │
│         ▼                                                                │
│  ┌──────────────┐     ┌─────────────────────────────────────────────┐   │
│  │  Enrichment  │────▶│ 1. Query SIEM for related events (±30 min) │   │
│  │              │     │ 2. Check asset inventory for host details  │   │
│  └──────┬───────┘     │ 3. Review user context and privileges      │   │
│         │             │ 4. Check threat intel for IOCs             │   │
│         │             └─────────────────────────────────────────────┘   │
│         ▼                                                                │
│  ┌──────────────┐                                                        │
│  │  Determine   │                                                        │
│  │   Verdict    │                                                        │
│  └──────┬───────┘                                                        │
│         │                                                                │
│    ┌────┼────┬────────┬─────────┐                                        │
│    ▼    ▼    ▼        ▼         ▼                                        │
│ ┌────┐┌────┐┌────┐ ┌──────┐ ┌──────┐                                   │
│ │True││True││False│ │Benign│ │Escalate│                                  │
│ │Pos ││Pos ││Pos  │ │      │ │ to L2  │                                  │
│ │Low ││High││     │ │      │ │        │                                  │
│ └─┬──┘└─┬──┘└──┬──┘ └──┬───┘ └──┬───┘                                   │
│   │     │      │       │        │                                        │
│   ▼     ▼      ▼       ▼        ▼                                        │
│ Close  L2   Close  Close   Create L2                                     │
│ Ticket Escalate Ticket Ticket  Case                                      │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Step-by-Step Triage Procedure

#### Step 1: Alert Receipt (0-5 minutes)

**Actions:**
1. Acknowledge alert in SIEM within 5 minutes
2. Create incident ticket with alert ID
3. Document initial alert details:
   - Alert name and description
   - Source IP/Host
   - Destination IP/Host
   - Timestamp (UTC)
   - User account (if applicable)
   - MITRE ATT&CK technique (if mapped)

**Documentation Template:**
```
INCIDENT ID: INC-YYYY-MM-DD-###
ALERT ID: [SIEM Alert ID]
ALERT NAME: [Alert Name]
SEVERITY: [Critical/High/Medium/Low]
SOURCE HOST: [Hostname/IP]
USER: [Username]
TIME DETECTED: [Timestamp]
MITRE TECHNIQUE: [T####.###]

INITIAL OBSERVATIONS:
- [Observation 1]
- [Observation 2]
```

#### Step 2: Initial Enrichment (5-15 minutes)

**SIEM Queries:**

```splunk
# Splunk - Related events in time window
index=windows OR index=sysmon earliest=-30m latest=+30m 
| where host="[TARGET_HOST]" OR src_ip="[SOURCE_IP]" OR user="[USERNAME]"
| stats count by sourcetype, eventcode, host
| sort -count
```

```kibana
# Kibana/Elasticsearch - Event timeline
GET /winlogbeat-*/_search
{
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-30m", "lte": "now+30m"}}},
        {"bool": {"should": [
          {"match": {"host.name": "[TARGET_HOST]"}},
          {"match": {"source.ip": "[SOURCE_IP]"}},
          {"match": {"user.name": "[USERNAME]"}}
        ]}}
      ]
    }
  },
  "aggs": {
    "events_over_time": {
      "date_histogram": {"field": "@timestamp", "fixed_interval": "1m"}
    }
  }
}
```

**Asset Lookup:**
- Query CMDB for host details
- Identify asset owner
- Determine asset criticality
- Check patch level and EDR status

**User Context:**
- Query Active Directory for user details
- Check user role and privileges
- Review recent login history
- Verify if user is on vacation/leave

#### Step 3: Threat Intelligence Check

**IOC Verification:**

```python
# Automated IOC enrichment script
import requests
import hashlib

class IOCEnricher:
    def __init__(self, misp_url, misp_key):
        self.misp_url = misp_url
        self.headers = {
            "Authorization": misp_key,
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
    
    def check_ip(self, ip_address):
        """Check IP against MISP threat intel"""
        url = f"{self.misp_url}/attributes/restSearch/json"
        data = {
            "returnFormat": "json",
            "type": "ip-dst",
            "value": ip_address
        }
        response = requests.post(url, headers=self.headers, json=data, verify=False)
        return response.json()
    
    def check_hash(self, file_hash):
        """Check file hash against MISP"""
        url = f"{self.misp_url}/attributes/restSearch/json"
        data = {
            "returnFormat": "json",
            "type": ["md5", "sha1", "sha256"],
            "value": file_hash
        }
        response = requests.post(url, headers=self.headers, json=data, verify=False)
        return response.json()
    
    def check_domain(self, domain):
        """Check domain against MISP"""
        url = f"{self.misp_url}/attributes/restSearch/json"
        data = {
            "returnFormat": "json",
            "type": "domain",
            "value": domain
        }
        response = requests.post(url, headers=self.headers, json=data, verify=False)
        return response.json()

# Usage
enricher = IOCEnricher("https://10.0.0.100", "MISP_API_KEY")
result = enricher.check_ip("[SUSPICIOUS_IP]")
```

#### Step 4: Verdict Determination

| Verdict | Criteria | Action |
|---------|----------|--------|
| **True Positive (High)** | Confirmed malicious activity | Escalate to L2 immediately |
| **True Positive (Low)** | Suspicious but not critical | Document and close with notes |
| **False Positive** | Known good activity, misconfiguration | Document root cause, close |
| **Benign** | Normal business activity | Close with justification |
| **Escalate** | Insufficient information or complexity | Transfer to L2 with context |

---

## L2 Analyst Workflow

### Deep Investigation Process

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    L2 DEEP INVESTIGATION WORKFLOW                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────┐                                                        │
│  │ Case Received│◀── From L1 Escalation or Critical Alert              │
│  │   from L1    │                                                        │
│  └──────┬───────┘                                                        │
│         │                                                                │
│         ▼                                                                │
│  ┌──────────────┐     ┌─────────────────────────────────────────────┐   │
│  │   Timeline   │────▶│ Build complete event timeline:              │   │
│  │ Construction │     │ - All related events (±2 hours)             │   │
│  └──────┬───────┘     │ - Process execution chain                     │   │
│         │             │ - Network connections                         │   │
│         │             │ - File system activity                        │   │
│         │             │ - Registry modifications                      │   │
│         │             └─────────────────────────────────────────────┘   │
│         ▼                                                                │
│  ┌──────────────┐     ┌─────────────────────────────────────────────┐   │
│  │   Process    │────▶│ Analyze process tree:                       │   │
│  │ Tree Analysis│     │ - Parent/child relationships                │   │
│  └──────┬───────┘     │ - Command line arguments                    │   │
│         │             │ - Process injection events                  │   │
│         │             │ - Memory access patterns                    │   │
│         │             └─────────────────────────────────────────────┘   │
│         ▼                                                                │
│  ┌──────────────┐     ┌─────────────────────────────────────────────┐   │
│  │  Scope       │────▶│ Determine blast radius:                     │   │
│  │ Assessment   │     │ - Affected systems                          │   │
│  └──────┬───────┘     │ - Compromised accounts                        │   │
│         │             │ - Data access/exfiltration                    │   │
│         │             │ - Lateral movement paths                      │   │
│         │             └─────────────────────────────────────────────┘   │
│         ▼                                                                │
│  ┌──────────────┐                                                        │
│  │  Containment │────▶│ Execute containment actions                   │   │
│  │  Decision    │                                                        │
│  └──────┬───────┘                                                        │
│         │                                                                │
│         ▼                                                                │
│  ┌──────────────┐                                                        │
│  │   Forensic   │────▶│ Collect evidence for potential investigation  │   │
│  │  Collection  │                                                        │
│  └──────┬───────┘                                                        │
│         │                                                                │
│         ▼                                                                │
│  ┌──────────────┐                                                        │
│  │   Incident   │────▶│ Create incident report with findings          │   │
│  │   Reporting  │                                                        │
│  └──────────────┘                                                        │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Timeline Construction

**Event Correlation Query:**

```splunk
# Splunk - Complete timeline construction
index=windows OR index=sysmon OR index=suricata 
    earliest=-2h latest=+30m 
    (host="[TARGET_HOST]" OR src_ip="[SOURCE_IP]" OR dest_ip="[SOURCE_IP]" OR user="[USERNAME]")
| eval event_time=strftime(_time, "%Y-%m-%d %H:%M:%S")
| eval event_type=case(
    sourcetype=="WinEventLog:Security", "Windows Security",
    sourcetype=="xmlwineventlog", "Sysmon",
    sourcetype=="suricata", "IDS Alert",
    1==1, "Other"
)
| eval description=case(
    EventCode=="4624", "Successful Logon: ".user,
    EventCode=="4625", "Failed Logon: ".AccountName,
    EventCode=="4688", "Process Created: ".NewProcessName,
    EventCode=="1", "Sysmon Process: ".Image,
    EventCode=="3", "Network Connection: ".SourceIp." -> ".DestinationIp,
    EventCode=="10", "Process Access: ".SourceImage." accessing ".TargetImage,
    1==1, "Event ".EventCode
)
| table event_time, event_type, host, description, EventCode, _raw
| sort event_time
```

### Process Tree Analysis

```powershell
# PowerShell - Extract process tree from Sysmon logs
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1,10} -MaxEvents 1000 | 
    Where-Object {$_.TimeCreated -gt (Get-Date).AddHours(-2)} |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        [PSCustomObject]@{
            Time = $_.TimeCreated
            EventId = $_.Id
            ProcessGuid = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessGuid'} | Select-Object -ExpandProperty '#text'
            Image = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'} | Select-Object -ExpandProperty '#text'
            CommandLine = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'CommandLine'} | Select-Object -ExpandProperty '#text'
            ParentImage = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ParentImage'} | Select-Object -ExpandProperty '#text'
            ParentProcessGuid = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ParentProcessGuid'} | Select-Object -ExpandProperty '#text'
            User = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'User'} | Select-Object -ExpandProperty '#text'
        }
    } | Export-Csv -Path "C:\Investigation\process_tree.csv" -NoTypeInformation
```

### Scope Assessment Matrix

| Assessment Area | Investigation Questions | Data Sources |
|-----------------|------------------------|--------------|
| **Affected Systems** | Which hosts show similar activity? | SIEM, EDR, Network logs |
| **Compromised Accounts** | Which accounts were used maliciously? | Windows Security logs, VPN logs |
| **Data Access** | What sensitive data was accessed? | File server logs, DLP logs |
| **Data Exfiltration** | Was data transferred externally? | Proxy logs, DLP, Network flow |
| **Persistence** | What persistence mechanisms exist? | Sysmon, Autoruns, Scheduled tasks |
| **Lateral Movement** | Which systems were accessed? | SMB logs, RDP logs, WMI logs |

### Containment Decision Tree

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    CONTAINMENT DECISION TREE                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│                    ┌─────────────────┐                                   │
│                    │  Confirmed      │                                   │
│                    │  Compromise?    │                                   │
│                    └────────┬────────┘                                   │
│                             │                                            │
│              ┌──────────────┼──────────────┐                            │
│              ▼              ▼              ▼                            │
│           ┌────┐       ┌────┐       ┌────────┐                          │
│           │YES │       │NO  │       │UNCLEAR │                          │
│           └──┬─┘       └─┬──┘       └───┬────┘                          │
│              │           │               │                               │
│              ▼           ▼               ▼                               │
│      ┌──────────────┐  ┌────────┐  ┌──────────────┐                     │
│      │   ISOLATE    │  │MONITOR │  │  ENHANCED    │                     │
│      │   IMMEDIATELY│  │  ONLY  │  │  MONITORING  │                     │
│      └──────┬───────┘  └────────┘  └──────────────┘                     │
│             │                                                            │
│             ▼                                                            │
│  ┌──────────────────────┐                                               │
│  │  CONTAINMENT ACTIONS │                                               │
│  ├──────────────────────┤                                               │
│  │ • Network isolation  │                                               │
│  │ • Account disable    │                                               │
│  │ • Process termination│                                               │
│  │ • Service stop       │                                               │
│  └──────────────────────┘                                               │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Forensic Evidence Collection

```powershell
# Automated evidence collection script
param(
    [Parameter(Mandatory=$true)]
    [string]$TargetHost,
    
    [Parameter(Mandatory=$true)]
    [string]$CaseNumber,
    
    [datetime]$StartTime = (Get-Date).AddHours(-2),
    [datetime]$EndTime = (Get-Date)
)

$EvidencePath = "C:\Investigation\$CaseNumber"
New-Item -ItemType Directory -Path $EvidencePath -Force

# Collect Windows Event Logs
$EventLogs = @(
    "Security",
    "System",
    "Application",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Sysmon/Operational"
)

foreach ($log in $EventLogs) {
    $outputFile = "$EvidencePath\$($log.Replace('/','_')).evtx"
    wevtutil epl $log $outputFile
    Write-Host "Collected: $log"
}

# Collect Sysmon configuration
Copy-Item "C:\Windows\sysmonconfig.xml" "$EvidencePath\sysmonconfig.xml" -ErrorAction SilentlyContinue

# Collect prefetch files
$PrefetchPath = "$EvidencePath\Prefetch"
New-Item -ItemType Directory -Path $PrefetchPath -Force
Copy-Item "C:\Windows\Prefetch\*.pf" $PrefetchPath -ErrorAction SilentlyContinue

# Collect recent files
$RecentFiles = Get-ChildItem -Path "C:\Users" -Recurse -Include "*.exe","*.dll","*.ps1","*.bat","*.vbs" -ErrorAction SilentlyContinue | 
    Where-Object {$_.LastWriteTime -ge $StartTime -and $_.LastWriteTime -le $EndTime}
$RecentFiles | Export-Csv "$EvidencePath\recent_files.csv" -NoTypeInformation

# Network connections
Get-NetTCPConnection | Export-Csv "$EvidencePath\network_connections.csv" -NoTypeInformation

# Running processes
Get-Process | Select-Object Name, Id, Path, Company, Product | 
    Export-Csv "$EvidencePath\running_processes.csv" -NoTypeInformation

# Scheduled tasks
Get-ScheduledTask | Where-Object {$_.State -eq "Running" -or $_.LastRunTime -ge $StartTime} |
    Export-Csv "$EvidencePath\scheduled_tasks.csv" -NoTypeInformation

# Services
Get-Service | Where-Object {$_.Status -eq "Running"} |
    Export-Csv "$EvidencePath\running_services.csv" -NoTypeInformation

Write-Host "Evidence collection complete. Location: $EvidencePath"
```

---

## Investigation Templates

### L1 Triage Report Template

```markdown
# L1 Triage Report

**Incident ID:** INC-YYYY-MM-DD-###
**Analyst:** [Name]
**Date/Time:** [Timestamp]
**Alert Source:** [SIEM/IDS/EDR]

## Alert Summary
- **Alert Name:** 
- **Severity:** 
- **MITRE Technique:** 
- **Affected Host:** 
- **User Account:** 

## Initial Assessment
[2-3 sentence summary of the alert and initial findings]

## Evidence Reviewed
- [ ] SIEM events (30-minute window)
- [ ] Asset inventory
- [ ] User context
- [ ] Threat intelligence

## Key Findings
1. [Finding 1]
2. [Finding 2]
3. [Finding 3]

## Verdict
- [ ] True Positive (Escalate to L2)
- [ ] False Positive (Document and close)
- [ ] Benign (Close with notes)
- [ ] Escalate to L2 for further investigation

## L2 Handoff Notes (if applicable)
[Critical context for L2 analyst]

## Closed Reason (if closing)
[Detailed justification for closure]
```

### L2 Investigation Report Template

```markdown
# L2 Investigation Report

**Incident ID:** INC-YYYY-MM-DD-###
**Analyst:** [Name]
**Investigation Start:** [Timestamp]
**Investigation End:** [Timestamp]
**Classification:** [Malware/Intrusion/Insider Threat/Policy Violation/False Positive]

## Executive Summary
[1 paragraph summary of incident, impact, and resolution]

## Timeline of Events
| Time (UTC) | Event | Source | Details |
|------------|-------|--------|---------|
| HH:MM:SS | [Event] | [Log Source] | [Details] |

## Technical Analysis

### Initial Vector
[How the attack began]

### Attack Progression
[Step-by-step attack flow]

### Affected Systems
- [System 1] - [Impact]
- [System 2] - [Impact]

### Compromised Accounts
- [Account 1] - [Actions performed]

### Data Impact
- [Data accessed/exfiltrated]

## Indicators of Compromise

### Network IOCs
| Type | Value | Confidence |
|------|-------|------------|
| IP | x.x.x.x | High/Medium/Low |
| Domain | example.com | High/Medium/Low |

### Host IOCs
| Type | Value | Confidence |
|------|-------|------------|
| File Hash | [SHA256] | High/Medium/Low |
| File Path | C:\malware.exe | High/Medium/Low |
| Registry Key | HKLM\... | High/Medium/Low |

## Containment Actions
| Time | Action | Performed By | Result |
|------|--------|--------------|--------|
| HH:MM | [Action] | [Name] | [Result] |

## Eradication Actions
[Steps taken to remove threat]

## Recovery Actions
[Steps taken to restore systems]

## Lessons Learned
[Recommendations for prevention]

## Detection Gaps
[Identified gaps and recommendations]
```

---

## Escalation Criteria

### L1 to L2 Escalation Triggers

| Scenario | Escalation Reason | Urgency |
|----------|-------------------|---------|
| Lateral movement detected | Requires deep analysis | Immediate |
| Credential theft suspected | High impact potential | Immediate |
| Multiple systems affected | Scope assessment needed | 30 minutes |
| Malware execution confirmed | Reverse engineering needed | 30 minutes |
| Data exfiltration suspected | Forensic collection needed | 1 hour |
| Unknown technique observed | Threat research needed | 2 hours |
| L1 time threshold exceeded | Efficiency | 4 hours |

### Escalation Communication

**Required Information:**
1. Incident ID and alert details
2. Summary of findings to date
3. Why escalation is needed
4. Recommended priority
5. Any immediate containment already performed

---

*This workflow ensures consistent, thorough investigation of security alerts. All analysts must follow documented procedures and maintain detailed case notes.*
