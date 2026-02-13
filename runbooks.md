# Runbooks

## Overview

This document contains operational runbooks for attack simulation execution, incident response, containment procedures, and MITRE ATT&CK alert mapping. Each runbook provides step-by-step procedures for consistent execution.

---

## Runbook Index

| Runbook ID | Name | Purpose | Owner |
|------------|------|---------|-------|
| RB-001 | Attack Simulation Execution | Standardized attack scenario execution | Red Team |
| RB-002 | Network Scan Response | Respond to network reconnaissance alerts | SOC L1 |
| RB-003 | Brute Force Response | Respond to authentication attacks | SOC L1/L2 |
| RB-004 | Lateral Movement Response | Respond to SMB/remote execution alerts | SOC L2 |
| RB-005 | Credential Dumping Response | Respond to LSASS/memory access alerts | SOC L2 |
| RB-006 | Malware Execution Response | Respond to malicious code execution | SOC L2 |
| RB-007 | Host Containment | Isolate compromised systems | SOC L2 |
| RB-008 | User Account Containment | Disable compromised accounts | SOC L1/L2 |
| RB-009 | MITRE ATT&CK Alert Mapping | Map alerts to MITRE techniques | Detection Engineering |

---

## RB-001: Attack Simulation Execution Runbook

### Purpose
Standardize the execution of attack simulation scenarios to ensure consistent, safe, and documented testing.

### Prerequisites

| Item | Verification Command |
|------|---------------------|
| Lab environment isolated | `ping [production_gateway]` (should fail) |
| Attacker machine ready | `systemctl status postgresql` |
| Target systems online | `nmap -sn [target_subnet]` |
| Sysmon running on targets | `Get-Service Sysmon64` |
| SIEM ingestion confirmed | Check last log timestamp |
| Snapshot/backup available | Verify VM snapshot exists |
| Authorization documented | Confirm test authorization ticket |

### Pre-Execution Checklist

```bash
#!/bin/bash
# pre_execution_check.sh

echo "=== Attack Simulation Pre-Execution Checklist ==="

# Check connectivity
echo "[*] Verifying attacker connectivity..."
ping -c 2 10.0.0.10 > /dev/null && echo "[+] DC reachable" || echo "[!] DC unreachable"
ping -c 2 10.0.0.20 > /dev/null && echo "[+] Workstation reachable" || echo "[!] Workstation unreachable"

# Verify tools
echo "[*] Verifying attack tools..."
which nmap > /dev/null && echo "[+] Nmap installed" || echo "[!] Nmap missing"
which hydra > /dev/null && echo "[+] Hydra installed" || echo "[!] Hydra missing"
which crackmapexec > /dev/null && echo "[+] CrackMapExec installed" || echo "[!] CME missing"
which python3 > /dev/null && echo "[+] Python3 installed" || echo "[!] Python3 missing"

# Check SIEM
echo "[*] Verifying SIEM connectivity..."
curl -s http://10.0.0.100:9200/_cluster/health > /dev/null && echo "[+] Elasticsearch reachable" || echo "[!] Elasticsearch unreachable"

echo "[*] Pre-execution check complete"
```

### Execution Procedures

#### Phase 1: Documentation

```bash
# Create test session directory
TEST_ID="TEST-$(date +%Y%m%d-%H%M%S)"
mkdir -p /opt/attack-sim/results/$TEST_ID
cd /opt/attack-sim/results/$TEST_ID

# Document test parameters
cat > test_metadata.txt << EOF
Test ID: $TEST_ID
Date: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Operator: $(whoami)
Scenario: [AS-001/002/003/004/005]
Target: [IP/Hostname]
Authorization: [Ticket Number]
EOF
```

#### Phase 2: Baseline Capture

```bash
# Capture 5 minutes of baseline activity
echo "[*] Capturing baseline telemetry..."
sleep 300

# Export baseline from SIEM
curl -X GET "http://10.0.0.100:9200/winlogbeat-*/_search?q=host.name:[TARGET_HOST]&size=100" \
  -H "Content-Type: application/json" > baseline_events.json
```

#### Phase 3: Attack Execution

```bash
# Execute attack scenario per attack_simulation_scenarios.md
echo "[*] Executing attack scenario..."
echo "Start Time: $(date -u +"%Y-%m-%d %H:%M:%S UTC")" >> execution_log.txt

# [ATTACK COMMANDS HERE]
nmap -sS -p- -T4 10.0.0.10 -oN nmap_scan.txt

echo "End Time: $(date -u +"%Y-%m-%d %H:%M:%S UTC")" >> execution_log.txt
```

#### Phase 4: Telemetry Collection

```bash
# Collect Windows Event Logs from target
scp administrator@10.0.0.10:/Windows/System32/winevt/Logs/Security.evtx ./
scp administrator@10.0.0.10:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon* ./

# Collect Suricata logs
scp root@10.0.0.1:/var/log/suricata/eve.json ./suricata_eve.json

# Export SIEM alerts
curl -X GET "http://10.0.0.100:9200/.kibana/_search?q=alert*" \
  -H "Content-Type: application/json" > siem_alerts.json
```

#### Phase 5: Analysis

```bash
# Analyze detection coverage
echo "[*] Analyzing detection coverage..."
python3 /opt/attack-sim/scripts/detection_analyzer.py \
  --test-id $TEST_ID \
  --expected-techniques T1046,T1018 \
  --telemetry-dir ./
```

### Post-Execution

```bash
# Generate report
python3 /opt/attack-sim/scripts/generate_report.py --test-id $TEST_ID

# Clean up target (if needed)
ssh administrator@10.0.0.10 'del C:\Windows\Temp\* /Q'

# Restore from snapshot (if required)
# [SNAPSHOT RESTORE COMMAND]

echo "[*] Test execution complete: $TEST_ID"
```

---

## RB-002: Network Scan Response Runbook

### Alert Trigger
- Suricata: `ET SCAN Nmap User-Agent`
- Suricata: `ET SCAN Potential Port Scan`
- Suricata: `GPL SCAN SYN FIN Scan`
- Custom: >50 connection attempts from single source in 60 seconds

### Response Procedures

#### Step 1: Alert Verification (5 minutes)

```splunk
# Verify scan activity
index=suricata alert.signature_id=2002910 OR alert.signature_id=2002911 OR alert.signature_id=2003068
| stats count by src_ip, dest_ip, alert.signature
| sort -count
```

```kibana
# Kibana verification
GET /suricata-*/_search
{
  "query": {
    "bool": {
      "must": [
        {"exists": {"field": "alert"}},
        {"range": {"@timestamp": {"gte": "now-1h"}}}
      ],
      "should": [
        {"match": {"alert.signature": "Nmap"}},
        {"match": {"alert.signature": "SCAN"}}
      ]
    }
  }
}
```

#### Step 2: Source IP Analysis

| Check | Command/Query | Decision Point |
|-------|---------------|----------------|
| Internal or External | `| iplocation src_ip` | Internal = escalate |
| Known asset? | Lookup CMDB | Known = check with owner |
| Previous activity? | Search 7-day history | Repeat offender = escalate |
| User associated? | Check VPN logs | Correlated user = investigate |

#### Step 3: Scope Assessment

```splunk
# Determine scan scope
index=suricata OR index=windows
    src_ip=[SCANNER_IP]
    earliest=-2h
| stats count by dest_ip, dest_port
| sort -count
```

#### Step 4: Response Actions

| Scenario | Action | Owner |
|----------|--------|-------|
| Authorized scan | Document, close with notes | L1 |
| Unauthorized internal | Escalate to L2, notify manager | L1 |
| External scan | Block at perimeter, document | L1 |
| Unknown origin | Escalate to L2 for investigation | L1 |

#### Step 5: Containment (if required)

```bash
# Add to pfSense block list via API
curl -X POST https://10.0.0.1/api/v1/firewall/alias \
  -H "Authorization: Bearer [API_TOKEN]" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "BLOCKED_SCANNERS",
    "type": "host",
    "address": "[SCANNER_IP]",
    "descr": "Blocked for network scanning - INC-[NUMBER]"
  }'
```

---

## RB-003: Brute Force Response Runbook

### Alert Trigger
- Windows Event ID 4625 (Failed Logon) - Multiple
- Windows Event ID 4771 (Kerberos Pre-Auth Failed) - Multiple
- Windows Event ID 4740 (Account Lockout)
- Custom: ≥5 failed logons from single source in 5 minutes

### Response Procedures

#### Step 1: Verify Brute Force Pattern

```splunk
# Identify brute force pattern
index=windows EventCode=4625 OR EventCode=4771
| eval Failure_Reason=case(
    Status=="0xC000006D", "Bad username or password",
    Status=="0xC000006A", "Bad password",
    Status=="0xC0000064", "Bad username",
    Status=="0xC0000234", "Account locked",
    1==1, "Other"
)
| stats count, values(Failure_Reason) as Reasons by src_ip, Account_Name
| where count >= 5
| sort -count
```

#### Step 2: Determine Attack Type

| Pattern | Description | Response |
|---------|-------------|----------|
| Single user, many passwords | Targeted brute force | Account review |
| Many users, single password | Password spraying | Organization-wide alert |
| Sequential usernames | User enumeration | Monitor for follow-up |
| Distributed sources | Slow brute force | Correlation analysis |

#### Step 3: Account Status Check

```powershell
# Check if account was compromised
$Account = "[TARGET_ACCOUNT]"
$StartTime = (Get-Date).AddHours(-1)

# Check for successful logon after failures
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4624, 4625
    StartTime = $StartTime
} | Where-Object {
    $_.Message -match $Account
} | Select-Object TimeCreated, Id, LevelDisplayName, @{N='Account';E={$Account}}
```

#### Step 4: Response Decision Matrix

| Condition | Action | Priority |
|-----------|--------|----------|
| Failed only | Monitor, notify account owner | Low |
| Success after failures | Disable account, force password reset | Critical |
| Account locked | Unlock after verification, force reset | Medium |
| Privileged account | Immediate disable, incident response | Critical |
| Multiple accounts | Organization-wide response | High |

#### Step 5: Account Disable Procedure

```powershell
# Disable compromised account
Disable-ADAccount -Identity "[USERNAME]"

# Force password reset at next logon
Set-ADUser -Identity "[USERNAME]" -ChangePasswordAtLogon $true

# Revoke all sessions
# (Requires Azure AD or specific session management)

# Document action
Write-Host "Account [USERNAME] disabled at $(Get-Date)" >> C:\Investigation\actions.log
```

#### Step 6: Source IP Blocking

```bash
# Add to network block list
curl -X POST https://10.0.0.1/api/v1/firewall/rule \
  -H "Authorization: Bearer [API_TOKEN]" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "block",
    "interface": "wan",
    "ipprotocol": "inet",
    "src": "[ATTACKER_IP]",
    "dst": "any",
    "descr": "Brute force attack - INC-[NUMBER]"
  }'
```

---

## RB-004: Lateral Movement Response Runbook

### Alert Trigger
- Sysmon Event ID 7045 (Service Install) - PSEXESVC
- Windows Event ID 4624 (Type 3) followed by 4688
- Sysmon Event ID 8 (CreateRemoteThread)
- SMB admin share access (Event ID 5140) + remote execution

### Response Procedures

#### Step 1: Alert Verification

```splunk
# Identify lateral movement pattern
index=sysmon EventCode=7045 ServiceName="PSEXESVC"
OR (index=sysmon EventCode=1 ParentImage="*services.exe" Image="*cmd.exe")
OR (index=sysmon EventCode=8 SourceImage="*services.exe")
| eval Movement_Type=case(
    ServiceName=="PSEXESVC", "PsExec",
    ParentImage=="*services.exe", "Service Execution",
    SourceImage=="*services.exe", "Process Injection",
    1==1, "Unknown"
)
| table _time, host, Movement_Type, Image, CommandLine, User
```

#### Step 2: Scope Assessment

```powershell
# Identify all systems accessed from source
$SourceIP = "[SOURCE_IP]"
$StartTime = (Get-Date).AddHours(-2)

Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4624, 5140
    StartTime = $StartTime
} | Where-Object {
    $_.Message -match $SourceIP
} | Group-Object {$_.MachineName} | Select-Object Name, Count
```

#### Step 3: Process Tree Analysis

```splunk
# Build process tree
index=sysmon EventCode=1 
    host=[TARGET_HOST]
    earliest=-2h
| eval ProcessTree=mvappend(ParentImage, Image)
| stats values(CommandLine) as Commands, count by ProcessTree, ProcessGuid
| sort -count
```

#### Step 4: Immediate Containment

| Priority | Action | Command |
|----------|--------|---------|
| 1 | Isolate source host | Network isolation |
| 2 | Disable compromised account | `Disable-ADAccount` |
| 3 | Terminate malicious processes | `Stop-Process -Force` |
| 4 | Remove persistence | Delete services, scheduled tasks |

#### Step 5: Network Isolation

```powershell
# Windows Firewall isolation
New-NetFirewallRule -DisplayName "INC-ISOLATION" -Direction Inbound -Action Block -RemoteAddress Any
New-NetFirewallRule -DisplayName "INC-ISOLATION-OUT" -Direction Outbound -Action Block -RemoteAddress Any

# Allow only management access
New-NetFirewallRule -DisplayName "INC-MGMT-IN" -Direction Inbound -Action Allow -RemoteAddress "10.0.0.0/24"
```

#### Step 6: Forensic Collection

```powershell
# Execute evidence collection
.\RB-ForensicCollection.ps1 -TargetHost [HOSTNAME] -CaseNumber [INC-###]
```

---

## RB-005: Credential Dumping Response Runbook

### Alert Trigger
- Sysmon Event ID 10 (ProcessAccess) - LSASS access
- Sysmon Event ID 25 (ProcessTampering)
- Windows Event ID 4656/4663 - SAM/SECURITY hive access
- Command line: `rundll32 comsvcs.dll MiniDump`

### Response Procedures

#### Step 1: Verify Credential Access

```splunk
# LSASS access detection
index=sysmon EventCode=10 TargetImage="*lsass.exe"
| eval Access_Type=case(
    GrantedAccess=="0x1010", "VM Read",
    GrantedAccess=="0x1410", "Query+VM Read",
    GrantedAccess=="0x143A", "All Access",
    1==1, GrantedAccess
)
| stats count, values(SourceImage) as Source_Processes by host, Access_Type
| sort -count
```

#### Step 2: Identify Dump Location

```splunk
# Find dump file creation
index=sysmon EventCode=11 
    (TargetFilename="*.dmp" OR TargetFilename="*lsass*")
    earliest=-1h
| table _time, host, TargetFilename, Image
```

#### Step 3: Immediate Actions

| Action | Command | Priority |
|--------|---------|----------|
| Disable affected account | `Disable-ADAccount` | Critical |
| Reset KRBTGT (if domain compromise suspected) | `Reset-KrbtgtKey` | Critical |
| Force password reset for affected users | `Set-ADUser -ChangePasswordAtLogon $true` | High |
| Revoke Kerberos tickets | `klist purge` | High |
| Isolate affected host | Network isolation | Critical |

#### Step 4: Domain Compromise Assessment

```powershell
# Check for DCSync attempts
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4662
    StartTime = (Get-Date).AddHours(-24)
} | Where-Object {
    $_.Message -match "Replicating Directory Changes"
}

# Check for Golden Ticket indicators
# Look for TGTs with unusual lifetimes or account mismatches
```

#### Step 5: Recovery Procedures

```powershell
# Reset KRBTGT password twice (if DCSync detected)
# WARNING: Only execute during maintenance window

# First reset
Set-ADAccountPassword -Identity "krbtgt" -Reset -NewPassword (ConvertTo-SecureString -String "[TEMP_PASSWORD_1]" -AsPlainText -Force)

# Wait 10 hours (or max TGT lifetime)
Start-Sleep -Seconds 36000

# Second reset
Set-ADAccountPassword -Identity "krbtgt" -Reset -NewPassword (ConvertTo-SecureString -String "[TEMP_PASSWORD_2]" -AsPlainText -Force)
```

---

## RB-006: Malware Execution Response Runbook

### Alert Trigger
- EDR: Malware detection
- Sysmon: Known malicious hash
- Suricata: Malware C2 communication
- Windows Defender: Threat detected

### Response Procedures

#### Step 1: Verify Detection

```powershell
# Check Windows Defender detections
Get-MpThreatDetection | Select-Object *

# Check for active threats
Get-MpThreat | Select-Object *
```

#### Step 2: Sample Collection

```powershell
# Collect malware sample (if safe)
$MalwarePath = "[DETECTED_PATH]"
$QuarantinePath = "C:\Investigation\Quarantine"

# Calculate hash
Get-FileHash -Path $MalwarePath -Algorithm SHA256

# Copy to quarantine (do not move - preserve evidence)
Copy-Item -Path $MalwarePath -Destination $QuarantinePath

# Upload to sandbox for analysis
# [SANDBOX API CALL]
```

#### Step 3: Scope Assessment

```splunk
# Find similar executions
index=sysmon EventCode=1 
    (Image="[MALWARE_PATH]" OR Hashes="[KNOWN_HASH]")
| stats count by host, Image, CommandLine, User
```

#### Step 4: Containment

```powershell
# Terminate malicious process
Stop-Process -Name "[PROCESS_NAME]" -Force

# Delete malware file
Remove-Item -Path "[MALWARE_PATH]" -Force

# Remove persistence
# Check Run keys
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

# Check scheduled tasks
Get-ScheduledTask | Where-Object {$_.TaskPath -eq "\"} | Get-ScheduledTaskInfo
```

---

## RB-007: Host Containment Runbook

### Purpose
Isolate compromised hosts from the network while preserving forensic evidence.

### Isolation Methods

| Method | Use Case | Command |
|--------|----------|---------|
| Network ACL | Quick isolation | pfSense API block |
| Windows Firewall | Host-based | `New-NetFirewallRule` |
| VLAN move | Network segmentation | Switch port reassign |
| Physical disconnect | Critical compromise | Unplug cable |

### Windows Firewall Isolation

```powershell
function Invoke-HostContainment {
    param(
        [string]$ComputerName,
        [string]$IncidentID,
        [string[]]$AllowedNetworks = @("10.0.0.0/24")
    )
    
    # Create isolation rules
    $RulePrefix = "CONTAIN-$IncidentID"
    
    # Block all inbound
    New-NetFirewallRule -DisplayName "$RulePrefix-IN" `
        -Direction Inbound `
        -Action Block `
        -RemoteAddress Any `
        -LocalAddress Any
    
    # Block all outbound
    New-NetFirewallRule -DisplayName "$RulePrefix-OUT" `
        -Direction Outbound `
        -Action Block `
        -RemoteAddress Any `
        -LocalAddress Any
    
    # Allow management access
    foreach ($network in $AllowedNetworks) {
        New-NetFirewallRule -DisplayName "$RulePrefix-MGMT-IN" `
            -Direction Inbound `
            -Action Allow `
            -RemoteAddress $network
        
        New-NetFirewallRule -DisplayName "$RulePrefix-MGMT-OUT" `
            -Direction Outbound `
            -Action Allow `
            -RemoteAddress $network
    }
    
    Write-Output "Host $ComputerName contained for incident $IncidentID"
}
```

---

## RB-008: User Account Containment Runbook

### Purpose
Disable compromised user accounts and revoke active sessions.

### Account Disable Procedure

```powershell
function Disable-CompromisedAccount {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Username,
        
        [Parameter(Mandatory=$true)]
        [string]$IncidentID,
        
        [switch]$ForcePasswordReset,
        [switch]$RevokeSessions
    )
    
    # Disable account
    Disable-ADAccount -Identity $Username
    
    # Force password reset
    if ($ForcePasswordReset) {
        Set-ADUser -Identity $Username -ChangePasswordAtLogon $true
    }
    
    # Add to incident group for tracking
    Add-ADGroupMember -Identity "Incident-CompromisedAccounts" -Members $Username
    
    # Log action
    $LogEntry = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Username = $Username
        Action = "Account Disabled"
        IncidentID = $IncidentID
        PerformedBy = $env:USERNAME
    }
    
    $LogEntry | ConvertTo-Json | Add-Content -Path "C:\Investigation\account_actions.log"
    
    Write-Output "Account $Username disabled for incident $IncidentID"
}
```

---

## RB-009: MITRE ATT&CK Alert Mapping Runbook

### Purpose
Map security alerts to MITRE ATT&CK techniques for coverage analysis.

### Mapping Procedure

```python
# mitre_mapping.py
import json
import yaml

class MITREMapper:
    def __init__(self, mitre_data_path):
        with open(mitre_data_path, 'r') as f:
            self.mitre_data = json.load(f)
    
    def map_alert_to_technique(self, alert_name, alert_description):
        """Map alert to MITRE technique based on keywords"""
        mapping = {
            # Credential Access
            "LSASS": "T1003.001",
            "SAM": "T1003.002",
            "NTDS": "T1003.003",
            "credential": "T1003",
            "password": "T1110",
            "brute": "T1110",
            
            # Execution
            "PowerShell": "T1059.001",
            "cmd.exe": "T1059.003",
            "wscript": "T1059.005",
            "mshta": "T1218.005",
            "rundll32": "T1218.011",
            
            # Persistence
            "scheduled task": "T1053.005",
            "service": "T1543.003",
            "run key": "T1547.001",
            
            # Lateral Movement
            "PsExec": "T1021.002",
            "SMB": "T1021.002",
            "WMI": "T1047",
            "RDP": "T1021.001",
            
            # Defense Evasion
            "injection": "T1055",
            "hollow": "T1055.012",
            "obfusc": "T1027",
            
            # Discovery
            "nmap": "T1046",
            "scan": "T1046",
            "enum": "T1087",
            "BloodHound": "T1087.002",
        }
        
        alert_text = f"{alert_name} {alert_description}".lower()
        
        matched_techniques = []
        for keyword, technique in mapping.items():
            if keyword.lower() in alert_text:
                matched_techniques.append(technique)
        
        return list(set(matched_techniques))
    
    def generate_coverage_map(self, alerts):
        """Generate MITRE coverage map from alert set"""
        coverage = {}
        
        for alert in alerts:
            techniques = self.map_alert_to_technique(
                alert['name'], 
                alert['description']
            )
            
            for technique in techniques:
                if technique not in coverage:
                    coverage[technique] = []
                coverage[technique].append(alert['name'])
        
        return coverage
    
    def export_navigator_layer(self, coverage, output_path):
        """Export coverage for MITRE ATT&CK Navigator"""
        layer = {
            "name": "SOC Detection Coverage",
            "versions": {
                "attack": "14",
                "navigator": "4.9.1",
                "layer": "4.5"
            },
            "domain": "enterprise-attack",
            "description": "Detection coverage based on alert rules",
            "techniques": []
        }
        
        for technique, alerts in coverage.items():
            layer["techniques"].append({
                "techniqueID": technique,
                "score": len(alerts) * 10,
                "comment": ", ".join(alerts),
                "enabled": True
            })
        
        with open(output_path, 'w') as f:
            json.dump(layer, f, indent=2)

# Usage
mapper = MITREMapper("mitre-enterprise-attack.json")

alerts = [
    {"name": "LSASS Access Detected", "description": "Process accessing LSASS memory"},
    {"name": "PowerShell Download Cradle", "description": "PowerShell downloading external content"},
    {"name": "PsExec Execution", "description": "PsExec service installation detected"}
]

coverage = mapper.generate_coverage_map(alerts)
mapper.export_navigator_layer(coverage, "coverage_layer.json")
```

---

*All runbooks must be reviewed quarterly and updated based on lessons learned from incidents and simulation exercises.*
