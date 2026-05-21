# 🔍 Splunk Detection Engineering Lab — MITRE ATT&CK Custom Rules

> A hands-on Detection Engineering lab built in **Splunk**, mapping five custom detection rules directly to the **MITRE ATT&CK framework**. Each rule uses Splunk's Search Processing Language (SPL) to query Windows Event Logs and Sysmon telemetry for real adversary techniques — from Process Injection to Pass-the-Hash lateral movement.

---

## 📐 Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                  Detection Pipeline                      │
│                                                          │
│   ┌──────────────────┐      ┌────────────────────────┐  │
│   │  Windows Endpoint │─────►│  Splunk Universal      │  │
│   │                  │      │  Forwarder             │  │
│   │  ● Security Logs  │      └──────────┬─────────────┘  │
│   │  ● Sysmon Events  │                 │                 │
│   │  ● PowerShell     │                 ▼                 │
│   │    ScriptBlock    │      ┌────────────────────────┐  │
│   └──────────────────┘      │  Splunk Indexer         │  │
│                              │  index=windows          │  │
│                              └──────────┬─────────────┘  │
│                                         │                 │
│                                         ▼                 │
│                              ┌────────────────────────┐  │
│                              │  SPL Detection Rules    │  │
│                              │  (Saved as Alerts)      │  │
│                              └──────────┬─────────────┘  │
│                                         │                 │
│                                         ▼                 │
│                              ┌────────────────────────┐  │
│                              │  Splunk Dashboard       │  │
│                              │  MITRE ATT&CK Coverage  │  │
│                              └────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

---

## 🗺️ MITRE ATT&CK Coverage

| Rule | Technique ID | Technique Name | Tactic | Event Source |
|---|---|---|---|---|
| RULE-001 | T1055 | Process Injection | Defense Evasion, Privilege Escalation | Sysmon EventCode 10, 8 |
| RULE-002 | T1053.005 | Scheduled Task / Job | Execution, Persistence | Windows Security 4698, 4702 |
| RULE-003 | T1003 | OS Credential Dumping (LSASS) | Credential Access | Sysmon EventCode 10 |
| RULE-004 | T1059.001 | PowerShell Obfuscation | Execution | PowerShell EventCode 4104 |
| RULE-005 | T1550.002 | Pass-the-Hash | Lateral Movement | Windows Security 4624 |

---

## 🔧 Prerequisites

- **Splunk Enterprise** (free trial or licensed) — [Download](https://www.splunk.com/en_us/download/splunk-enterprise.html)
- **Sysmon** (System Monitor by Sysinternals) deployed on the Windows endpoint — [Download](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- **Sysmon config** with ProcessAccess (EventCode 10) and CreateRemoteThread (EventCode 8) logging enabled
- Windows endpoint with Security Event logging configured via Group Policy

**Required Windows Audit Policies:**

| Policy | Setting |
|---|---|
| Audit Logon Events | Success and Failure |
| Audit Process Creation | Success |
| Audit Account Logon Events | Success and Failure |
| PowerShell Script Block Logging | Enabled (Group Policy) |
| Sysmon EventCode 10 (ProcessAccess) | Enabled in Sysmon config |
| Sysmon EventCode 8 (CreateRemoteThread) | Enabled in Sysmon config |

**Enable PowerShell Script Block Logging (Group Policy):**
```
Computer Configuration → Administrative Templates →
Windows Components → Windows PowerShell →
Turn on Script Block Logging → Enabled
```

---

## ⚙️ Splunk Setup

**1. Create the index:**

In Splunk: `Settings → Indexes → New Index → Name: windows`

**2. Configure the Universal Forwarder `inputs.conf`:**
```ini
[WinEventLog://Security]
index = windows
disabled = false

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index = windows
disabled = false

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
index = windows
disabled = false
```

**3. Verify data is flowing:**
```spl
index=windows | head 10
```

> 💡 Use the [SwiftOnSecurity Sysmon config](https://github.com/SwiftOnSecurity/sysmon-config) for comprehensive endpoint telemetry out of the box.

---

## 🧠 Detection Rules (SPL)

### RULE-001 — Process Injection (T1055)

Detects cross-process memory access via Sysmon EventCode 10 (ProcessAccess) with high-privilege access rights — a key indicator of DLL injection, process hollowing, and shellcode injection.

```spl
index=windows EventCode=10 OR EventCode=8
| where TargetImage!=SourceImage
| eval technique="T1055 - Process Injection"
| stats count by SourceImage, TargetImage, GrantedAccess, _time
| where GrantedAccess="0x1fffff" OR GrantedAccess="0x1f0fff"
| eval severity=if(count>5,"HIGH","MEDIUM")
| table _time, SourceImage, TargetImage, GrantedAccess, count, severity
```

**Key indicators:**
- `GrantedAccess = 0x1fffff` — Full process access (all rights)
- Source processes: `powershell.exe`, `mshta.exe`, `cmd.exe`
- Target processes: `lsass.exe`, `svchost.exe`, `winlogon.exe`, `explorer.exe`

---

### RULE-002 — Scheduled Task Creation (T1053.005)

Flags Windows task creation or modification (EventCode 4698 / 4702) where the task command uses a suspicious interpreter such as PowerShell, cmd, mshta, wscript, or rundll32.

```spl
index=windows EventCode=4698 OR EventCode=4702
| eval technique="T1053.005 - Scheduled Task"
| rex field=TaskContent "(?<TaskCommand><Command>(?P<cmd>[^<]+))"
| eval suspicious=if(match(cmd, "powershell|cmd|wscript|mshta|rundll32"), "YES", "NO")
| where suspicious="YES"
| stats count by TaskName, TaskCommand, UserName, ComputerName
| sort -count
```

**Key indicators:**
- Task names mimicking Windows built-ins (e.g., `\Microsoft\WindowsUpdate`)
- Commands using `-enc`, `-w hidden`, or `-exec bypass`
- Tasks containing external URLs (`mshta.exe http://...`)

---

### RULE-003 — OS Credential Dumping / LSASS (T1003)

Detects any process accessing `lsass.exe` memory — the primary method used by tools like Mimikatz and ProcDump to extract password hashes and plaintext credentials.

```spl
index=windows EventCode=10 TargetImage="*lsass.exe"
| eval technique="T1003 - Credential Dumping"
| eval tool=case(
    match(SourceImage,"mimikatz"),"Mimikatz",
    match(SourceImage,"procdump"),"ProcDump",
    match(GrantedAccess,"0x1fffff"),"Full Access Dump",
    1==1,"Unknown")
| eval severity="CRITICAL"
| stats count by SourceImage, GrantedAccess, tool, _time, ComputerName
| sort -_time
```

**Key indicators:**
- `mimikatz.exe` or `procdump.exe` as `SourceImage` → **immediate CRITICAL response required**
- `powershell.exe` accessing `lsass.exe` → in-memory Mimikatz
- `GrantedAccess = 0x1fffff` on lsass

> ⚠️ Any confirmed lsass.exe access by an untrusted process should be treated as an active compromise. Isolate the host and begin incident response immediately.

---

### RULE-004 — PowerShell Obfuscation (T1059.001)

Identifies obfuscated PowerShell executions using ScriptBlock Logging (EventCode 4104). Assigns a composite risk score based on obfuscation indicators found in the script block.

```spl
index=windows EventCode=4104
| eval technique="T1059.001 - PowerShell Obfuscation"
| eval obfuscated=if(match(ScriptBlockText,
    "-[Ee][Nn][Cc]|-[Ee][Nn][Cc][Oo][Dd][Ee]|IEX|Invoke-Expression|FromBase64String"),
    "YES", "NO")
| where obfuscated="YES"
| eval score=0
| eval score=score+if(match(ScriptBlockText,"-enc"),3,0)
| eval score=score+if(match(ScriptBlockText,"IEX|Invoke-Expression"),2,0)
| eval score=score+if(match(ScriptBlockText,"FromBase64String"),2,0)
| eval score=score+if(match(ScriptBlockText,"-NonInteractive"),1,0)
| table _time, ComputerName, UserName, score, ScriptBlockText
```

**Risk score guide:**

| Score | Severity | Description |
|---|---|---|
| 5+ | HIGH | Multiple obfuscation techniques combined |
| 2–4 | MEDIUM | Single obfuscation indicator |
| 1 | LOW | Minor flag, needs context |

**Key indicators:**
- `-enc` or `-EncodedCommand` with a long Base64 string
- `IEX` / `Invoke-Expression` with download cradle patterns
- `SYSTEM` account running encoded PowerShell

---

### RULE-005 — Pass-the-Hash / Lateral Movement (T1550.002)

Detects Pass-the-Hash attacks using EventCode 4624 (Network Logon) with NTLM authentication, `KeyLength=0`, and a null `SubjectUserName` — the combination that distinguishes PtH from legitimate network logons.

```spl
index=windows EventCode=4624 LogonType=3
| eval technique="T1550.002 - Pass the Hash"
| where AuthenticationPackageName="NTLM" AND KeyLength=0
| eval pth_indicator=if(
    match(SubjectUserName,"-") AND SubjectLogonId="0x0",
    "LIKELY_PTH","REVIEW")
| stats count by SubjectUserName, IpAddress, WorkstationName, LogonType, pth_indicator
| where pth_indicator="LIKELY_PTH"
| sort -count
```

**Key indicators:**
- `SubjectUserName = "-"` (dash) — hallmark of PtH, no subject identity at logon time
- `KeyLength = 0` combined with NTLM authentication
- Repeated hits from a single source IP to multiple destinations in a short window
- Cross-reference with RULE-003 — credentials dumped then used laterally

---

## 💾 Saving Rules as Scheduled Alerts

Once a query produces accurate results, save it as a Splunk Alert to run automatically:

1. Run the SPL query in **Search & Reporting**
2. Click **Save As → Alert**
3. Set **Alert Title** (e.g., `RULE-003: LSASS Credential Dump Detected`)
4. Set **Permissions** to `Shared in App`
5. Set **Alert type** to `Scheduled`
6. Set **Cron schedule** (e.g., every 15 minutes: `*/15 * * * *`)
7. Set **Time Range** to match the schedule window (e.g., Last 15 minutes)
8. Set **Trigger Condition**: Number of results is greater than `0`
9. Add **Trigger Action**: Send email or Slack webhook notification
10. Click **Save**

> 💡 For CRITICAL rules (RULE-003 Credential Dumping), set the schedule to every 5 minutes and add a real-time Slack notification for the fastest possible response time.

---

## 📊 Quick Reference — All 5 Rules

| Rule ID | MITRE ID | EventCode(s) | SPL Key Filter |
|---|---|---|---|
| RULE-001 | T1055 | Sysmon 10, 8 | `GrantedAccess="0x1fffff" AND TargetImage!=SourceImage` |
| RULE-002 | T1053.005 | 4698, 4702 | `match(cmd, "powershell\|mshta\|wscript")` |
| RULE-003 | T1003 | Sysmon 10 | `TargetImage="*lsass.exe"` |
| RULE-004 | T1059.001 | 4104 | `match(ScriptBlockText, "-enc\|IEX\|FromBase64String")` |
| RULE-005 | T1550.002 | 4624 | `LogonType=3 AND NTLM AND KeyLength=0` |

---

## 🛠️ Tech Stack

| Technology | Purpose |
|---|---|
| **Splunk Enterprise** | SIEM platform — indexing, SPL querying, alerts, dashboards |
| **Sysmon (Sysinternals)** | Endpoint telemetry — ProcessAccess, CreateRemoteThread, network events |
| **Windows Event Log** | Native Windows security and PowerShell events |
| **SPL** | Splunk's Search Processing Language — detection rule logic |
| **MITRE ATT&CK** | Adversary technique framework used to map and validate each rule |

---

## 📚 References

- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [Splunk SPL Documentation](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference)
- [Sysmon Event IDs Reference](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Splunk Security Essentials App](https://splunkbase.splunk.com/app/3435)
- [MITRE ATT&CK T1055 — Process Injection](https://attack.mitre.org/techniques/T1055/)
- [MITRE ATT&CK T1003 — Credential Dumping](https://attack.mitre.org/techniques/T1003/)

---

## ⚠️ Disclaimer

This project is built entirely for **educational and cybersecurity research purposes**. All detection rules, event data, and screenshots shown are generated in a controlled lab environment. These SPL queries are starting points — always tune them to your specific environment to reduce false positives before deploying in production. Never run offensive security tools outside of an authorised, isolated lab.

---

## 📄 License

MIT License — free to fork, adapt, and build on.
