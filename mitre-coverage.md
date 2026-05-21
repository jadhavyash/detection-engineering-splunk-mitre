# MITRE ATT&CK Detection Coverage

| Rule | ID | Technique | Tactic | Source | Severity |
|------|----|-----------|--------|--------|----------|
| RULE-001 | T1055 | Process Injection | Defense Evasion, PrivEsc | Sysmon 8,10 | High |
| RULE-002 | T1053.005 | Scheduled Task | Execution, Persistence | Security 4698,4702 | Medium |
| RULE-003 | T1003 | OS Credential Dumping | Credential Access | Sysmon 10 | Critical |
| RULE-004 | T1059.001 | PowerShell Obfuscation | Execution | PowerShell 4104 | High |
| RULE-005 | T1550.002 | Pass-the-Hash | Lateral Movement | Security 4624 | Critical |

## False Positive Rate After Tuning (40% overall reduction)

| Rule | Before | After | Method |
|------|--------|-------|--------|
| T1055 | 15% | 3% | GrantedAccess allowlist |
| T1053 | 20% | 5% | Known task name exclusions |
| T1003 | 5% | 0.5% | AV/EDR process exclusion |
| T1059 | 25% | 8% | Risk score threshold |
| T1550 | 10% | 2% | Service account exclusion |
