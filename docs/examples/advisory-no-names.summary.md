# Advisory: credential theft and data staging observed on a file server (synthetic example)

_`examples/advisory-no-names.txt` · sha256 `bf2c45c3feac…` · 11 sentences · Gleaner 0.1.0 (iocs, gazetteer, crf, technique-classifier)_

## Indicators (1)

| Type | Value | Exported as | Mentions |
|---|---|---|---:|
| url | `hxxp://files[.]example[.]com/upload` | indicator (documentation range) | 1 |

## Named entities (0)


## ATT&CK techniques (10)

| Technique | Tactics | Score | Found by | Evidence |
|---|---|---:|---|---|
| [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery | discovery | 1.00 | classifier | The script then collected the hostname, operating system version and network configuration of the server. |
| [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols | command-and-control | 0.99 | classifier | The archive was sent to hxxp://files.example[.]com/upload over the same HTTP channel used for commands. |
| [T1518.001](https://attack.mitre.org/techniques/T1518/001) Security Software Discovery | discovery | 0.99 | classifier | A PowerShell script queried the registry for installed security products and listed running processes. |
| [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion | stealth | 0.98 | classifier | Finally, the attacker deleted the scripts and cleared the event logs to cover their tracks. |
| [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery | discovery | 0.96 | classifier | A PowerShell script queried the registry for installed security products and listed running processes. |
| [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery | discovery | 0.95 | classifier | The script then collected the hostname, operating system version and network configuration of the server. |
| [T1570](https://attack.mitre.org/techniques/T1570) Lateral Tool Transfer | lateral-movement | 0.85 | classifier | The intruder copied a remote administration utility to two other servers over SMB and started it as a service. |
| [T1078](https://attack.mitre.org/techniques/T1078) Valid Accounts | stealth, persistence, privilege-escalation, initial-access | 0.42 | classifier | The attacker logged in through the VPN with a valid account belonging to a contractor. |
| [T1112](https://attack.mitre.org/techniques/T1112) Modify Registry | defense-impairment, persistence | 0.39 | classifier | A PowerShell script queried the registry for installed security products and listed running processes. |
| [T1569.002](https://attack.mitre.org/techniques/T1569/002) Service Execution | execution | 0.30 | classifier | The intruder copied a remote administration utility to two other servers over SMB and started it as a service. |

