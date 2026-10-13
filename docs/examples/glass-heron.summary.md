# GLASS HERON: from invoice lures to domain-wide staging

_`examples/glass-heron.md` · sha256 `3ec1377dd534…` · 31 sentences · Gleaner 0.1.0 (iocs, gazetteer, crf, technique-classifier)_

## Indicators (10)

| Type | Value | Exported as | Mentions |
|---|---|---|---:|
| url | `hxxps://cdn-update[.]example[.]net/gate.php` | indicator (documentation range) | 2 |
| ipv4-addr | `198[.]51[.]100[.]23` | indicator (documentation range) | 2 |
| ipv4-addr | `203[.]0[.]113[.]77` | indicator (documentation range) | 2 |
| email-addr | `billing[@]example[.]org` | indicator (documentation range) | 2 |
| md5 | `0e89c5158f2be2617031b91a940c1a84` | indicator | 1 |
| sha256 | `1d7b812b382823167c94c15aa73d62905889d8341fc1d2f892fa40f9051b3eec` | indicator | 1 |
| sha256 | `74ffa40e9a870c0aad199d386c0081924ea570c89b70c398974c613a2ab49c82` | indicator | 1 |
| file-path | `C:\ProgramData\Updates\svcupdate.dll` | artifact | 1 |
| registry-key | `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveSync` | artifact | 1 |
| cve | `CVE-2021-44228` | vulnerability | 1 |

Not exported: 1 benign, 1 internal, 1 reference (references, well-known services, non-routable).

## Named entities (5)

| Type | Name | ATT&CK | Mentions | Found by |
|---|---|---|---:|---|
| malware | QakBot | [S0650](https://attack.mitre.org/software/S0650) | 5 | crf |
| malware | Cobalt Strike | [S0154](https://attack.mitre.org/software/S0154) | 2 | crf |
| tool | AdFind | [S0552](https://attack.mitre.org/software/S0552) | 1 | gazetteer |
| tool | Mimikatz | [S0002](https://attack.mitre.org/software/S0002) | 1 | crf |
| tool | PsExec | [S0029](https://attack.mitre.org/software/S0029) | 1 | crf |

## ATT&CK techniques (10)

| Technique | Tactics | Score | Found by | Evidence |
|---|---|---:|---|---|
| [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory | credential-access | 1.00 | classifier, name | The operators enumerate the domain with AdFind and dump credentials from LSASS memory with Mimikatz. |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003) Windows Service | persistence, privilege-escalation | 1.00 | classifier, name | They then move laterally with PsExec, creating a temporary Windows service on each target host. |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001) Registry Run Keys / Startup Folder | persistence, privilege-escalation | 0.99 | classifier | The loader adds a Run key value under HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveSync and cre… |
| [T1190](https://attack.mitre.org/techniques/T1190) Exploit Public-Facing Application | initial-access | 0.98 | classifier | On exposed servers, the group also exploited CVE-2021-44228 to obtain initial access. |
| [T1218.011](https://attack.mitre.org/techniques/T1218/011) Rundll32 | stealth | 0.97 | classifier | The ISO image contains a shortcut file that launches rundll32.exe to load a QakBot DLL from the mounted volum… |
| [T1566.001](https://attack.mitre.org/techniques/T1566/001) Spearphishing Attachment | initial-access | 0.95 | classifier | The group sends invoice-themed spearphishing emails with a malicious ISO attachment from billing[@]example[.]… |
| [T1204.002](https://attack.mitre.org/techniques/T1204/002) Malicious File | execution | 0.86 | classifier | When the victim opens the attachment, the shortcut runs a hidden cmd.exe window and the DLL is copied to C:\P… |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task | execution, persistence, privilege-escalation | 0.86 | classifier | The loader adds a Run key value under HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveSync and cre… |
| [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer | command-and-control | 0.83 | classifier | QakBot contacts its command and control servers over HTTPS at hxxps://cdn-update.example[.]net/gate.php and 1… |
| [T1569.002](https://attack.mitre.org/techniques/T1569/002) Service Execution | execution | 0.58 | classifier | They then move laterally with PsExec, creating a temporary Windows service on each target host. |

