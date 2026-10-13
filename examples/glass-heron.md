# GLASS HERON: from invoice lures to domain-wide staging

*Synthetic report written to exercise Gleaner. The actor is fictional, and every indicator
uses ranges and names reserved for documentation (RFC 5737, RFC 2606) or digests of
placeholder strings. Nothing below describes a real intrusion.*

## Summary

GLASS HERON is a financially motivated intrusion set that we have tracked since early 2026.
The group sends invoice-themed spearphishing emails with a malicious ISO attachment from
billing[@]example[.]org and lookalike addresses.

## Initial access and execution

The ISO image contains a shortcut file that launches rundll32.exe to load a QakBot DLL from the
mounted volume. When the victim opens the attachment, the shortcut runs a hidden cmd.exe
window and the DLL is copied to C:\ProgramData\Updates\svcupdate.dll.

QakBot contacts its command and control servers over HTTPS at
hxxps://cdn-update.example[.]net/gate.php and 198.51.100[.]23, and downloads additional
payloads, including Cobalt Strike beacons.

## Persistence and privilege escalation

The loader adds a Run key value under
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveSync and creates a scheduled
task named "OneDrive Sync" that executes the DLL every hour.

## Discovery, credential access and lateral movement

The operators enumerate the domain with AdFind and dump credentials from LSASS memory with
Mimikatz. They then move laterally with PsExec, creating a temporary Windows service on each
target host.

On exposed servers, the group also exploited CVE-2021-44228 to obtain initial access.

## Collection and exfiltration

Files from network shares are compressed into password-protected archives with 7-Zip before
being uploaded to 203.0.113[.]77 over the existing command and control channel.

## Indicators of compromise

| Indicator | Type | Description |
|---|---|---|
| hxxps://cdn-update.example[.]net/gate.php | URL | QakBot C2 |
| 198.51.100[.]23 | IPv4 | QakBot C2 |
| 203.0.113[.]77 | IPv4 | Exfiltration server |
| billing[@]example[.]org | E-mail | Phishing sender |
| 1d7b812b382823167c94c15aa73d62905889d8341fc1d2f892fa40f9051b3eec | SHA-256 | QakBot DLL |
| 74ffa40e9a870c0aad199d386c0081924ea570c89b70c398974c613a2ab49c82 | SHA-256 | Cobalt Strike beacon |
| 0e89c5158f2be2617031b91a940c1a84 | MD5 | ISO attachment |

Internal staging host 10.20.30.40 and the DNS resolver 8.8.8.8 appear in the logs but are not
indicators. Background reading: [ATT&CK](https://attack.mitre.org/).
