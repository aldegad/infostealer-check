# Windows Attack Mapping

This document maps the Windows scanner to ATT&CK-style behaviors and defines safe validation patterns.

## Goals

- Keep validation focused on **artifacts and persistence clues**, not real credential theft.
- Use **benign simulations** that create the same kind of traces an infostealer or loader would leave.
- Make every high-signal heuristic traceable to a known behavior family.

## Coverage Map

| Scanner Area | Example ATT&CK Technique | What we look for | Safe validation idea |
|---|---|---|---|
| Suspicious processes | `T1059.001` PowerShell, `T1218` signed binary proxy execution | stealer family names, execution from temp/downloads/public paths | run a benign marker script from `%TEMP%` and confirm it is reported as an unusual process |
| Run keys / Startup folder | `T1547.001` Registry Run Keys / Startup Folder | autoruns from temp paths, encoded PowerShell, script hosts, recent startup items | create a temporary HKCU Run key that points to a marker script in `%APPDATA%`, then remove it |
| Scheduled tasks | `T1053.005` Scheduled Task | script engines, encoded payloads, remote content, user-writable execution paths | register a test task that launches a marker PowerShell command from `%APPDATA%`, then clean it up |
| Recent downloads | `T1105` Ingress Tool Transfer | unsigned/untrusted recent executables and scripts | place a benign `.ps1` or `.cmd` marker in Downloads and verify it shows as a warning |
| Browser extensions | `T1176.001` Browser Extensions | risky permissions, untrusted update URLs, broad host access | load a fixture manifest with `<all_urls>` and `nativeMessaging` from a non-store update URL |
| Network connections | `T1071` application layer protocols, generic C2 ports | established connections to a suspicious port list | create a local test connection on a flagged high port and confirm the log/export behavior |
| Credential store metadata | related follow-on access to browser stores | recent Login Data / Cookies timestamps by profile | modify a fixture profile copy, not the real profile, and confirm metadata reads correctly |
| Defender threat history | defender remediation and residue follow-up | whether detections still have live file residue in user-writable paths | feed fixture resources with and without a live temp artifact and confirm severity changes |
| PowerShell history | `T1059.001` PowerShell command abuse | `IEX`, download cradles, `-enc`, base64, web fetches | append benign marker commands to a copied PSReadLine history fixture and run detection against the copy |

## Test Philosophy

### Use fixtures for pure heuristics

Use JSON fixtures for:

- scheduled task assessment
- browser extension assessment
- Defender detection residue assessment

These should be deterministic and safe to run in CI or on a developer workstation.

### Use local marker artifacts for integration checks

Use local, reversible markers for:

- temp-file residue paths
- Run key persistence
- scheduled tasks
- downloaded marker scripts

Always clean up after the test.

### Avoid real malware behaviors

Do not:

- download credential theft tools
- access real browser secrets
- simulate token theft
- leave persistence behind after tests

The goal is to validate that the scanner recognizes **the traces**, not to emulate full malware.

## Recommended Safe Test Set

Start with these repeatable checks:

1. A benign HKCU Run key pointing to `%APPDATA%\infostealer-check-marker.ps1`
2. A benign scheduled task that launches `powershell.exe -enc ...` with a marker command
3. A fake extension manifest with `nativeMessaging` plus `<all_urls>` and a non-store update URL
4. A Defender fixture with only `CmdLine` resources and successful remediation
5. A Defender fixture with a real temp file path to confirm residual artifact detection

These cover the highest-value Windows heuristics without crossing into unsafe territory.

## External References

- MITRE ATT&CK `T1547.001` Run Keys / Startup Folder
- MITRE ATT&CK `T1053.005` Scheduled Task
- MITRE ATT&CK `T1176.001` Browser Extensions
- Microsoft Defender `Get-MpThreatDetection`
- Red Canary Atomic Red Team for safe, technique-oriented test inspiration
