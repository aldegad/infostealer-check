# Infostealer Check v2 — Architecture Design Document

**Author:** 새미 (Eagle) — Security Reviewer  
**Date:** 2026-04-02  
**Status:** Proposal  
**Based on:** security-threat-intel SKILL.md, check-mac.sh, check-windows.ps1

---

## Table of Contents

1. [Gap Analysis](#1-gap-analysis)
2. [Modular Architecture](#2-modular-architecture)
3. [New Detections Needed](#3-new-detections-needed)
4. [Cross-platform Strategy](#4-cross-platform-strategy)
5. [Output Format](#5-output-format)
6. [Integration Points](#6-integration-points)
7. [Priority Roadmap](#7-priority-roadmap)

---

## 1. Gap Analysis

### P0-P3 Coverage Matrix

The SKILL.md knowledge base defines 4 priority tiers of detection. The current v1 scanners (`check-mac.sh`, `check-windows.ps1`) cover only a subset.

#### P0 — Must-Have Detection (5 items)

| # | P0 Checklist Item | macOS v1 | Windows v1 | Gap |
|---|-------------------|----------|------------|-----|
| 1 | Suspicious process name/path matching | **Covered** (Section 2) — keyword list + unusual path check | **Covered** (Section 2) — keyword list + Temp folder check | Pattern list is static; no hash-based or behavioral matching |
| 2 | Auto-start registration (LaunchAgent / Registry Run) | **Covered** (Section 3) — LaunchAgents/Daemons with known-good prefix exclusion | **Covered** (Section 3) — Run/RunOnce keys + Startup folder | No detection of DLL search-order hijacking or COM object persistence |
| 3 | Browser credential DB abnormal access | **Covered** (Section 8) — `lsof` on Login Data/Cookies, non-Chrome process check | **Partial** (Section 8) — attempts module-based check but unreliable on Windows | Windows implementation uses `Get-Process.Modules` which does not reliably detect file handle access; needs `handle.exe` or ETW |
| 4 | Suspicious network connections (C2 ports, webhooks) | **Covered** (Section 7) — port list + Discord/Telegram/Pastebin grep | **Covered** (Section 7) — port list via `Get-NetTCPConnection` | No DNS-level detection, no domain reputation check, no TLS certificate analysis |
| 5 | Recently installed unsigned apps | **Covered** (Section 5) — `codesign -v` on /Applications + Downloads scan | **Covered** (Section 5) — `Get-AuthenticodeSignature` on Downloads | Only checks /Applications and ~/Downloads; misses apps installed to ~/Library, /usr/local, or AppData |

**P0 Result: 4/5 fully covered, 1/5 partial (browser DB access on Windows)**

#### P1 — Recommended Detection (5 items)

| # | P1 Checklist Item | macOS v1 | Windows v1 | Gap |
|---|-------------------|----------|------------|-----|
| 1 | Browser extension permission audit | **Covered** (Section 6) — Chrome manifest.json high-risk permission check | **Covered** (Section 6) — same approach | Only Chrome; no Firefox, Edge, Brave, Arc support |
| 2 | Scheduled task/cron tampering | **Partial** (Section 9) — `crontab -l` + /etc/periodic mtime check | **Covered** (Section 4) — `Get-ScheduledTask` with suspicious command patterns | macOS misses `at` jobs, `launchd` overrides, and doesn't inspect cron job content for malicious patterns |
| 3 | PowerShell/bash history suspicious commands | **Not covered** — no bash/zsh history analysis | **Covered** (Section 10) — PSReadLine history with download/encoded command detection | macOS completely misses shell history analysis for `curl`, `osascript`, `security` command abuse |
| 4 | Security software status (real-time protection) | **Not covered** — no XProtect/MRT/Gatekeeper status check | **Covered** (Section 9) — `Get-MpComputerStatus` for Defender real-time protection | macOS has no equivalent check for XProtect/Gatekeeper enabled status |
| 5 | Keychain/credential manager access log | **Partial** (Section 8) — `log show` for securityd subsystem | **Not covered** — no Credential Manager or DPAPI access monitoring | Both platforms have weak implementation; log query is slow and unreliable |

**P1 Result: 1/5 fully covered on both platforms, 2/5 partial, 2/5 missing on one or both**

#### P2 — Advanced Detection (5 items)

| # | P2 Checklist Item | macOS v1 | Windows v1 | Gap |
|---|-------------------|----------|------------|-----|
| 1 | DNS query log (DGA domain detection) | **Not covered** | **Not covered** | No DNS cache or query log analysis on either platform |
| 2 | Filesystem timeline analysis (MAC times) | **Not covered** | **Not covered** | No file timeline reconstruction for forensic analysis |
| 3 | Memory dump analysis | **Not covered** | **Not covered** | Out of scope for shell scripts; requires specialized tooling |
| 4 | YARA rule-based file scanning | **Not covered** | **Not covered** | No YARA integration despite SKILL.md referencing it |
| 5 | Network traffic payload analysis | **Not covered** | **Not covered** | Requires packet capture; impractical for a lightweight scanner |

**P2 Result: 0/5 covered. All advanced detection missing.**

#### P3 — Hard-to-Detect (4 items, acknowledged limitations)

| # | P3 Item | Feasibility |
|---|---------|-------------|
| 1 | Self-deleting infostealers | Can detect residual artifacts (empty dirs, dangling plist refs) |
| 2 | Process hollowing/injection | Requires memory analysis — out of scope for shell scripts |
| 3 | In-memory / fileless execution | ETW on Windows, Endpoint Security Framework on macOS — requires privileged agent |
| 4 | Timestomping | Can cross-reference birth time vs modify time on APFS/NTFS |

**P3 Result: Acknowledged as detection limits. Items 1 and 4 have partial workarounds we should implement.**

### MITRE ATT&CK Technique Coverage

| ATT&CK ID | Technique | v1 Coverage | Notes |
|------------|-----------|-------------|-------|
| T1566.001 | Spearphishing Attachment | **Partial** | Checks Downloads for DMG/PKG but not ISO/ZIP content |
| T1566.002 | Spearphishing Link | **Not covered** | No browser history or DNS log analysis |
| T1189 | Drive-by Compromise | **Not covered** | No browser cache or redirect analysis |
| T1204.002 | Malicious File Execution | **Partial** | Code signing check, but no execution history correlation |
| T1059.001 | PowerShell | **Windows only** | PSReadLine history grep |
| T1059.002 | AppleScript | **Partial** | Process check for `osascript.*password` pattern only |
| T1059.004 | Unix Shell | **Partial** | Process check for `curl.*pastebin` patterns, no history |
| T1204.001 | ClickFix / Malicious Link | **Not covered** | No clipboard history or recent terminal paste detection |
| T1555.001 | Keychain | **Partial** | Log subsystem query but unreliable |
| T1555.003 | Browser Credentials | **Covered** | lsof-based non-Chrome access detection |
| T1539 | Steal Web Session Cookie | **Covered** | Same mechanism as credential DB check |
| T1552.001 | Credentials in Files | **Not covered** | No .env, credentials.json, AWS config scanning |
| T1056.001 | Keylogging | **Partial** | TCC Accessibility check on macOS only |
| T1005 | Data from Local System | **Not covered** | No crypto wallet path or SSH key access monitoring |
| T1115 | Clipboard Data | **Not covered** | No clipboard monitoring detection |
| T1113 | Screen Capture | **Not covered** | No screen recording permission abuse detection |
| T1567.001 | Exfil to Code Repository | **Not covered** | No abnormal git push detection |
| T1567.002 | Exfil to Cloud Storage | **Not covered** | No cloud storage upload monitoring |
| T1567.004 | Exfil via Webhook | **Partial** | Network connection grep for Discord/Telegram |
| T1041 | Exfil Over C2 | **Partial** | Suspicious port check only |
| T1543.001 | Launch Agent (macOS) | **Covered** | Plist enumeration with recency filter |
| T1547.001 | Registry Run Keys | **Covered** | Run/RunOnce + suspicious path patterns |
| T1053.005 | Scheduled Task | **Covered** | Both platforms |
| T1176 | Browser Extensions | **Covered** | Chrome only |

**Overall: 7/24 techniques fully covered, 9/24 partial, 8/24 not covered at all.**

---

## 2. Modular Architecture

### Design Principles

1. **One module per MITRE technique** — each detection maps to exactly one ATT&CK ID
2. **Platform adapters** — shared detection logic with OS-specific implementations
3. **Structured output** — every module emits the same JSON schema
4. **Plugin architecture** — new modules can be added without touching core code
5. **Dependency-free core** — bash/PowerShell only; optional dependencies for advanced modules

### Module Structure

```
infostealer-check/
├── core/
│   ├── runner.sh                  # macOS orchestrator
│   ├── runner.ps1                 # Windows orchestrator
│   ├── output.sh                  # JSON output formatter (macOS)
│   ├── output.ps1                 # JSON output formatter (Windows)
│   └── config.json                # Detection thresholds, exclusion lists
│
├── modules/
│   ├── initial-access/
│   │   ├── T1566.001-phishing-attachment.sh    # macOS
│   │   ├── T1566.001-phishing-attachment.ps1   # Windows
│   │   ├── T1204.002-malicious-file.sh
│   │   └── T1204.002-malicious-file.ps1
│   │
│   ├── execution/
│   │   ├── T1059.001-powershell.ps1            # Windows only
│   │   ├── T1059.002-applescript.sh            # macOS only
│   │   ├── T1059.004-unix-shell.sh             # macOS only
│   │   └── T1204.001-clickfix.sh               # macOS (+ .ps1 for Windows)
│   │
│   ├── credential-access/
│   │   ├── T1555.001-keychain.sh               # macOS only
│   │   ├── T1555.003-browser-creds.sh
│   │   ├── T1555.003-browser-creds.ps1
│   │   ├── T1539-session-cookie.sh
│   │   ├── T1539-session-cookie.ps1
│   │   ├── T1552.001-creds-in-files.sh
│   │   ├── T1552.001-creds-in-files.ps1
│   │   └── T1056.001-keylogging.sh             # macOS TCC
│   │
│   ├── collection/
│   │   ├── T1005-local-data.sh
│   │   ├── T1005-local-data.ps1
│   │   ├── T1115-clipboard.sh
│   │   ├── T1115-clipboard.ps1
│   │   └── T1113-screen-capture.sh             # macOS TCC
│   │
│   ├── exfiltration/
│   │   ├── T1567.004-webhook-exfil.sh
│   │   ├── T1567.004-webhook-exfil.ps1
│   │   ├── T1041-c2-channel.sh
│   │   └── T1041-c2-channel.ps1
│   │
│   ├── persistence/
│   │   ├── T1543.001-launch-agent.sh           # macOS only
│   │   ├── T1547.001-registry-run.ps1          # Windows only
│   │   ├── T1053.005-scheduled-task.sh
│   │   ├── T1053.005-scheduled-task.ps1
│   │   └── T1176-browser-extensions.sh         # cross-platform logic
│   │
│   └── defense-evasion/
│       ├── T1070.004-file-deletion-residue.sh   # P3 partial
│       ├── T1070.006-timestomping.sh            # P3 partial
│       └── T1070.006-timestomping.ps1
│
├── signatures/
│   ├── process-names.json          # Known infostealer process names
│   ├── file-hashes.json            # Known bad file hashes (updated via CI)
│   ├── network-iocs.json           # C2 IPs, domains, ports
│   └── yara/                       # Optional YARA rules
│       ├── atomic-stealer.yar
│       ├── lumma.yar
│       └── redline.yar
│
├── docs/
│   └── v2-architecture.md          # This document
│
├── check-mac.sh                    # v1 legacy (kept for compatibility)
├── check-windows.ps1               # v1 legacy (kept for compatibility)
└── README.md
```

### Module Interface Contract

Every module must implement the following interface:

**macOS (bash):**

```bash
#!/bin/bash
# Module: T1555.003 — Credentials from Web Browsers
# Platform: macOS
# Priority: P0

MODULE_ID="T1555.003"
MODULE_NAME="Browser Credential Access"
MODULE_PRIORITY="P0"

# Source the output helper
source "$(dirname "$0")/../../core/output.sh"

run_check() {
    local findings=()
    
    # ... detection logic ...
    
    if [ ${#findings[@]} -gt 0 ]; then
        emit_finding "$MODULE_ID" "$MODULE_NAME" "high" \
            "Non-Chrome process accessing credential database" \
            "$evidence" \
            "Kill the process, change all browser-saved passwords, revoke active sessions"
    else
        emit_clean "$MODULE_ID" "$MODULE_NAME"
    fi
}

run_check
```

**Windows (PowerShell):**

```powershell
# Module: T1555.003 — Credentials from Web Browsers
# Platform: Windows
# Priority: P0

$ModuleId = "T1555.003"
$ModuleName = "Browser Credential Access"
$ModulePriority = "P0"

. "$PSScriptRoot\..\..\core\output.ps1"

function Invoke-Check {
    $findings = @()
    
    # ... detection logic ...
    
    if ($findings.Count -gt 0) {
        Emit-Finding -TechniqueId $ModuleId -Name $ModuleName -Severity "High" `
            -Description "Non-Chrome process accessing credential database" `
            -Evidence $evidence `
            -Remediation "Kill the process, change all browser-saved passwords, revoke active sessions"
    } else {
        Emit-Clean -TechniqueId $ModuleId -Name $ModuleName
    }
}

Invoke-Check
```

### Runner Orchestration

The runner discovers and executes all modules:

```bash
# core/runner.sh (simplified)
#!/bin/bash

MODULES_DIR="$(dirname "$0")/../modules"
RESULTS=()

# Discover platform-appropriate modules
for module in $(find "$MODULES_DIR" -name "*.sh" -type f | sort); do
    echo "[*] Running: $(basename $module .sh)"
    result=$(bash "$module" 2>/dev/null)
    RESULTS+=("$result")
done

# Aggregate and output
aggregate_results "${RESULTS[@]}"
```

---

## 3. New Detections Needed

### By Infostealer Family

#### macOS Families

| Family | Missing Detection | Proposed Module | Priority |
|--------|-------------------|-----------------|----------|
| **Atomic Stealer (AMOS)** | AppleScript password prompt social engineering — `osascript -e 'display dialog "Enter password"'` in process tree | `T1059.002-applescript.sh`: grep running processes and recent shell history for `osascript` + `display dialog` + `password` patterns; check for DMG files in Downloads that contain unsigned .app bundles | P0 |
| **Atomic Stealer (AMOS)** | Keychain export via `security` CLI — `security find-generic-password`, `security dump-keychain` | `T1555.001-keychain.sh`: check bash history and process list for `security` CLI credential extraction commands | P0 |
| **Poseidon Stealer** | Google Ads malvertising landing — browser history contains SEO-poisoned download URLs | `T1566.002-phishing-link.sh`: parse Chrome/Safari history DB for known malvertising domain patterns (e.g., fake-software-download domains) | P1 |
| **Banshee Stealer** | XProtect evasion — checks if XProtect definitions are outdated or tampered | `defense-evasion/xprotect-status.sh`: verify XProtect version, check `/Library/Apple/System/Library/CoreServices/XProtect.bundle` integrity | P1 |
| **Banshee Stealer** | Targets 100+ browser extensions — broader extension enumeration needed | `T1176-browser-extensions.sh`: extend to Firefox, Brave, Arc, Edge extension directories | P1 |
| **Cuckoo Stealer** | Fake music converter app — specific app name patterns, SSH key exfiltration | `T1005-local-data.sh`: check for recent access to `~/.ssh/`, iCloud Notes database, and crypto wallet paths | P0 |
| **MetaStealer** | DMG social engineering — unsigned DMG with embedded Mach-O in non-standard location | `T1204.002-malicious-file.sh`: scan recent DMG mounts for unsigned executables, check `diskutil list` for recently mounted DMGs | P1 |

#### Windows Families

| Family | Missing Detection | Proposed Module | Priority |
|--------|-------------------|-----------------|----------|
| **RedLine** | VPN credential theft — targets NordVPN, ProtonVPN, OpenVPN config files | `T1552.001-creds-in-files.ps1`: scan for access to VPN config directories, check if VPN credential files were recently read | P0 |
| **RedLine** | Game client credentials — Steam, Discord tokens, Telegram session files | `T1552.001-creds-in-files.ps1`: check `%APPDATA%\discord\Local Storage`, Steam `ssfn*` files, Telegram `tdata` directory access | P1 |
| **Raccoon v2** | Telegram C2 communication — bot API calls from non-Telegram processes | `T1041-c2-channel.ps1`: detect `api.telegram.org` connections from processes that are not `Telegram.exe` | P0 |
| **Vidar** | Configuration-based targeting — downloads config from C2 specifying what to steal | `T1041-c2-channel.ps1`: detect processes making HTTP requests immediately after launch to suspicious domains | P1 |
| **Vidar** | 2FA app data theft — targets Authy, Google Authenticator desktop data | `T1005-local-data.ps1`: monitor access to Authy/2FA app data directories | P1 |
| **Lumma Stealer** | DLL sideloading — places malicious DLL alongside legitimate executable | `T1574.002-dll-sideload.ps1`: scan for recently created DLLs in legitimate application directories that don't match expected signatures | P0 |
| **Lumma Stealer** | Anti-analysis / sandbox detection — checks mouse movement, screen resolution | Not directly detectable; flag as P3 limitation | P3 |
| **StealC** | Modular data collection — downloads additional modules after initial execution | `T1105-remote-file-copy.ps1`: detect processes that download and execute additional payloads post-launch | P2 |
| **Rhadamanthys** | OCR-based seed phrase extraction from screenshots and images | `T1113-screen-capture.ps1`: detect screen capture API usage by non-standard processes, check for recently created image files in temp directories | P1 |
| **Rhadamanthys** | Advanced evasion — process hollowing, Heaven's Gate | P3 — requires kernel-level or EDR integration | P3 |
| **ACR Stealer** | Dead Drop Resolver — fetches C2 address from legitimate services (Steam, Google Forms) | `T1102-web-service.ps1`: detect connections to Steam community profiles, Google Forms, Pastebin from non-browser processes | P1 |

### By MITRE Technique (Cross-family)

| New Module | Technique | What It Detects | Platform |
|------------|-----------|-----------------|----------|
| `T1552.001-creds-in-files` | Credentials in Files | `.env`, `credentials.json`, AWS `~/.aws/credentials`, SSH keys, VPN configs — checks recent access or modification by non-standard processes | Both |
| `T1005-local-data` | Data from Local System | Crypto wallet directories (`~/Library/Application Support/Bitcoin/`, `%APPDATA%\Ethereum\`), SSH keys, password manager vaults | Both |
| `T1115-clipboard` | Clipboard Data | Detect clipboard monitoring processes, check for clipboard history tools used maliciously | Both |
| `T1113-screen-capture` | Screen Capture | macOS: TCC screen recording permissions granted to suspicious apps; Windows: processes using screen capture APIs | Both |
| `T1059.002-applescript` | AppleScript Abuse | Detect `osascript` invocations that display fake password dialogs | macOS |
| `T1574.002-dll-sideload` | DLL Side-Loading | Recently placed DLLs in legitimate app directories with mismatched signatures | Windows |
| `T1102-web-service` | Web Service (Dead Drop) | Non-browser processes connecting to Steam, Google Forms, Pastebin | Windows |

---

## 4. Cross-platform Strategy

### Architecture Layers

```
┌─────────────────────────────────────────────────┐
│                   Runner Layer                   │
│         runner.sh (macOS) / runner.ps1 (Win)     │
├─────────────────────────────────────────────────┤
│                  Module Layer                    │
│   T1555.003.sh  T1543.001.sh  T1059.001.ps1    │
│   Each module = 1 technique, 1 platform          │
├─────────────────────────────────────────────────┤
│               Shared Logic Layer                 │
│              config.json (thresholds,            │
│          exclusions, IOC signatures)             │
├─────────────────────────────────────────────────┤
│                 Output Layer                     │
│        Unified JSON schema per finding           │
└─────────────────────────────────────────────────┘
```

### What Can Be Shared

| Component | Shared? | How |
|-----------|---------|-----|
| Process name patterns | **Yes** | `signatures/process-names.json` — same stealer names across platforms |
| Network IOCs (ports, domains) | **Yes** | `signatures/network-iocs.json` — C2 ports and webhook domains are platform-agnostic |
| Browser extension analysis | **Yes** | Same `manifest.json` parsing logic, different filesystem paths |
| Chrome credential DB detection | **Mostly** | Same DB file names (`Login Data`, `Cookies`), different access detection mechanisms |
| File hash IOCs | **Yes** | `signatures/file-hashes.json` — SHA256 hashes are universal |
| YARA rules | **Yes** | Platform-agnostic binary signatures |
| Output JSON schema | **Yes** | Identical structure on both platforms |
| Detection thresholds | **Yes** | `config.json` — recency windows, severity mappings |

### What Must Differ

| Component | macOS | Windows |
|-----------|-------|---------|
| Process enumeration | `ps aux`, `lsof` | `Get-Process`, `Get-NetTCPConnection` |
| Auto-start detection | LaunchAgent/Daemon plist parsing | Registry Run keys, Startup folder, Services |
| Code signing verification | `codesign -v` | `Get-AuthenticodeSignature` |
| Privilege/permission check | TCC database (`sqlite3`) | ACL queries, service permissions |
| Shell history | `~/.zsh_history`, `~/.bash_history` | PSReadLine `ConsoleHost_history.txt` |
| Security software status | XProtect, Gatekeeper, MRT | Windows Defender (`Get-MpComputerStatus`) |
| File handle detection | `lsof` | `handle.exe` (Sysinternals) or ETW |
| Keychain/credential store | `security` CLI, securityd logs | DPAPI, Credential Manager |

### Shared Configuration Format

```json
{
  "version": "2.0.0",
  "scan_window_days": 30,
  "severity_thresholds": {
    "critical": ["unsigned_app_running", "credential_db_non_browser_access"],
    "high": ["suspicious_process", "c2_port_connection", "malicious_extension"],
    "medium": ["recent_launch_agent", "suspicious_scheduled_task"],
    "low": ["unusual_path_process", "recent_download"]
  },
  "exclusions": {
    "processes": ["claude", "codex", "node", "bun", "vite", "docker"],
    "launch_agents": ["com.apple.*", "com.google.*", "com.microsoft.*", "com.docker.*"],
    "network": {
      "allowed_ports": [80, 443, 8080, 8443],
      "allowed_domains": ["*.apple.com", "*.google.com", "*.microsoft.com"]
    }
  }
}
```

---

## 5. Output Format

### JSON Schema

Every module emits findings in this structure. The runner aggregates them into a single report.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "scan_metadata": {
      "type": "object",
      "properties": {
        "tool_version": { "type": "string", "example": "2.0.0" },
        "scan_id": { "type": "string", "format": "uuid" },
        "timestamp": { "type": "string", "format": "date-time" },
        "platform": { "type": "string", "enum": ["macOS", "Windows"] },
        "os_version": { "type": "string" },
        "hostname": { "type": "string" },
        "user": { "type": "string" },
        "modules_executed": { "type": "integer" },
        "scan_duration_seconds": { "type": "number" }
      }
    },
    "summary": {
      "type": "object",
      "properties": {
        "total_findings": { "type": "integer" },
        "critical": { "type": "integer" },
        "high": { "type": "integer" },
        "medium": { "type": "integer" },
        "low": { "type": "integer" },
        "info": { "type": "integer" },
        "clean_modules": { "type": "integer" },
        "risk_score": {
          "type": "integer",
          "minimum": 0,
          "maximum": 100,
          "description": "Weighted score: critical=25, high=10, medium=5, low=1"
        }
      }
    },
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["technique_id", "technique_name", "severity", "description"],
        "properties": {
          "technique_id": {
            "type": "string",
            "pattern": "^T[0-9]{4}(\\.[0-9]{3})?$",
            "description": "MITRE ATT&CK technique ID",
            "example": "T1555.003"
          },
          "technique_name": {
            "type": "string",
            "example": "Credentials from Web Browsers"
          },
          "tactic": {
            "type": "string",
            "enum": [
              "initial-access", "execution", "persistence",
              "credential-access", "collection", "exfiltration",
              "defense-evasion"
            ]
          },
          "severity": {
            "type": "string",
            "enum": ["critical", "high", "medium", "low", "info"]
          },
          "description": {
            "type": "string",
            "example": "Non-Chrome process 'python3' (PID 4821) has open handle on Chrome Login Data"
          },
          "evidence": {
            "type": "object",
            "properties": {
              "process_name": { "type": "string" },
              "process_id": { "type": "integer" },
              "process_path": { "type": "string" },
              "file_path": { "type": "string" },
              "network_endpoint": { "type": "string" },
              "registry_key": { "type": "string" },
              "command_line": { "type": "string" },
              "raw_output": { "type": "string" }
            }
          },
          "related_families": {
            "type": "array",
            "items": { "type": "string" },
            "description": "Known infostealer families that use this technique",
            "example": ["Atomic Stealer", "Poseidon", "RedLine"]
          },
          "remediation": {
            "type": "object",
            "properties": {
              "immediate": {
                "type": "array",
                "items": { "type": "string" },
                "example": [
                  "Kill the suspicious process: kill -9 4821",
                  "Change all browser-saved passwords immediately"
                ]
              },
              "follow_up": {
                "type": "array",
                "items": { "type": "string" },
                "example": [
                  "Run Malwarebytes full scan",
                  "Revoke all active Google sessions",
                  "Enable 2FA on all accounts"
                ]
              },
              "reference_urls": {
                "type": "array",
                "items": { "type": "string", "format": "uri" }
              }
            }
          },
          "false_positive_notes": {
            "type": "string",
            "description": "Known legitimate reasons this might trigger",
            "example": "Password managers like 1Password may legitimately access Chrome credential stores"
          },
          "first_seen": {
            "type": "string",
            "format": "date-time",
            "description": "Earliest timestamp of the suspicious activity"
          }
        }
      }
    },
    "system_info": {
      "type": "object",
      "description": "Collected system context for incident response",
      "properties": {
        "security_software": {
          "type": "object",
          "properties": {
            "realtime_protection": { "type": "boolean" },
            "last_full_scan": { "type": "string", "format": "date-time" },
            "definitions_version": { "type": "string" }
          }
        },
        "active_network_connections": { "type": "integer" },
        "login_items_count": { "type": "integer" },
        "browser_extensions_count": { "type": "integer" }
      }
    }
  }
}
```

### Example Output

```json
{
  "scan_metadata": {
    "tool_version": "2.0.0",
    "scan_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "timestamp": "2026-04-02T14:30:00+09:00",
    "platform": "macOS",
    "os_version": "15.4 (24E5238a)",
    "hostname": "dev-macbook",
    "user": "soohong",
    "modules_executed": 18,
    "scan_duration_seconds": 12.4
  },
  "summary": {
    "total_findings": 3,
    "critical": 1,
    "high": 1,
    "medium": 1,
    "low": 0,
    "info": 0,
    "clean_modules": 15,
    "risk_score": 40
  },
  "findings": [
    {
      "technique_id": "T1555.003",
      "technique_name": "Credentials from Web Browsers",
      "tactic": "credential-access",
      "severity": "critical",
      "description": "Non-Chrome process 'python3' (PID 4821) has open handle on Chrome Login Data",
      "evidence": {
        "process_name": "python3",
        "process_id": 4821,
        "process_path": "/private/tmp/.hidden/python3",
        "file_path": "~/Library/Application Support/Google/Chrome/Default/Login Data",
        "raw_output": "python3 4821 user 12r REG 1,18 0t1048576 /Users/user/Library/Application Support/Google/Chrome/Default/Login Data"
      },
      "related_families": ["Atomic Stealer", "Poseidon", "Banshee"],
      "remediation": {
        "immediate": [
          "Kill the process: kill -9 4821",
          "Delete the suspicious binary: rm /private/tmp/.hidden/python3",
          "Change all Chrome-saved passwords NOW"
        ],
        "follow_up": [
          "Run Malwarebytes full system scan",
          "Revoke all active Google sessions at myaccount.google.com/device-activity",
          "Enable 2FA on all accounts that had saved passwords",
          "Check Chrome Sync for unauthorized devices"
        ],
        "reference_urls": [
          "https://attack.mitre.org/techniques/T1555/003/"
        ]
      },
      "false_positive_notes": "Password managers (1Password, Bitwarden) may legitimately access Chrome credential stores. Development tools testing browser integration may also trigger this.",
      "first_seen": "2026-04-02T14:29:45+09:00"
    }
  ]
}
```

### Output Modes

The runner supports multiple output formats:

| Mode | Flag | Use Case |
|------|------|----------|
| Terminal (colored text) | `--format text` (default) | Interactive use, same UX as v1 |
| JSON | `--format json` | Programmatic consumption, SIEM ingestion |
| JSON (pretty) | `--format json-pretty` | Human-readable JSON |
| SARIF | `--format sarif` | IDE integration (VS Code, GitHub Code Scanning) |
| CSV | `--format csv` | Spreadsheet analysis |

---

## 6. Integration Points

### YARA Rules

SKILL.md references `github.com/Yara-Rules/rules` for malware signatures.

**Integration approach:**

```bash
# Optional YARA scanning module (requires yara binary)
# T1588.001-yara-scan.sh

if command -v yara &>/dev/null; then
    RULES_DIR="$(dirname "$0")/../../signatures/yara"
    
    # Scan recently modified files in suspicious locations
    SCAN_DIRS=(
        "$HOME/Downloads"
        "/tmp"
        "/private/var/tmp"
        "$HOME/Library/Application Support"
    )
    
    for dir in "${SCAN_DIRS[@]}"; do
        find "$dir" -mtime -7 -type f -size +1k -size -50M 2>/dev/null | while read -r file; do
            yara -r "$RULES_DIR/*.yar" "$file" 2>/dev/null | while read -r match; do
                emit_finding "YARA" "YARA Rule Match" "high" \
                    "File matches known malware signature: $match" \
                    "$file" \
                    "Quarantine the file and run full AV scan"
            done
        done
    done
else
    emit_info "YARA" "yara binary not found — skipping signature scan (install: brew install yara)"
fi
```

**Custom YARA rules for known families:**

```yara
// signatures/yara/atomic-stealer.yar
rule AtomicStealer_AppleScript_Prompt {
    meta:
        description = "Atomic Stealer fake password dialog via AppleScript"
        family = "AMOS"
        technique = "T1059.002"
        severity = "critical"
    strings:
        $prompt1 = "display dialog" ascii
        $prompt2 = "password" ascii nocase
        $prompt3 = "keychain" ascii nocase
        $osascript = "osascript" ascii
    condition:
        $osascript and $prompt1 and ($prompt2 or $prompt3)
}

rule Lumma_DLL_Sideload {
    meta:
        description = "Lumma Stealer DLL sideloading indicator"
        family = "Lumma"
        technique = "T1574.002"
        severity = "high"
    strings:
        $s1 = "steam_api64.dll" ascii nocase
        $s2 = "user32.dll" ascii nocase
        $import = "LummaC" ascii nocase
    condition:
        ($s1 or $s2) and $import
}
```

### Sigma Rules

SKILL.md references `github.com/SigmaHQ/sigma` for log-based detection.

**Integration approach:** Generate Sigma-compatible log output that can be ingested by SIEMs.

```yaml
# sigma/infostealer-check-findings.yml
# Auto-generated from infostealer-check v2 scan results

title: Infostealer Check Scanner Finding
id: a1b2c3d4-5678-90ab-cdef-1234567890ab
status: stable
description: Finding from infostealer-check v2 scanner
author: ANTTIME
date: 2026/04/02
logsource:
    product: infostealer-check
    service: scanner
detection:
    selection:
        severity:
            - critical
            - high
    condition: selection
level: high
tags:
    - attack.credential_access
    - attack.t1555.003
```

**Sigma rule export from scan results:**

```bash
# Convert JSON findings to Sigma-compatible events
jq -r '.findings[] | {
    timestamp: .first_seen,
    technique_id: .technique_id,
    technique_name: .technique_name,
    severity: .severity,
    description: .description,
    evidence: .evidence
}' report.json > sigma-events.jsonl
```

### Semgrep

SKILL.md references `semgrep --config auto .` for code-level scanning.

**Integration approach:** Use Semgrep for scanning scripts, configs, and source files for embedded credentials or suspicious patterns — complementary to our runtime detection.

```yaml
# .semgrep/infostealer-indicators.yml
rules:
  - id: hardcoded-webhook-url
    pattern: |
      "https://discord.com/api/webhooks/$WEBHOOK_ID/$TOKEN"
    message: "Hardcoded Discord webhook URL — potential data exfiltration endpoint"
    languages: [python, javascript, bash]
    severity: ERROR
    metadata:
      technique: T1567.004
      
  - id: suspicious-credential-access
    patterns:
      - pattern: open("$PATH")
      - metavariable-regex:
          metavariable: $PATH
          regex: ".*(Login Data|Cookies|key3\.db|logins\.json).*"
    message: "Direct file access to browser credential database"
    languages: [python]
    severity: ERROR
    metadata:
      technique: T1555.003
```

### SIEM / SOC Integration

```
┌──────────────┐     JSON      ┌──────────────┐
│ infostealer  │───────────────▶│   Filebeat   │
│   check v2   │  report.json  │   / Fluentd  │
└──────────────┘               └──────┬───────┘
                                      │
                               ┌──────▼───────┐
                               │  Elastic /   │
                               │  Splunk /    │
                               │  Sentinel    │
                               └──────┬───────┘
                                      │
                               ┌──────▼───────┐
                               │  Sigma Rule  │
                               │  Matching    │
                               └──────┬───────┘
                                      │
                               ┌──────▼───────┐
                               │  Alert /     │
                               │  Dashboard   │
                               └──────────────┘
```

---

## 7. Priority Roadmap

### Phase 0: Foundation (Week 1-2) — P0

**Goal:** Modularize existing v1 detection and fix known gaps.

| Task | Deliverable | Effort |
|------|-------------|--------|
| Create module runner framework | `core/runner.sh`, `core/runner.ps1` | 2 days |
| Create JSON output formatter | `core/output.sh`, `core/output.ps1` | 1 day |
| Extract v1 process detection into module | `T1204.002-malicious-file.*` | 0.5 day |
| Extract v1 auto-start detection | `T1543.001-launch-agent.sh`, `T1547.001-registry-run.ps1` | 0.5 day |
| Extract v1 browser credential check | `T1555.003-browser-creds.*` | 0.5 day |
| Extract v1 network detection | `T1041-c2-channel.*`, `T1567.004-webhook-exfil.*` | 0.5 day |
| Fix Windows browser DB detection | Use `handle.exe` or file timestamp correlation instead of module enumeration | 1 day |
| Add shared IOC signature files | `signatures/process-names.json`, `signatures/network-iocs.json` | 1 day |
| Add macOS shell history analysis | `T1059.004-unix-shell.sh` with zsh/bash history parsing | 1 day |
| Add credential file scanning | `T1552.001-creds-in-files.*` for .env, AWS, SSH, VPN configs | 1 day |
| Backward compatibility wrapper | `check-mac.sh` and `check-windows.ps1` call the new runner and format as text | 0.5 day |

**Total: ~10 days**

### Phase 1: Family-Specific Detection (Week 3-4) — P1

**Goal:** Add detections specific to the 12 known infostealer families.

| Task | Deliverable | Effort |
|------|-------------|--------|
| Atomic Stealer AppleScript detection | `T1059.002-applescript.sh` | 1 day |
| Atomic Stealer Keychain abuse | `T1555.001-keychain.sh` | 1 day |
| Lumma DLL sideloading detection | `T1574.002-dll-sideload.ps1` | 1 day |
| Rhadamanthys screen capture detection | `T1113-screen-capture.*` | 1 day |
| ACR Stealer dead drop resolver | `T1102-web-service.ps1` | 1 day |
| Crypto wallet path monitoring | `T1005-local-data.*` | 1 day |
| Multi-browser extension support | Extend `T1176-browser-extensions.*` for Firefox, Edge, Brave, Arc | 1 day |
| macOS security software status | XProtect version, Gatekeeper status, SIP check | 1 day |
| ClickFix / clipboard paste detection | `T1204.001-clickfix.*` | 1 day |
| Raccoon Telegram C2 detection | Extend `T1041-c2-channel.*` for Telegram API patterns | 0.5 day |

**Total: ~10 days**

### Phase 2: Advanced Detection (Week 5-8) — P2

**Goal:** Add forensic-level detection capabilities.

| Task | Deliverable | Effort |
|------|-------------|--------|
| DNS cache/query log analysis | `dns-analysis.*` — DGA domain detection via entropy scoring | 3 days |
| YARA rule integration | Optional `yara-scan.*` module + initial rule set for 12 families | 3 days |
| Filesystem timeline analysis | `timeline.*` — MAC time correlation for suspicious activity windows | 2 days |
| SARIF output format | IDE/GitHub integration support | 1 day |
| Sigma-compatible event export | Log format for SIEM ingestion | 1 day |
| Semgrep custom rule pack | `.semgrep/infostealer-indicators.yml` | 1 day |
| CI/CD: automated IOC signature updates | GitHub Action to pull latest IOCs from threat intel feeds | 2 days |
| False positive tuning | Config-based exclusion system with community-contributed allowlists | 2 days |

**Total: ~15 days**

### Phase 3: Limits & Hardening (Week 9-12) — P3

**Goal:** Address detection limitations and harden the tool.

| Task | Deliverable | Effort |
|------|-------------|--------|
| Self-deletion residue detection | Check for orphaned plist refs, empty staging directories, dangling symlinks | 2 days |
| Timestomping detection | Birth time vs modification time anomalies on APFS/NTFS | 2 days |
| Fileless execution indicators | ETW consumer on Windows, Endpoint Security Framework on macOS (requires privileged daemon) | 5 days |
| Report encryption | Encrypt output with user-provided public key for safe transmission | 1 day |
| Script self-integrity check | Embedded SHA256 hash verification to prevent tampering | 1 day |
| Localization | Korean/English/Japanese output support | 2 days |
| Performance profiling | Ensure full scan completes in under 30 seconds | 1 day |
| Documentation & threat model | Updated README, threat model diagram, contribution guide | 2 days |

**Total: ~16 days**

### Milestone Summary

| Phase | Timeline | Findings Coverage | Technique Coverage |
|-------|----------|-------------------|--------------------|
| v1 (current) | Done | P0: 80%, P1: 30% | 7/24 full, 9/24 partial |
| v2 Phase 0 | Week 1-2 | P0: 100%, P1: 50% | 12/24 full, 8/24 partial |
| v2 Phase 1 | Week 3-4 | P0: 100%, P1: 90% | 18/24 full, 4/24 partial |
| v2 Phase 2 | Week 5-8 | P0: 100%, P1: 100%, P2: 70% | 22/24 full, 2/24 partial |
| v2 Phase 3 | Week 9-12 | P0-P2: 100%, P3: partial workarounds | 24/24 addressed |

---

## Appendix A: Risk Score Calculation

```
risk_score = min(100, sum(
    critical_count * 25 +
    high_count * 10 +
    medium_count * 5 +
    low_count * 1
))
```

| Score | Rating | Action |
|-------|--------|--------|
| 0 | Clean | No action needed |
| 1-10 | Low | Review findings at convenience |
| 11-30 | Medium | Investigate within 24 hours |
| 31-60 | High | Investigate immediately, change critical passwords |
| 61-100 | Critical | Assume compromise — full incident response required |

## Appendix B: Testing Strategy

Each module should include:

1. **Unit test with mock data** — simulated process lists, fake plist files
2. **Known-good baseline** — expected output on a clean system
3. **Known-bad samples** — test IOCs that should trigger detection (using safe test patterns, never real malware)
4. **False positive regression tests** — ensure legitimate software (Claude, Docker, VS Code, etc.) does not trigger alerts

```bash
# Example test runner
for test in tests/modules/*.test.sh; do
    echo "Running: $(basename $test)"
    bash "$test" && echo "PASS" || echo "FAIL"
done
```
