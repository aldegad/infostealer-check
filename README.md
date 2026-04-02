# Infostealer Check

Lightweight scripts that scan your machine for signs of infostealer infection. No installation required — just download and run.

## What It Does

Checks **10 categories** of common infostealer indicators:

| # | Check | macOS | Windows |
|---|-------|-------|---------|
| 1 | System info | hostname, OS, uptime | hostname, OS, last boot |
| 2 | Suspicious processes | known stealer names + unusual paths | known stealer names + Temp folder exes |
| 3 | Auto-start entries | LaunchAgents / LaunchDaemons | Registry Run keys |
| 4 | Login items | Login Items list | Startup folder |
| 5 | Recently installed apps | 7-day app changes + code signing | 7-day installs + signature verification |
| 6 | Chrome extensions | high-risk permissions audit | high-risk permissions audit |
| 7 | Network connections | suspicious ports + webhook comms | suspicious ports + full connection export |
| 8 | Chrome credential store metadata | non-Chrome processes touching Login Data / Cookies DB | Login Data / Cookies timestamps by Chrome profile |
| 9 | Scheduled tasks | cron / periodic scripts | Scheduled Tasks + Defender threat history |
| 10 | Privacy permissions | TCC database (Full Disk Access, Accessibility) | PowerShell command history |

## What It Does NOT Do

- **Does not access, decrypt, or transmit any passwords or credentials**
- Does not read cookie values or session tokens
- Does not send any data anywhere — everything stays local
- Does not modify any files on your system
- Does not require internet access

This is purely an **anomaly detector**. It checks process names, file metadata, network connection endpoints, and permission configurations — never actual credential content.

## Quick Start

### macOS

```bash
curl -fsSL https://raw.githubusercontent.com/aldegad/infostealer-check/main/check-mac.sh -o check-mac.sh
chmod +x check-mac.sh
./check-mac.sh
```

### Windows (PowerShell as Administrator)

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
irm https://raw.githubusercontent.com/aldegad/infostealer-check/main/check-windows.ps1 -OutFile check-windows.ps1
.\check-windows.ps1
```

## Output

Both scripts create a timestamped folder on your Desktop:

```
~/Desktop/infostealer-check-20260402_114825/
  report.txt                 # Full scan report
  network_connections.txt    # All active network connections (macOS)
  network_connections.csv    # All active network connections (Windows)
  powershell_history.txt     # PowerShell history copy (Windows only)
```

Results are color-coded in the terminal:
- `[OK]` Green — no issues found
- `[!]` Yellow — worth reviewing
- `[X]` Red — suspicious, investigate further

## When to Use This

- After a **phishing incident** or account compromise
- When you suspect **malware infection** (unexpected ads, redirects, account takeovers)
- As part of **incident response** for compromised Google Ads / OAuth tokens
- Regular **security hygiene** checks on workstations

## Known Infostealers Detected

The scripts check for indicators associated with:

| Family | Platform | Notes |
|--------|----------|-------|
| Amatera Stealer | Win/Mac | ACR Stealer successor, spread via fake Claude Code pages |
| Atomic Stealer (AMOS) | Mac | Targets macOS keychain and browser data |
| Poseidon Stealer | Mac | Distributed via Google Ads malvertising |
| Banshee Stealer | Mac | Targets 100+ browser extensions |
| RedLine | Win | Most prevalent Windows infostealer |
| Raccoon | Win | Stealer-as-a-service |
| Vidar | Win | Targets browsers, crypto wallets |
| Lumma | Win | Active MaaS operation |
| StealC | Win | Lightweight credential stealer |
| Rhadamanthys | Win | Advanced evasion techniques |
| MetaStealer | Win/Mac | Cross-platform stealer |

## False Positives

Some legitimate software may trigger warnings:

- **Development tools** (Claude, Codex, Node.js) running from user directories
- **Chrome Helper** processes accessing Chrome databases (expected behavior)
- **Security software** (nProtect, etc.) registered as LaunchDaemons
- **Discord/Slack** network connections (legitimate app usage)

The report provides enough context to distinguish real threats from false positives.

## Claude Code Skill

This project can also be used as a Claude Code skill. Place the `SKILL.md` in your skills directory:

```bash
ln -s /path/to/infostealer-check ~/.claude/skills/infostealer-check
```

Then use `/infostealer-check` in Claude Code to run the appropriate script for your platform.

## License

MIT
