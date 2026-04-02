# Infostealer Check

Run platform-appropriate infostealer detection scan on the current machine.

## Usage

Detect the current platform and run the matching script:

```bash
# macOS
bash /path/to/infostealer-check/check-mac.sh

# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -File /path/to/infostealer-check/check-windows.ps1
```

## What This Does

Scans for 10 categories of infostealer indicators: suspicious processes, auto-start entries, Chrome extension permissions, network connections, credential DB access, and more.

**Does NOT access, decrypt, or expose any passwords or credentials.** This is purely an anomaly detector.

## Output

Creates a report folder on the Desktop with full scan results and network connection logs.
