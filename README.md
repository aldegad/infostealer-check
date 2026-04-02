# infostealer-check

Modular infostealer detection toolkit for macOS and Windows.

![Shell](https://img.shields.io/badge/shell-bash%205.x-green)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Windows-blue)
![License](https://img.shields.io/badge/license-MIT-yellow)

## Quick Start

```bash
# Full scan (macOS)
bash core/runner.sh

# Single module
bash core/runner.sh --module T1555.003

# JSON output
bash core/runner.sh --format json

# SARIF for IDE/GitHub
bash core/runner.sh --format json | bash core/sarif-formatter.sh > report.sarif

# Performance check
bash core/perf-profile.sh --threshold 30
```

## Modules

| Category | Module ID | Description | Platform |
|----------|-----------|-------------|----------|
| Credential Access | T1555.003 | Browser credential DB access | macOS |
| Credential Access | T1552.001 | Credentials in files (.env, .aws) | macOS |
| Credential Access | T1555.001 | Keychain abuse | macOS |
| Execution | T1204.002 | Malicious file/process detection | macOS |
| Execution | T1059.004 | Shell history analysis | macOS |
| Execution | T1059.002 | AppleScript password prompts | macOS |
| Execution | T1204.001 | ClickFix clipboard attacks | macOS |
| Execution | T1574.002 | DLL sideloading (Lumma) | Windows |
| Persistence | T1543.001 | LaunchAgent/Daemon | macOS |
| Persistence | T1176 | Browser extensions audit | macOS |
| Collection | T1005 | Crypto wallet/messenger data | macOS |
| Collection | T1113 | Screen capture detection | macOS |
| Collection | T1518.001 | Security software status | macOS |
| Collection | T1083 | Filesystem timeline analysis | macOS |
| Exfiltration | T1041 | C2 channel detection | macOS |
| Exfiltration | T1071.001 | Telegram C2 abuse | macOS |
| Exfiltration | T1071.004 | DNS/DGA analysis | macOS |
| Exfiltration | T1102 | Dead Drop Resolver (ACR) | Windows |
| Defense Evasion | T1070.004 | Self-deletion residue | macOS |
| Defense Evasion | T1070.006 | Timestomping detection | macOS |
| Defense Evasion | T1055 | Fileless execution indicators | macOS |

## Architecture

```
core/
  runner.sh             Module discovery and orchestration
  output.sh             Shared output library (emit_finding/emit_clean/emit_info)
  sarif-formatter.sh    SARIF v2.1.0 conversion
  sigma-export.sh       Sigma-compatible event export
  encrypt-report.sh     GPG report encryption
  integrity-check.sh    SHA256 verification
  perf-profile.sh       Performance profiling

signatures/             IOC signatures (process names, network, file paths, YARA)

config/
  allowlist.json        False positive exclusions
  i18n/                 Localization (ko, en, ja)
```

## Writing a Module

1. Copy `core/module-template.sh` to `modules/`.
2. Set `MODULE_ID`, `TECHNIQUE`, and `DESCRIPTION` at the top.
3. Implement `run_checks()` with your detection logic.
4. Use `emit_finding`, `emit_clean`, or `emit_info` from `core/output.sh` for results.
5. Run `bash tests/run-tests.sh` to verify.

## MITRE ATT&CK Coverage

This toolkit maps to the following MITRE ATT&CK techniques:

- **Credential Access**: T1555.003, T1552.001, T1555.001
- **Execution**: T1204.002, T1059.004, T1059.002, T1204.001, T1574.002
- **Persistence**: T1543.001, T1176
- **Collection**: T1005, T1113, T1518.001, T1083
- **Exfiltration**: T1041, T1071.001, T1071.004, T1102
- **Defense Evasion**: T1070.004, T1070.006, T1055

Technique details reference the [security-threat-intel](https://attack.mitre.org/) knowledge base.

## Testing

```bash
bash tests/run-tests.sh
```

Individual module tests live under `tests/` and follow the naming convention
`test-<MODULE_ID>.sh`.

## License

MIT. See [LICENSE](LICENSE) for details.
