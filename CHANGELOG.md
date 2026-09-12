# Changelog

All notable changes to ATLAS are documented in this file.

## [0.1.0] - 2026-09-12

- Chat avançado agora usa `deepseek-v4-flash-free` por padrão, com migração automática do modelo inicial `nemotron-3-ultra-free`.

### Added

- Changed-line snapshots for the built-in incremental scanner.
- Configurable ignored rules and severity overrides.
- Quiet mode and optional Windows desktop notifications for new findings.
- Windows Firewall profile change detection and process termination events.
- Continuous `atlas watch PATH` Security Watchdog TUI.
- Two-second file-event debounce and priority file filtering.
- Local adapters for Semgrep, Bandit, pip-audit, npm audit,
  PSScriptAnalyzer, and Trivy with graceful fallback.
- Built-in token-free source scanner.
- Stable finding fingerprints and `NEW`, `EXISTING`, `RESOLVED` lifecycle.
- Incremental scan and finding persistence in SQLite.
- Real-time Watchdog, findings, resolved, scan, and settings views.
- `atlas watch PATH --once` for headless verification.
- Stronger credential and connection-string redaction.
- Native monochrome ATLAS dashboard and conversation UI inspired by the release design.
- Bare `atlas` startup opens the native ATLAS dashboard without external UI.
- `atlas agent` uses the branded advanced backend when installed and falls
  back to the portable local Ask ATLAS interface on clean machines.
- Launcher actions now execute scans, toggle Watch Mode, summarize reports, and
  show settings directly in the conversation panel.
- Generate Report now writes a sanitized Markdown security report to the
  Windows Downloads folder without overwriting an existing report.
- `atlas monitor start` now starts local code Watchdogs for all configured
  project roots in addition to the existing event monitor.

### Existing functionality retained

- Optional advanced terminal agent, local system dashboard, security scanner, operational
  sessions, history, and background machine monitor.
