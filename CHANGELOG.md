# Changelog

All notable changes to ATLAS are documented in this file.

## [0.1.6] - 2026-09-19

- Reduce secret and local-port false positives using contextual validation, placeholders and test-fixture exclusions.
- Add line-shift-resistant finding fingerprints and a silent initial Watchdog baseline.
- Recover abandoned scans and expose live scan phases in the integrated panel.
- Add Security Score domains with repetition caps and explain them in CLI, Markdown and HTML reports.
- Improve scanner coverage details and Ollama installation/service diagnostics.
- Expand regression coverage for fingerprints, baseline, score categories and secret fixtures.

## [0.1.5] - 2026-09-18

- Add executive summaries and severity/state metrics to Markdown reports.
- Replace the plain HTML export with a responsive dashboard, severity bars, print layout and collapsible details.
- Keep report output local, sanitized and compatible with project-specific and consolidated exports.

## [0.1.4] - 2026-09-16

- Add automatic project source retrieval for the local Ollama assistant.
- Add content and line focused context, sanitized in-memory cache, source coverage, and conversation controls.
- Add `/context`, `/clear`, `/ai on` and `/ai off` to the integrated panel.
- Preserve active findings after unrelated edits and reduce credential, Docker and dependency false positives.
- Harden local model transport, Windows reparse point traversal and malformed model responses.

## [Unreleased]

- Add automatic project-scoped source retrieval, content search, line windows and sanitized memory caching.
- Add per-project conversational context, source coverage, `/context`, `/clear`, and persistent `/ai on|off` for panel scans.
- Respect `atlas agent --model` for the local assistant and optional Watch review.
- Fix false resolution of existing findings after unrelated edits; only claim coverage for readable files.
- Reduce credential false positives in Python comments, environment lookups and placeholders; support quoted JSON keys.
- Distinguish privileged Docker configuration from verified running containers.
- Reject Ollama redirects, bypass HTTP proxies for loopback requests, and handle malformed model responses.
- Preserve source line numbers while redacting multiline credentials; exclude Windows reparse points from traversal.

## [0.1.3] - 2026-09-15

- Integrate scan history, findings, Watch actions and local chat in one terminal panel.
- Restore the original monochrome portrait and bound banner height on large terminals.
- Start the installed local Ollama service without extra terminal windows and check exact model tags.
- Handle panel scan failures without closing the interface; add responsive-layout regression tests.
- Build public Windows executables from the release tag in GitHub Actions, without local profiles or databases.

- Add opt-in, local-only Ollama review for new sanitized findings.
- Add deterministic Security Guard detection for prompt injection, exfiltration,
  obfuscation, privilege escalation, tool abuse and multi-step attack chains.
- Add Microsoft Defender status, detection-history and no-remediation custom scans.
- Poll new Defender detections from the resident monitor every 30 seconds.
- Add graceful coverage reporting when Defender requires Administrator access.

## [0.1.2] - 2026-09-13

- Add repository hygiene checks for sensitive files and personal absolute paths.
- Replace credential-shaped test fixtures with explicit test-only values.
- Add a reproducible GitHub Actions workflow for Windows release executables.
- Parse Python, JSON and TOML without executing project code.
- Add optional isolated Ruff diagnostics for changed Python files.
- Prune ignored directories before traversal and avoid full discovery on incremental scans.
- Prevent overlapping dashboard scans and handle background scan failures.
- Release Watch scan locks after database startup errors and isolate UI callback failures.
- Add regression tests for syntax lifecycle, directory scope and Watch recovery.

## [0.1.1] - 2026-09-12

- Corrigido o Agent avançado para não iniciar o Watchdog automaticamente.
- Subprocessos de configuração agora são ocultos no Windows.
- Inicialização automática do Watchdog não usa launcher intermediário.
- TUI multi-projeto não redesenha sem mudanças, evitando flicker.
- Proteção contra monitores duplicados.

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
