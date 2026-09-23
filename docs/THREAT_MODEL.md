# ATLAS threat model

## Assets

- Source code and dependency manifests in explicitly selected project roots.
- Redacted scanner evidence and operational metadata in the local SQLite store.
- Local configuration, report output, and optional Ollama model requests.

## Trust boundaries

- Files, comments, documents, scanner output, and retrieved source are untrusted
  data. They cannot authorize tool execution or change ATLAS policy.
- External scanners are separate programs invoked with argument arrays, no shell,
  timeouts, and bounded output where supported.
- Ollama receives only a user-requested, minimized context; its answer is advisory.
- Reports are local artifacts and may contain identifying paths even after
  credential redaction.

## Defenses

- Watchdog is read-only and does not remediate or execute scanned content.
- Project scope, ignore directories, file-size limits, timeouts, and scanner
  availability are surfaced to the user.
- Findings use stable fingerprints, lifecycle states, and optional expiring
  per-finding suppressions with reasons.
- SQLite migrations are additive; scanner failure does not resolve old findings.
- Process invocation uses `shell=False`; Defender scans request no remediation.

## Out of scope and residual risks

- ATLAS is not a full antivirus, EDR, sandbox, or proof that a host is clean.
- Static rules can miss vulnerabilities or report false positives.
- Optional tools can have their own vulnerabilities and network behavior.
- Redaction and prompt-injection detection are heuristic.
- Local malware scanning and system inventory coverage vary by Windows policy,
  permissions, and Defender availability.
- ATLAS does not monitor every application, browser, network packet, or action
  performed by another agent.

Report security vulnerabilities through GitHub private vulnerability reporting
as described in `SECURITY.md`.
