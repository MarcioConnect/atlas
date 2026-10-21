# ATLAS threat model

This page describes what ATLAS is meant to protect, where it draws boundaries,
and what it cannot promise. It is a guide to the design, not a claim that every
threat can be detected.

## Assets

- The source code and dependency manifests under project roots the user selects.
- Redacted findings and activity metadata in the local SQLite database.
- Local settings and reports, plus any context a user chooses to send to Ollama.

## Trust boundaries

- Treat project files, comments, documents, and scanner output as untrusted.
  Their contents cannot authorize a command or change ATLAS settings.
- ATLAS runs external scanners as separate programs, without a shell, and uses
  timeouts and output limits where the scanner interface allows it.
- Ollama receives context only after a user requests a review. Its response is
  advice for a person to assess, not an instruction ATLAS should follow.
- Reports stay local until shared, but may still reveal computer or project
  paths after credentials have been redacted.

## Defenses

- The Watchdog reads and reports; it does not fix findings or run scanned code.
- The interface shows the selected scope, ignored paths, file-size limits,
  timeouts, and scanners that could not run.
- Findings have stable fingerprints and clear lifecycle states. A user can
  suppress an individual finding with a reason and an expiry date.
- A scanner failure cannot mark an older finding as resolved. Database changes
  use additive migrations.
- External processes are started with `shell=False`. Defender scans request no
  remediation.

## Out of scope and residual risks

- ATLAS is not an antivirus, EDR, or sandbox, and a clean scan does not prove a
  computer or project is safe.
- Static checks can miss issues and can flag code that is harmless in context.
- Optional scanners have their own rules, network behavior, and security risks.
- Secret redaction and prompt-injection checks use heuristics; neither catches
  every case.
- Defender and system inventory results depend on Windows configuration,
  permissions, and Defender availability.
- ATLAS watches selected files. It does not observe every app, browser, network
  packet, or action taken by another coding agent.

Report security vulnerabilities through GitHub private vulnerability reporting
as described in `SECURITY.md`.
