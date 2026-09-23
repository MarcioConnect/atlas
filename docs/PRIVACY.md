# ATLAS privacy

ATLAS stores scan metadata, finding evidence after redaction, event metadata, and
project paths in a per-user SQLite database. It does not store source file
contents in Watch activity. Settings and database files remain on the local
machine unless the user exports or shares them.

The local scanners run on the selected project. Dependency tools such as
Semgrep auto configuration, pip-audit, npm audit, and Trivy can access their
configured advisory sources when invoked. Watch mode itself does not use AI.

Ollama requests are sent to `127.0.0.1` by default. A chat request may include
sanitized snippets selected from the project by the user's question. Watchdog AI
review requires `--ai` and a separate explicit finding selection. ATLAS does not
send secrets intentionally; redaction is heuristic and cannot guarantee that all
sensitive data is removed. Do not configure a remote Ollama endpoint without
reviewing its data handling and network path.

Reports can contain hostnames and project paths. Review them before sharing.
Microsoft Defender telemetry is queried locally; only a user-requested scan
passes a selected path to Defender.
