# Privacy

ATLAS is designed to run on your machine. Its settings and SQLite database stay
on your computer. The database can contain project paths, scan history, event
details, and scanner evidence after redaction. If you export or share a report,
review it first; reports can include identifying details.

During Watch, ATLAS records file activity as sanitized metadata; it does not
save the contents of changed files in that history. Scanners read files in the
project you selected. Some optional tools, including Semgrep auto configuration,
`pip-audit`, `npm audit`, and Trivy, may contact their advisory services when
you run them.

In its normal mode, Watch does not send project data to an AI service. If you
ask ATLAS to review something with Ollama, it sends a minimized, sanitized
excerpt to the configured Ollama endpoint. The default is `127.0.0.1`.
Redaction is based on patterns and can miss sensitive values, so review remote
endpoints and reports before sharing them. Reviewing a Watchdog finding with AI
also requires starting Watch with `--ai` and choosing the finding yourself.

Reports may include computer names and project paths. Check a report before
posting or sending it. Microsoft Defender checks run locally; ATLAS passes it a
path only when you explicitly request a scan.
