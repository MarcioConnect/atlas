# ATLAS implementation report

Status: preparing v0.1.8 from the public v0.1.7 release. The v0.1.7 release
contains the Windows executable and SHA-256 sidecar; no PyPI package was
uploaded. The v0.1.8 release should remain a draft until its Windows build and
checksum have been validated.

The v0.1.8 candidate adds a one-shot `atlas scan` command,
persists coverage gaps for source files skipped by the 2 MB limit, distinguishes
incremental coverage, and prevents repeated baseline acceptance.

## Summary

The existing package structure and working scanners, Watchdog, Textual panel,
reports, Defender support, and Ollama integration were retained. This pass
focuses on finding lifecycle/metadata, explicit AI review, Watchdog reliability,
defensive Windows inventory helpers, JSON reporting, packaging checks, and
project security documentation.

## Implemented

- Findings now carry category, estimated confidence, and suppression metadata.
  Existing SQLite databases are extended with additive columns. Suppressions
  require a reason, are fingerprint-specific, expire, remain visible, and are
  not counted as new alerts.
- Added CLI configuration for suppressing/unsuppressing findings and JSON report
  generation with lifecycle and scanner-coverage information.
- Watchdog AI review is now explicit: `--ai` enables the feature, but a user must
  select a finding and request review. Startup failures roll back already-started
  observers; stop-during-scan preserves an honest state. Multi-project startup
  also rolls back on a partial failure.
- Added optional, local-directory-only YARA support with bounded inputs/timeouts;
  executable SHA-256 and Windows Authenticode status inspection; and read-only
  startup Run/RunOnce and scheduled-task snapshots that persist metadata rather
  than raw command values.
- Startup-persistence changes are polled as metadata events. Source files larger
  than 2 MB are excluded from source scanners and do not cause unsupported
  findings to be marked resolved; source context extraction streams to the
  requested line.
- Added regression tests, additive configuration-save behavior, Windows Python
  CI matrix, CodeQL and Dependabot configuration, privacy/threat-model/permission
  and signing documentation, and a manually triggered release-artifact checksum
  step.
- Updated README and changelog; added this implementation report.

## Validation performed

- `py -m pytest --basetemp .pytest-atlas-confirm -p no:cacheprovider -o addopts='' -q`
  — 126 passed in 118.71 seconds on this Windows machine with Python 3.14.
- `py -m ruff check src tests tools` — passed.
- `py -m compileall -q src tests tools` — passed.
- `git diff --check` — passed (Git emitted only line-ending conversion notices).
- CLI smoke checks: `py -m atlas --version`, and `report`, `malware`, and
  `config` help — passed; the v0.1.7 release reported version 0.1.7.
- `py -m build` — wheel and source distribution built successfully.
- `py -m twine check` on both built artifacts — passed.
- GitHub Actions for commit `8b149c2` — CI matrix and CodeQL succeeded; inspection
  found the manual release workflow failed before starting jobs due to an invalid
  `workflow_dispatch` input schema. The schema is corrected locally below but has
  not yet been pushed or revalidated remotely.
- Regression suite includes temp-directory filesystem watcher/debounce/lifecycle,
  Windows paths with spaces, optional scanner absence, redaction, migration,
  concurrent-start rollback, reporting and security helper tests. Platform
  APIs/external scanners are mocked where appropriate; this is not a separate
  clean-machine CI run.

### Current local follow-up validation

- Full pytest suite (`-p no:cacheprovider -o addopts='' -q`) — 136 passed in
  64.40 seconds on Windows with Python 3.14 (temporary files outside the repo).
- Focused regression set — 42 passed in 20.73 seconds.
- `py -m ruff check src tests tools`, `py -m compileall -q src tests tools`,
  `py -m atlas scan --help`, and `git diff --check` — passed.
- The new `atlas scan` table/JSON flows, skipped-large-file coverage, additive
  SQLite migration, incremental-scan scope, one-time baseline acceptance, and
  partial-coverage UI state are covered by regression tests. These changes remain
  local and have not been validated by remote CI.

No before/after performance benchmark was recorded. Streaming source context and
file-size limits reduce memory exposure by design, but no numerical speedup is
claimed. The full test result is not proof that ATLAS is vulnerability-free.

## Partial or not implemented

- Confidence/category are deterministic metadata derived from scanner/rule
  context, not calibrated probabilities. Cross-scanner correlation remains
  limited; no claim is made that duplicate issues across unrelated tools are
  fully correlated.
- Current per-finding suppressions have reason and expiration; a general policy
  language with arbitrary scope, ownership and approval is not implemented.
- Findings filters/details and historical trend charts are not added in this
  pass. Existing HTML/Markdown output remains; JSON was added, but reports do not
  yet provide the full requested scan-to-scan trend dashboard.
- Startup persistence covers Run/RunOnce registry entries and scheduled tasks;
  startup folders and every persistence mechanism are not covered. Defender,
  service, firewall and process visibility depend on Windows version and user
  permissions. No packet-level or every-application monitoring is provided.
- YARA is optional (`pip install .[yara]`), uses only a user-supplied local rules
  folder, and is not an antivirus or automatic quarantine system.
- The optional AI backend is Ollama only. Requests remain user-initiated, but
  heuristic redaction cannot guarantee removal of every sensitive value.
- No Authenticode signing certificate or signing process is configured. The
  release workflow can generate a SHA-256 sidecar; no automatic updater,
  installer, or secure update-verification client was added.
- Dependabot, CodeQL, and Python 3.11–3.14 Windows CI are configured; CI/CodeQL
  passed on the v0.1.7 main commit, but the current local
  follow-up change has not yet run on the remote matrix.
- Authenticode signing is still unavailable because there is no legitimate
  signing certificate configured; the executable is not claimed to be signed.

## Local commands

```powershell
py -m pip install .
atlas --version
atlas watch "C:\Path With Spaces\Project"
atlas report --format json
atlas config --suppress-finding FINGERPRINT="Reviewed: accepted risk" --suppression-days 30
py -m pip install ".[yara]"
atlas malware inspect "C:\Path\program.exe"
atlas malware yara "C:\Path\Project" --rules "C:\Trusted\YaraRules"
```

Review `docs/PRIVACY.md`, `docs/THREAT_MODEL.md`, `docs/PERMISSIONS.md`, and
`docs/SIGNING.md` before sharing reports or building a public release.
