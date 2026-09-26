# ATLAS implementation report

## Precision and scan-health pass (2026-09-25, v0.1.9)

This section describes the v0.1.9 source and release candidate. The published
v0.1.8 information below is historical; release artifact validation is tracked
separately from the code and test results in this report.

### Extended deterministic validation (2026-09-25)

- Added `tests/test_stress_precision.py` with 2,580 parameterized cases:
  1,536 plausible/fake/environment-reference secret candidates, 512 redaction
  cases, 256 Python call-versus-string cases, 256 fingerprint movement cases,
  and a 20-case scanner-status/coverage matrix. The separate groups sum to
  2,580; all passed in 17.20 seconds when run alone.
- Added a Watchdog burst regression: 1,000 repeated events for one file yielded
  one scan after debounce. This test passed in 1.82 seconds.
- Baseline before additions: 163 tests passed in 64.53 seconds. A full suite
  after the generated cases, but before the burst test, passed 2,743 tests in
  83.99 seconds. Final full suite including the burst test: 2,744 passed in
  83.75 seconds (Python 3.14 on this Windows machine). Ruff, compileall, and
  `git diff --check` also passed.
- These samples are synthetic and deterministic. The earlier 9-case fixture
  precision/recall/F1 figures remain fixture-only; neither test volume nor a
  zero-failure result establishes field accuracy or absence of vulnerabilities.

### Completed

- Scanner availability is now separate from execution status. Each local or
  optional adapter records its actual outcome (`SUCCESS`, `PARTIAL`, `FAILED`,
  `TIMEOUT`, `NOT_INSTALLED`, `NOT_APPLICABLE`, or `SKIPPED`), timing, exit code
  when available, and coverage. Malformed output and scanner-reported errors
  no longer become successful empty scans. Raw tool error output is not stored.
- Findings from failed/partial/unavailable scanners become `UNVERIFIED`, not
  `RESOLVED`. Successful resolution requires scanner success and relevant file
  coverage; a full scan can confirm a deleted source file. An unexpected whole-scan
  crash also leaves prior active findings `UNVERIFIED`. The database keeps
  existing history through additive migration.
- Source-scope traversal gaps and oversized files make scan health partial.
  CLI, TUI, Markdown, and JSON reports show scan health, scanner status, and
  coverage gaps, avoiding a misleading zero-findings conclusion. Historical
  records with only `available=true` no longer imply a verified scan. Confidence
  is also shown as LOW/MEDIUM/HIGH alongside its heuristic score.
- Native secret detection now distinguishes obvious synthetic placeholders
  from plausible literals while keeping suspicious values redacted. Python
  wildcard-bind checks use the AST rather than matching quoted examples.
  Test/fixture code is not treated as production Python vulnerability code.
- Repeated identical source lines now receive distinct fingerprints while
  unrelated line insertion preserves a finding fingerprint. Rapid file events
  remain debounced; non-priority file changes do not trigger a source scan.
- A wildcard `LISTEN` socket is reported as an observation rather than proven
  external exposure. Port 2375 remains a high-severity potential risk with low
  confidence. Passive Microsoft Defender mode is not equated with unprotected
  Windows; incomplete Defender history is retained as incomplete coverage.

### Verification

- Baseline before this pass: 136 tests passed.
- Final full suite: 163 passed in 64.16 seconds (Python 3.14 on Windows).
- Final targeted report, scan-health, detection-corpus, and security tests:
  38 passed. The corpus
  contains 3 positive and 6 negative examples for selected native rules:
  TP=3, FP=0, TN=6, FN=0; precision=recall=F1=1.0 **only on these nine
  fixtures**. This is not a field accuracy estimate.
- `py -m ruff check src tests tools`, `py -m compileall -q src tests tools`,
  `git diff --check`, and CLI help smoke check passed. No release executable
  or independent clean-machine run was produced in this local pass.

### Partial or not implemented

- No calibrated confidence probabilities, comprehensive cross-scanner
  correlation, or representative real-world precision/recall dataset.
- Firewall profile/rule correlation and proof of remote reachability are not
  implemented; network findings explicitly communicate that uncertainty.
- Watchdog Windows-module health by subsystem, general suppression policies,
  and complete scan-to-scan trend comparisons are not implemented in this pass.
- Optional external scanners and Defender depend on the tools, OS permissions,
  and environment. Passing tests does not prove freedom from vulnerabilities.

Status: ATLAS v0.1.8 is published at
https://github.com/MarcioConnect/atlas/releases/tag/v0.1.8 with the Windows
executable and SHA-256 sidecar. No PyPI package was uploaded. The executable is
not Authenticode-signed.

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
- CLI smoke checks for the v0.1.8 candidate: version, `scan`, `security`,
  `report`, `watch`, `monitor`, and `agent` help — passed; version reports 0.1.8.
- `py -m build` — wheel and source distribution built successfully.
- `py -m twine check` on both built artifacts — passed.
- Historical GitHub Actions for `8b149c2`: CI matrix and CodeQL passed, but the
  manually triggered release workflow failed before starting jobs due to an
  invalid `workflow_dispatch` input schema. The schema fix is included in v0.1.8.
- Regression suite includes temp-directory filesystem watcher/debounce/lifecycle,
  Windows paths with spaces, optional scanner absence, redaction, migration,
  concurrent-start rollback, reporting and security helper tests. Platform
  APIs/external scanners are mocked where appropriate; this is not a separate
  clean-machine CI run.

### Current local follow-up validation

- Full pytest suite (`-p no:cacheprovider -o addopts='' -q`) — 136 passed in
  65.77 seconds on Windows with Python 3.14 (temporary files outside the repo).
- Focused regression set — 42 passed in 20.73 seconds.
- `py -m ruff check src tests tools`, `py -m compileall -q src tests tools`,
  `py -m build --no-isolation`, `py -m twine check` for v0.1.8 wheel/sdist, and
  `git diff --check` — passed.
- The new `atlas scan` table/JSON flows, skipped-large-file coverage, additive
  SQLite migration, incremental-scan scope, one-time baseline acceptance, and
  partial-coverage UI state are covered by regression tests. GitHub CI passed
  on application commit `f80db87` across Python 3.11–3.14 and package checks;
  CodeQL passed on `f80db87` and report update `6b5dab9`. The Windows release
  workflow passed as run `35921058832`; the downloaded executable returned
  version 0.1.8 and matched its SHA-256 sidecar before publication.

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
- Dependabot, CodeQL, and Python 3.11–3.14 Windows CI are configured. CI and
  CodeQL passed on the v0.1.8 source commit; the docs-only report update does not
  change the tested application code.
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
