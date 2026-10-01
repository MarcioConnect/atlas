# ATLAS implementation report

## Windows executable v0.2.0 (2026-10-01)

- Updated package, CLI, Windows file/product metadata, README download and
  release-workflow default to 0.2.0. Detection capabilities are unchanged.
- Added two regression tests comparing CLI/package/Windows versions and the
  README download/release-workflow version.
- The first local suite identified an intermittent chat-test failure (2,754
  passed, one failed). The test patched the Ollama module but not the service
  function already imported by the assistant, and relied on a fixed sleep.
  Both references are now mocked and the test awaits worker completion.
- The final complete local suite passed 2,755 tests on Python 3.12.14 in 36.59 s;
  Ruff checks passed for src, tests and tools.
- Built with Python 3.12.14 and PyInstaller 6.22.3. Compiled version and Windows
  file/product metadata are 0.2.0. CLI/help, native detection, redaction, verified
  resolution, saved projects, Watch once, monitor status and Markdown/HTML/JSON
  reports passed using isolated temporary state and a path containing spaces.
  The artificial secret was absent from reports and the actual SQLite database.
- File size: 27503754 bytes. SHA-256:
  `6b323d9d52c79ced179cd4109393d98842b862e767595ac3962472464fd298ad`.
- Authenticode is NotSigned. No compiled-TUI visual inspection was performed.

## Windows executable v0.1.10 (2026-09-30)

- Bumped Python package, CLI, Windows file/product metadata, README download link
  and release-workflow default to 0.1.10.
- Fixed the hosted Python 3.12 Help test: the scroll was deferred until a refresh,
  while the assertion could run first. The test now requests an immediate scroll
  after measuring the available viewport. Windows CI keeps running the other
  matrix jobs when one fails so all supported versions can be inspected.
- The complete local suite on Python 3.12.14 passed 2,753 tests in 61.19 s.
- Built the standalone console executable with Python 3.12.14 and PyInstaller
  6.22.3. The build script now fails explicitly on packaging errors and accepts
  an optional Python executable argument.
- Tested the compiled executable itself: version and Windows metadata are
  0.1.10; CLI/help, native detection, secret redaction, verified resolution, saved
  project configuration, Watch once, monitor status, and Markdown/HTML/JSON
  reports passed in isolated temporary configurations. The artificial fixture
  secret was absent from both exported reports and the actual SQLite database.
- The compiled Defender status command returned active protection and zero
  history records on the local machine.
- File size: 27504162 bytes. SHA-256:
  `c1c929b103b1e6c426033a966e08e2d99bc808850b546a5b51280a8c59758c0f`.
- Authenticode status is `NotSigned`. A matching checksum verifies the artifact
  bytes, not an independently authenticated publisher.
- Interactive execution of the compiled TUI could not be exercised through this
  automation because creating a terminal PTY was denied. Headless source-panel
  tests passed; no visual inspection of the compiled interface is claimed.

## Windows regression validation (2026-09-30)

This section records validation of the September 30 command-reference UI
changes and the fixes below. The release executable has not been rebuilt during
this validation.

### Bugs reproduced and corrected

- The command-reference popup allocated a fixed viewport height to its text,
  preventing scrolling in smaller terminals. Its content now determines its
  height, and the panel test checks scrolling through the complete reference.
- A file rename caused the destination to be scanned while the old source's
  finding remained active. The event handler now queues both in-scope paths.
  The missing source requests a full scan, and successful scanner coverage
  verifies the removed path. Any issue still present at the destination remains
  an active finding; renaming does not make its content safe.
- The real local Defender query returned valid protection status but `null` for
  empty threat history. ATLAS incorrectly discarded the valid status and reported
  Defender unavailable with `TypeError`. Empty history now yields an empty list;
  the PowerShell query explicitly serializes an array and stops on cmdlet errors.
- A malformed or inaccessible threat-history response no longer masks valid
  protection telemetry. The CLI shows the history limitation instead of implying
  zero detections were confirmed.
- Missing, null, or string-valued protection indicators previously satisfied the
  CLI's active-protection check. The CLI now requires actual boolean `True`
  values, reports explicitly disabled protection, and returns an unknown status
  with exit code 1 when protection cannot be determined.

### New regression coverage

Added 15 cases: seven live Watchdog integration cases, two Defender history
cases, and six Defender CLI cases. Live integration uses the Windows filesystem
observer, the real native scanner, and temporary SQLite databases. It covers
new detection, line movement without duplication, confirmed fixes, renaming,
moves into/out of ignored dependencies, deletion, editor atomic saves, and
changes plus conflicting scan requests while another scan is active.

Optional scanner discovery and desktop notifications are disabled in these
live cases to isolate the native pipeline. External scanner failures/timeouts,
AI service failures, and Defender permission errors remain covered with mocks.
The rename regression and six Defender/CLI assertions failed before their fixes
and passed afterwards.

### Final results

| Check | Result |
| --- | --- |
| Complete suite, Windows / Python 3.11.16 | 2,753 passed in 128.62 s |
| Complete suite, Windows / Python 3.14 | 2,753 passed in 127.30 s |
| Focused Watchdog / Defender / CLI suite | 32 passed in 10.75 s |
| Panel suite after the final Help scrolling adjustment | 7 passed in 16.88 s |
| Ruff, bytecode compilation, installed dependency check | Passed |
| Wheel build and Twine metadata check | Passed |
| Wheel installed independently of source checkout on Python 3.11 | Entry point reports 0.1.9; bundled icon and version rules present |
| Wheel archive inspection | Icon/rules included; no `.env`, `.pem`, `.key`, `.pfx`, SQLite or database files |
| Real local `atlas malware status` after correction | `Defender ACTIVE`, zero records in available threat history |

The two final full-suite runs account for 5,506 passing test executions. They
used separate temporary configurations/databases and ran in parallel; durations
are verification timings rather than performance benchmarks. JUnit XML results
were saved outside the repository in the local temporary validation directory.
The full-suite runs preceded the final Help scrolling adjustment, which was
then verified against all seven panel tests.

The existing nine-case synthetic corpus still reports 3 true positives, 6 true
negatives, no false positives and no false negatives (precision/recall/F1 1.0
for those fixtures only). Most suite cases are generated regression samples;
these figures do not measure field accuracy. No live malware scan, adversarial
malware sample execution, remote Ollama request, executable rebuild or release
publication was performed. The real Defender check was read-only status/history
inspection. Passing this suite does not establish absence of vulnerabilities.

## Precision and scan-health pass (2026-09-25, v0.1.9)

This section describes the published v0.1.9 source and Windows release. The
v0.1.8 information below is historical. The public release includes the Windows
executable and SHA-256 sidecar; it is not Authenticode-signed.

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
- After the v0.1.9 launcher and CLI-help wording changes, the complete local
  suite passed 2,745 tests in 80.62 seconds. GitHub Actions passed on Python
  3.11–3.14, package validation, and CodeQL. The Windows release workflow passed.
- Downloaded release executable reports version, FileVersion, and ProductVersion
  `0.1.9`; its SHA-256 matched the published sidecar:
  `1ce6746b0174af96d9d8816f2599232cc14737a47650e136ae406f5ed4556bbd`.
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
  `git diff --check`, and CLI help smoke check passed. The published executable
  was checked locally for version metadata, startup, help output, and checksum;
  this was not an independent clean-machine installation test.

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
