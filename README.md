# ATLAS v0.1

## Melhorias locais (ainda nao publicadas)

- Validacao de sintaxe Python, JSON e TOML, sem executar o codigo analisado.
- Ruff opcional para diagnosticos Python: instale com `python -m pip install ruff`.
- Diagnosticos `[BUG]` e `[LINT]` nao significam invasao ou comprometimento.
- Exclusao antecipada de dependencias, ambientes virtuais e artefatos de testes
  durante a descoberta de arquivos.
- Recuperacao do Watch apos falhas temporarias do SQLite ou fechamento da TUI.

Para testar esta copia local:

```powershell
python -m pip install .
atlas watch "C:\Meu Projeto"
```

O Watch nao detecta todos os erros possiveis. As ferramentas opcionais ampliam
a cobertura; resultados continuam exigindo revisao humana. O executavel de uma
release anterior nao inclui automaticamente estas alteracoes.

ATLAS is a defensive Security Watchdog for Windows that runs entirely in the
terminal. It watches a source tree, scans changed code with local tools, and
reports only findings that are new since the previous measured scan.

It is independent of Codex, Cursor, Claude Code, IDEs, and editors. The core
watch mode does not call an LLM and does not consume AI tokens.

> Alpha software. ATLAS reduces review time but does not guarantee that a
> system or project is free of vulnerabilities.

## Download rápido (Windows)

Quer apenas usar? Baixe o executável pronto na página da release:

**[Baixar ATLAS-Security-Agent.exe — v0.1.1](https://github.com/MarcioConnect/atlas/releases/download/v0.1.1/ATLAS-Security-Agent.exe)**

Depois, no PowerShell:

```powershell
.\ATLAS-Security-Agent.exe --version
.\ATLAS-Security-Agent.exe monitor start
```

Não precisa instalar Python, Git ou abrir navegador. A logo usada pelo
executável está disponível em [`assets/atlas.ico`](assets/atlas.ico).

Para instalar como pacote Python e usar o comando `atlas`, siga a seção de
instalação abaixo.

## v0.1 implementation status

The core workflow is functional:

```text
CODE CHANGES
    -> ATLAS detects the filesystem event
    -> waits for the debounce window
    -> runs available local scanners
    -> compares stable fingerprints with the previous measured state
    -> stores NEW / EXISTING / RESOLVED in SQLite
    -> refreshes the terminal TUI
```

Validation completed on Windows:

- 47 automated tests passing;
- real filesystem event detection verified;
- repeated events coalesced by debounce;
- `NEW -> EXISTING -> RESOLVED` lifecycle verified end to end;
- paths containing spaces verified;
- missing optional scanners verified without crashes;
- consecutive unchanged scans verified without repeated findings;
- source tree checked with zero exposed-secret findings;
- package metadata validated for `pip install .`;
- Textual Watchdog TUI opened and exercised in Windows Terminal.

Current optional-tool availability depends on the host. ATLAS always keeps the
built-in scanner active and prints an installation command for each missing
scanner.

## Screenshot

![ATLAS Security Watchdog TUI](docs/screenshots/atlas-watchdog.png)

See [`docs/screenshots/README.md`](docs/screenshots/README.md) for reproducible
capture steps.

## Requirements

- Windows 10 or Windows 11
- PowerShell 7 and Windows Terminal recommended
- Python 3.11 or newer
- Administrator privileges are **not** required to scan source code

Optional scanners are detected at runtime. Missing tools never stop the ATLAS
Native scanner or another available scanner.

## Installation

To install from the source ZIP, use **Code > Download ZIP** on GitHub, extract
it, open PowerShell in that folder, and run:

```powershell
py -m pip install .
atlas --version
```

Git is not required. To upgrade a previously installed copy, use
`py -m pip install --upgrade .` from the newly extracted release folder.

If the GitHub release provides `ATLAS-Security-Agent.exe`, Python is not needed
for normal use. Download the executable and run:

```powershell
.\ATLAS-Security-Agent.exe --version
.\ATLAS-Security-Agent.exe monitor start
```

For development:

```powershell
python -m pip install -e ".[dev]"
```

To build the standalone Windows executable with the ATLAS icon and process
identity:

```powershell
.\tools\build_windows.ps1
.\release\ATLAS-Security-Agent.exe monitor start
```

The resident monitor then appears in Task Manager as
`ATLAS-Security-Agent.exe`, with the bundled ATLAS icon instead of `python.exe`.
The one-file Windows build can appear as two grouped ATLAS processes while it
is active: the PyInstaller launcher and the resident agent. Both use the ATLAS
name and icon.

Optional Windows notifications and Python scanners:

```powershell
python -m pip install ".[desktop]"
python -m pip install ".[python-scanners]"
```

The runtime dependency source of truth is `pyproject.toml`.

## Quick start

```powershell
atlas watch "C:\Meu Projeto"
```

For continuous monitoring of every saved project in the background:

```powershell
atlas monitor start
atlas monitor status
```

ATLAS opens a Textual TUI in the current terminal. Keep it running while using
any editor or coding agent. Relevant changes are coalesced with a two-second
debounce, scanned locally, reconciled with SQLite, and displayed as `NEW`,
`EXISTING`, or `RESOLVED`.

To monitor every existing project path saved in ATLAS, omit the path or use
`--all`:

```powershell
atlas watch
atlas watch --all
```

The multi-project TUI shows each project's status, scan counters, and new
findings in one screen. If no paths are configured, first run for example:

```powershell
atlas monitor start --watch "C:\Meu Projeto"
```

Run one scan without opening the TUI:

```powershell
atlas watch "C:\Meu Projeto" --once
```

`--ai` is reserved for a future provider integration. In v0.1 it makes no paid
or remote AI call.

Use `--silent` to keep the watcher quiet, or persist rule exclusions with
`--ignore-rule`:

```powershell
atlas watch "C:\Meu Projeto" --silent
atlas watch "C:\Meu Projeto" --notify
atlas watch "C:\Meu Projeto" --ignore-rule hardcoded-secret
```

The native scanner uses an in-memory file snapshot to inspect only changed
lines after the first observation. Optional scanners remain scoped to the
changed files and unavailable tools are reported without stopping the watch.
When `winotify` is installed, new findings also generate a Windows desktop
notification; otherwise the TUI remains the source of truth.

## Generate Report

Use **4. Generate Report** in the launcher (or activate it with the keyboard)
to write a local Markdown report containing the latest system Security Score,
Watchdog findings, scanner status, evidence, risk, recommendations, and the
sanitized file-change history for each known project. Without `--project`, the
report consolidates all configured and previously scanned projects. The
file is saved in your Windows Downloads folder as
`atlas-report-YYYY-MM-DD.md`; an existing report is never overwritten and a
time suffix is used when necessary. All report fields are sanitized and
sensitive values are replaced with `[REDACTED]`.

Reports can also be generated directly from the CLI:

```powershell
atlas report --format md
atlas report --format html
atlas report --project "C:\Meu Projeto" --output "C:\Relatorios"
```

## Watchdog TUI

Views: Overview, Watchdog, New Findings, All Findings, Resolved, Scan, and
Settings.

Keyboard shortcuts:

- `W`: start or stop watching
- `S`: run a full manual scan
- `Enter`: open details for the selected finding
- `R`: refresh
- `Q`: quit

## Supported files

ATLAS records create, modify, move, and delete events for every non-ignored
file. Security scans prioritize `.html`, `.py`, `.js`, `.ts`, `.tsx`, `.jsx`,
`.ps1`, `.bat`, `.json`, `.yaml`, `.yml`, `Dockerfile`, and Compose files.
File contents are never stored in the activity history.

It ignores VCS metadata, `node_modules`, virtual environments, `site-packages`,
Python caches, test/build artifacts, `dist`, and `build`.

## Scanners

| Scanner | Scope | Optional install |
|---|---|---|
| ATLAS Native | Secrets, risky APIs, exposed binds, Docker basics | Built in |
| Semgrep | Multi-language static analysis | `python -m pip install semgrep` |
| Bandit | Python security linting | `python -m pip install bandit` |
| pip-audit | Python dependencies | `python -m pip install pip-audit` |
| npm audit | npm dependencies | Install Node.js/npm |
| PSScriptAnalyzer | PowerShell analysis | `Install-Module PSScriptAnalyzer -Scope CurrentUser` |
| Trivy | Dependencies, containers, misconfigurations, secrets | `winget install AquaSecurity.Trivy` |

Some dependency scanners may need network access to refresh advisory databases.
This does not involve an LLM or AI tokens.

## Other commands

```powershell
atlas                         # native ATLAS dashboard + conversation TUI
atlas agent                   # conversa do agente ATLAS no terminal
atlas agent --advanced        # exige o chat avançado do ATLAS
atlas dashboard               # system security dashboard
atlas security                # read-only machine scan
atlas monitor start           # background events + code Watchdogs for all configured paths
atlas monitor install         # start now and register ATLAS for Windows login
atlas monitor status
atlas monitor events
atlas monitor stop
atlas config                  # mostra caminhos, regras ignoradas e severidades
atlas start                   # controlled operational session
atlas stop
atlas history
```

Persist projects and customize findings without editing files manually:

```powershell
atlas config --add-path "C:\Meu Projeto"
atlas config --ignore-rule RULE-ID
atlas config --unignore-rule RULE-ID
atlas config --risk RULE-ID=HIGH
```

## Finding lifecycle

A stable SHA-256 fingerprint uses scanner, rule, normalized project-relative
file path, and location. On every scan:

- `NEW`: not active in the previous measured state, or it reappeared;
- `EXISTING`: still present;
- `RESOLVED`: absent from a scanner/file scope that was successfully measured.

An unavailable scanner has no coverage and therefore cannot accidentally mark
its older findings as resolved.

## Privacy and safety

ATLAS is read-only by default and never exploits vulnerabilities. Evidence is
sanitized before display or storage. Passwords, tokens, API keys, cookies,
connection strings, private keys, `.env` values, and common credential formats
are replaced with `[REDACTED]` or omitted entirely.

For ordinary file activity, ATLAS stores only sanitized metadata: timestamp,
event type, severity, and path. It does not store file contents. Sensitive
filenames are replaced with `[SENSITIVE_FILE]`.

## v0.1 limitations

- Windows is the primary supported platform; other systems are best effort.
- Optional scanner accuracy and coverage depend on installed versions and rules.
- Semgrep `auto` configuration and vulnerability databases can require network access.
- Protected machine-wide checks may be incomplete without Administrator access;
  ATLAS reports reduced coverage rather than failing.
- `atlas agent` opens the advanced ATLAS chat when its optional local backend
  is installed, preserving the ATLAS profile and terminal branding. On a clean
  computer it falls back to the portable rule-based ATLAS chat. Use
  `atlas agent --advanced` when the advanced backend is required.
- The native scanner is intentionally conservative and is not a replacement for
  specialist scanners or a professional security review.
- `atlas watch --ai` is a placeholder and performs no AI analysis.

## Development

```powershell
python -m pytest -q
atlas --version
atlas watch . --once
.\tools\build_windows.ps1
.\release\ATLAS-Security-Agent.exe --version
```

`atlas monitor start` runs in the background and starts one local code Watchdog
per existing configured path. All non-ignored file changes are recorded as
sanitized metadata; supported source/configuration files are debounced, scanned locally, and
reconciled as `NEW`/`EXISTING`/`RESOLVED` without AI calls. Use
`atlas monitor status` and `atlas monitor events` to inspect the resident
service.

See [CHANGELOG.md](CHANGELOG.md) for release notes.

## GitHub release checklist

- [x] Runtime dependencies declared in `pyproject.toml`
- [x] CLI, Watchdog, debounce, lifecycle, redaction, and TUI tests
- [x] `README.md`, `LICENSE`, `.gitignore`, and `CHANGELOG.md`
- [x] PyPI-compatible package metadata
- [x] Add the final sanitized TUI screenshot
- [x] MIT copyright holder set to `ATLAS contributors`
- [x] Install and execute the built wheel in an isolated Windows environment
- [ ] Let GitHub Actions validate the Python 3.11/3.12/3.13 matrix after push
- [x] Build and inspect wheel and source distribution
- [ ] Create the GitHub repository, review staged files, and tag `v0.1.0`
