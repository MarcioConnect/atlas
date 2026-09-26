from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
import tomllib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from atlas.config import Settings
from atlas.file_scope import ignored_name, scoped_files
from atlas.models import Severity
from atlas.security import SKIP_DIRS, is_secret_candidate, redact
from atlas.security_guard import LEVELS, assess_untrusted

IGNORED_DIRS = {
    ".git", ".hg", ".svn", ".tox", ".nox", "node_modules", "venv", ".venv",
    "__pycache__", "_pycache_", "site-packages", "dist", "build", "appdata",
    ".vscode", ".idea", "docs", "documentation", "examples", "vendor", "third_party", "generated",
} | SKIP_DIRS
PRIORITY_SUFFIXES = {".py", ".js", ".ts", ".tsx", ".jsx", ".html", ".ps1", ".bat", ".json", ".yaml", ".yml", ".toml"}
PRIORITY_NAMES = {"dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
MAX_SOURCE_FILE_BYTES = 2_000_000
INSTALL_HINTS = {
    "Ruff": "python -m pip install ruff",
    "Semgrep": "python -m pip install semgrep",
    "Bandit": "python -m pip install bandit",
    "pip-audit": "python -m pip install pip-audit",
    "npm audit": "Install Node.js/npm: https://nodejs.org/",
    "PSScriptAnalyzer": "Install-Module PSScriptAnalyzer -Scope CurrentUser",
    "Trivy": "winget install AquaSecurity.Trivy",
}


@dataclass(slots=True)
class NormalizedFinding:
    severity: str
    scanner: str
    rule_id: str
    file_path: str
    line: int | None
    description: str
    evidence: str
    recommendation: str
    fingerprint: str = ""
    category: str = "code"
    confidence: int = 70
    suppressed: bool = False
    suppression_reason: str = ""

    def finalize(self, project: Path) -> NormalizedFinding:
        absolute = Path(self.file_path)
        if not absolute.is_absolute():
            absolute = project / absolute
        try:
            relative = absolute.resolve().relative_to(project.resolve()).as_posix()
        except (OSError, ValueError):
            relative = absolute.name
        self.file_path = str(absolute.resolve())
        self.severity = normalize_severity(self.severity)
        self.description = redact(self.description)
        self.evidence = redact(self.evidence)
        self.recommendation = redact(self.recommendation)
        rule = self.rule_id.casefold()
        if any(token in rule for token in ("secret", "credential", "password", "token")):
            self.category = "credentials"
        elif any(token in rule for token in ("docker", "container", "privileged")):
            self.category = "containers"
        elif any(token in rule for token in ("network", "http", "tls", "port", "firewall")):
            self.category = "network"
        elif any(token in rule for token in ("dependency", "vuln", "cve", "audit")):
            self.category = "dependencies"
        elif any(token in rule for token in ("prompt", "injection", "exfiltration", "tool-abuse")):
            self.category = "agent-safety"
        elif "syntax" in rule:
            self.category = "correctness"
        self.confidence = max(0, min(100, int(self.confidence)))
        if self.scanner == "ATLAS Syntax":
            self.confidence = max(self.confidence, 95)
        context = _finding_context(absolute, self.line)
        location = context or str(self.line or 0)
        identity = f"{self.scanner.casefold()}|{self.rule_id.casefold()}|{relative.casefold()}|{location}"
        self.fingerprint = hashlib.sha256(identity.encode("utf-8", "replace")).hexdigest()
        return self

    def record(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "scanner": self.scanner,
            "rule_id": self.rule_id,
            "file_path": self.file_path,
            "line": self.line,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "category": self.category,
            "confidence": self.confidence,
            "suppressed": self.suppressed,
            "suppression_reason": redact(self.suppression_reason),
        }


def _finding_context(path: Path, line: int | None) -> str:
    """Build a secret-safe identity that survives unrelated line insertions."""
    if not line or line < 1:
        return ""
    try:
        if path.stat().st_size > MAX_SOURCE_FILE_BYTES:
            return ""
        selected_line = ""
        with path.open(encoding="utf-8", errors="replace") as stream:
            for index, current in enumerate(stream, 1):
                if index == line:
                    selected_line = _normalized_fingerprint_line(current)
                    break
        occurrence = 0
        if selected_line:
            with path.open(encoding="utf-8", errors="replace") as stream:
                for index, current in enumerate(stream, 1):
                    if index > line:
                        break
                    if _normalized_fingerprint_line(current) == selected_line:
                        occurrence += 1
    except OSError:
        return ""
    if not selected_line:
        return ""
    identity = selected_line if occurrence == 1 else f"{selected_line}|occurrence={occurrence}"
    return hashlib.sha256(identity.encode("utf-8", "replace")).hexdigest()[:20]


def _normalized_fingerprint_line(value: str) -> str:
    normalized = value.strip().casefold()
    normalized = re.sub(r"(['\"]).*?\1", "[literal]", normalized)
    normalized = re.sub(r"\b\d+(?:\.\d+)?\b", "[number]", normalized)
    return re.sub(r"\s+", " ", normalized)


@dataclass(slots=True)
class ScannerAvailability:
    name: str
    available: bool
    install: str
    detail: str = ""
    status: str = "READY"
    version: str = ""
    started_at: str = ""
    finished_at: str = ""
    duration_seconds: float = 0.0
    files_analyzed: int | None = None
    files_skipped: int | None = None
    scope: str = ""
    exit_code: int | None = None
    reason: str = ""

    def record(self) -> dict[str, Any]:
        return {
            "name": self.name, "status": self.status, "available": self.available,
            "version": self.version, "started_at": self.started_at,
            "finished_at": self.finished_at, "duration_seconds": round(self.duration_seconds, 3),
            "files_analyzed": self.files_analyzed, "files_skipped": self.files_skipped,
            "scope": self.scope, "exit_code": self.exit_code,
            "reason": redact(self.reason or self.detail)[:240], "install": self.install,
        }


@dataclass(slots=True)
class CodeScanResult:
    findings: list[NormalizedFinding] = field(default_factory=list)
    availability: list[ScannerAvailability] = field(default_factory=list)
    coverage: dict[str, set[str] | None] = field(default_factory=dict)
    files_analyzed: int = 0
    files_skipped_large: int = 0
    files_skipped_unreadable: int = 0
    health: str = "PARTIAL"


def normalize_severity(value: str) -> str:
    mapping = {
        "ERROR": Severity.HIGH.value,
        "WARNING": Severity.MEDIUM.value,
        "WARN": Severity.MEDIUM.value,
        "HIGH": Severity.HIGH.value,
        "MEDIUM": Severity.MEDIUM.value,
        "MODERATE": Severity.MEDIUM.value,
        "LOW": Severity.LOW.value,
        "INFO": Severity.INFO.value,
        "INFORMATION": Severity.INFO.value,
        "CRITICAL": Severity.CRITICAL.value,
    }
    return mapping.get(str(value).upper(), Severity.MEDIUM.value)


def is_ignored(path: Path, project: Path) -> bool:
    try:
        parts = path.resolve().relative_to(project.resolve()).parts
    except (OSError, ValueError):
        return True
    return any(
        ignored_name(part, IGNORED_DIRS)
        for part in parts
    )


def is_priority_file(path: Path) -> bool:
    name = path.name.lower()
    return path.suffix.lower() in PRIORITY_SUFFIXES or name in PRIORITY_NAMES or name == ".env" or name.startswith(".env.")


def _is_test_or_fixture(path: Path, project: Path) -> bool:
    try:
        parts = {part.casefold() for part in path.relative_to(project).parts}
    except ValueError:
        return False
    return bool(parts & {"test", "tests", "fixtures"}) or path.name.casefold().startswith(("test_", "spec."))


def discover_files(project: Path) -> list[Path]:
    return _discover_files(project)[0]


def _discover_files(project: Path) -> tuple[list[Path], int, int]:
    found: list[Path] = []
    skipped_large = 0
    skipped_unreadable = 0

    def record_walk_error(_error: OSError) -> None:
        nonlocal skipped_unreadable
        skipped_unreadable += 1

    try:
        candidates = scoped_files(project, IGNORED_DIRS, onerror=record_walk_error)
        for path in candidates:
            try:
                if path.is_file() and is_priority_file(path) and not is_ignored(path, project):
                    if path.stat().st_size > MAX_SOURCE_FILE_BYTES:
                        skipped_large += 1
                    else:
                        found.append(path.resolve())
            except OSError:
                skipped_unreadable += 1
                continue
    except OSError:
        skipped_unreadable += 1
    return found, skipped_large, skipped_unreadable


def _run(command: list[str], cwd: Path, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    try:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        return subprocess.run(
            command, cwd=cwd, text=True, capture_output=True, check=False,
            timeout=timeout, shell=False, encoding="utf-8", errors="replace", creationflags=flags,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(command, 1, "", type(exc).__name__)


def _json(text: str) -> Any:
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None


class LocalCodeScanners:
    """Adapter layer for optional local tools plus a small always-on native pass."""

    def __init__(self, project: Path) -> None:
        self.project = project.expanduser().resolve()

    def scan(self, changed: list[Path] | None = None, changed_lines: dict[str, set[int]] | None = None) -> CodeScanResult:
        if changed is None:
            targets, skipped_large, skipped_unreadable = _discover_files(self.project)
        else:
            targets = []
            skipped_large = 0
            skipped_unreadable = 0
            for item in changed:
                try:
                    path = item.expanduser().resolve()
                    if path.exists() and path.is_file() and is_priority_file(path) and not is_ignored(path, self.project):
                        if path.stat().st_size > MAX_SOURCE_FILE_BYTES:
                            skipped_large += 1
                        else:
                            targets.append(path)
                except OSError:
                    skipped_unreadable += 1
        targets = list(dict.fromkeys(targets))
        result = CodeScanResult(
            files_analyzed=len(targets), files_skipped_large=skipped_large,
            files_skipped_unreadable=skipped_unreadable,
        )
        # Reconcile complete findings for each changed file. Filtering out unchanged
        # lines here would falsely resolve still-present findings in that file.
        runners = (
            ("ATLAS Native", lambda: self._native(targets, result)),
            ("ATLAS Security Guard", lambda: self._security_guard(targets, result)),
            ("ATLAS Syntax", lambda: self._syntax(targets, result)),
            ("Ruff", lambda: self._ruff(targets, result)),
            ("Semgrep", lambda: self._semgrep(targets, result)),
            ("Bandit", lambda: self._bandit(targets, result)),
            ("pip-audit", lambda: self._pip_audit(changed, result)),
            ("npm audit", lambda: self._npm_audit(changed, result)),
            ("PSScriptAnalyzer", lambda: self._psscriptanalyzer(targets, result)),
            ("Trivy", lambda: self._trivy(changed, result)),
        )
        for name, run in runners:
            started = datetime.now(UTC)
            clock_started = time.monotonic()
            try:
                run()
            except Exception as exc:
                result.coverage.pop(name, None)
                result.findings = [item for item in result.findings if item.scanner != name]
                if not any(item.name == name for item in result.availability):
                    self._availability(result, name, True)
                failed = next(item for item in reversed(result.availability) if item.name == name)
                failed.reason = f"Scanner raised {type(exc).__name__}; partial output discarded."
            finished = datetime.now(UTC)
            execution = next((item for item in reversed(result.availability) if item.name == name), None)
            if execution:
                execution.started_at = started.isoformat()
                execution.finished_at = finished.isoformat()
                execution.duration_seconds = max(0.0, time.monotonic() - clock_started)
                covered = result.coverage.get(name, set())
                execution.files_analyzed = len(covered) if covered is not None else None
                execution.scope = "FULL" if changed is None else "INCREMENTAL"
        self._finalize_execution_status(result, targets, changed)
        settings = Settings.load()
        ignored = {str(rule).casefold() for rule in settings.ignored_rules}
        unique: dict[str, NormalizedFinding] = {}
        for item in result.findings:
            item.finalize(self.project)
            if item.rule_id.casefold() in ignored or item.scanner.casefold() in ignored:
                continue
            override = settings.risk_overrides.get(item.rule_id) or settings.risk_overrides.get(item.scanner)
            if override:
                item.severity = normalize_severity(override)
            suppression = next((entry for entry in settings.finding_suppressions
                                if entry.get("fingerprint") == item.fingerprint
                                and _suppression_active(entry)), None)
            if suppression:
                item.suppressed = True
                item.suppression_reason = redact(suppression.get("reason", ""))[:500]
            unique[item.fingerprint] = item
        result.findings = list(unique.values())
        return result

    def _finalize_execution_status(
        self, result: CodeScanResult, targets: list[Path], changed: list[Path] | None,
    ) -> None:
        python_files = [path for path in targets if path.suffix.lower() == ".py"]
        power_shell_files = [path for path in targets if path.suffix.lower() == ".ps1"]
        requirement_files = [self.project / name for name in ("requirements.txt", "requirements-dev.txt")
                             if (self.project / name).is_file()]
        manifests = bool(requirement_files)
        npm_manifest = (self.project / "package.json").is_file()
        trivy_inputs = any(path.name.lower() in {
            "dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml",
            "package-lock.json", "requirements.txt", "pyproject.toml",
        } for path in targets) if changed is not None else (manifests or npm_manifest or any(
            path.name.lower() in {"dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml", "package-lock.json"}
            for path in targets
        ))
        applicable = {
            "ATLAS Native": True, "ATLAS Security Guard": True,
            "ATLAS Syntax": True,
            "Ruff": bool(python_files), "Semgrep": bool(targets), "Bandit": bool(python_files),
            "pip-audit": manifests and (changed is None or any(path.name.lower() in
                {"requirements.txt", "requirements-dev.txt"} for path in changed)),
            "npm audit": npm_manifest and (changed is None or any(path.name.lower() in
                {"package.json", "package-lock.json", "npm-shrinkwrap.json"} for path in changed)),
            "PSScriptAnalyzer": bool(power_shell_files), "Trivy": trivy_inputs,
        }
        partial = False
        for execution in result.availability:
            if execution.name == "pip-audit" and not manifests and (self.project / "pyproject.toml").is_file() and (
                changed is None or any(path.name.lower() == "pyproject.toml" for path in changed)
            ):
                execution.status = "SKIPPED"
                execution.reason = "No requirements file; this adapter cannot confirm pyproject dependency coverage."
                partial = True
                continue
            if not applicable.get(execution.name, False):
                execution.status = "NOT_APPLICABLE"
                execution.reason = "No files or manifests in this scan scope require this scanner."
                continue
            if not execution.available:
                execution.status = "NOT_INSTALLED"
                execution.reason = execution.detail or "Optional scanner is not installed."
                partial = True
                continue
            if execution.name not in result.coverage:
                execution.status = "TIMEOUT" if execution.reason == "Scanner timed out." else "FAILED"
                execution.reason = execution.reason or execution.detail or "Scanner did not return a validated result; prior findings were not resolved."
                partial = True
                continue
            covered = result.coverage[execution.name]
            if covered is None:
                execution.status = "SUCCESS"
            else:
                expected = {str(path.resolve()).casefold() for path in targets if
                            (execution.name not in {"ATLAS Syntax", "Ruff", "Bandit", "PSScriptAnalyzer"} or
                             (execution.name == "ATLAS Syntax" and path.suffix.lower() in {".py", ".json", ".toml"}) or
                             (execution.name in {"Ruff", "Bandit"} and path.suffix.lower() == ".py") or
                             (execution.name == "PSScriptAnalyzer" and path.suffix.lower() == ".ps1"))}
                if execution.name == "ATLAS Security Guard":
                    expected = {str(path.resolve()).casefold() for path in targets
                                if not _is_test_or_fixture(path, self.project)}
                if execution.name == "pip-audit":
                    expected = {str(path.resolve()).casefold() for path in requirement_files if
                                changed is None or any(path.resolve() == item.resolve() for item in changed)}
                if expected <= covered:
                    execution.status = "SUCCESS"
                else:
                    execution.status = "PARTIAL"
                    execution.reason = "One or more eligible files could not be confirmed as analyzed."
                    partial = True
        result.health = "PARTIAL" if partial or result.files_skipped_large or result.files_skipped_unreadable else "COMPLETE"


    def _syntax(self, targets: list[Path], result: CodeScanResult) -> None:
        """Parse whole changed files without importing or executing user code."""
        scanner = "ATLAS Syntax"
        self._availability(result, scanner, True)
        coverage: set[str] = set()
        for path in targets:
            if path.suffix.lower() not in {".py", ".json", ".toml"}:
                continue
            try:
                content = path.read_text(encoding="utf-8-sig")
            except (OSError, UnicodeError):
                continue
            coverage.add(str(path.resolve()).casefold())
            try:
                if path.suffix.lower() == ".py":
                    ast.parse(content, filename=str(path))
                elif path.suffix.lower() == ".json":
                    json.loads(content)
                else:
                    tomllib.loads(content)
            except (SyntaxError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
                result.findings.append(NormalizedFinding(
                    "MEDIUM", scanner, "syntax-" + path.suffix[1:].lower(), str(path),
                    getattr(exc, "lineno", None), "[BUG] Invalid syntax: " + path.suffix[1:].upper(),
                    "Parser rejected this file; source and values omitted.",
                    "Correct the syntax at the reported location; this is a code/configuration error, not evidence of intrusion.",
                ))
        result.coverage[scanner] = coverage

    def _ruff(self, targets: list[Path], result: CodeScanResult) -> None:
        executable = shutil.which("ruff")
        self._availability(result, "Ruff", bool(executable))
        python_files = [path for path in targets if path.suffix.lower() == ".py"]
        if not executable or not python_files:
            return
        # Isolated rules: no project plugins, execution, installation or auto-fix.
        process = _run([executable, "check", "--isolated", "--select", "F", "--output-format", "json",
                        *map(str, python_files)], self.project)
        payload = _json(process.stdout)
        if process.returncode not in {0, 1} or not isinstance(payload, list):
            self._process_failure(result, "Ruff", process)
            return
        self._process_success(result, "Ruff", process)
        result.coverage["Ruff"] = {str(path.resolve()).casefold() for path in python_files}
        for item in payload:
            code = item.get("code") or "invalid-syntax"
            result.findings.append(NormalizedFinding(
                "MEDIUM" if code in {"F821", "F822", "F823", "invalid-syntax"} else "LOW",
                "Ruff", code, item.get("filename", "unknown"),
                (item.get("location") or {}).get("row"), "[LINT] Python diagnostic " + code,
                "Diagnostic source omitted to protect sensitive values.",
                "Review Ruff rule " + code + "; this diagnostic is not a confirmed security vulnerability.",
            ))

    def _availability(self, result: CodeScanResult, name: str, available: bool, detail: str = "") -> None:
        result.availability.append(ScannerAvailability(
            name, available, INSTALL_HINTS.get(name, "Built into ATLAS"), redact(detail),
            status="READY" if available else "NOT_INSTALLED",
        ))

    @staticmethod
    def _process_failure(result: CodeScanResult, name: str, process: subprocess.CompletedProcess[str]) -> None:
        execution = next((item for item in reversed(result.availability) if item.name == name), None)
        if execution:
            execution.exit_code = process.returncode
            timed_out = "TimeoutExpired" in (process.stderr or "")
            execution.reason = "Scanner timed out." if timed_out else (
                f"Exit code {process.returncode} or invalid scanner output; raw output was not stored."
            )

    @staticmethod
    def _process_success(result: CodeScanResult, name: str, process: subprocess.CompletedProcess[str]) -> None:
        execution = next((item for item in reversed(result.availability) if item.name == name), None)
        if execution:
            execution.exit_code = process.returncode

    def _security_guard(
        self, targets: list[Path], result: CodeScanResult, changed_lines: dict[str, set[int]] | None = None,
    ) -> None:
        scanner = "ATLAS Security Guard"
        coverage: set[str] = set()
        severity = {"SUSPICIOUS": "LOW", "HIGH_RISK": "HIGH", "CRITICAL": "CRITICAL"}
        for path in targets:
            if _is_test_or_fixture(path, self.project):
                continue
            try:
                if path.stat().st_size > 2_000_000:
                    continue
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            key = str(path.resolve()).casefold()
            coverage.add(key)
            allowed = changed_lines.get(key) if changed_lines is not None else None
            for incident in assess_untrusted(content):
                if allowed is not None and incident.line not in allowed and incident.line != 1:
                    continue
                if LEVELS[incident.level] == 0:
                    continue
                result.findings.append(NormalizedFinding(
                    severity[incident.level], scanner, f"guard-{incident.category}", str(path), incident.line,
                    f"[{incident.level}] Untrusted-content {incident.category} detected",
                    incident.evidence, incident.recommendation,
                ))
        result.coverage[scanner] = coverage
        self._availability(result, scanner, True, "local deterministic guard")

    def _native(self, targets: list[Path], result: CodeScanResult, changed_lines: dict[str, set[int]] | None = None) -> None:
        scanner = "ATLAS Native"
        result.coverage[scanner] = set()
        secret_pattern = re.compile(
            r"(?i)\b(password|passwd|token|secret|api[_-]?key|connection[_-]?string)['\"]?\s*[:=]\s*"
            r"(?:['\"][A-Za-z0-9_./+:-]{6,}['\"]|[A-Za-z0-9_./+:-]{12,})"
        )
        for path in targets:
            try:
                if path.stat().st_size > 2_000_000:
                    continue
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            result.coverage[scanner].add(str(path.resolve()).casefold())
            literal_secret_lines = None
            if path.suffix.casefold() == '.py':
                literal_secret_lines = set()
                try:
                    tree = ast.parse(content)
                except (SyntaxError, ValueError):
                    tree = ast.Module(body=[], type_ignores=[])
                for node in ast.walk(tree):
                    if isinstance(node, (ast.Assign, ast.AnnAssign)):
                        value = node.value
                        targets_ast = node.targets if isinstance(node, ast.Assign) else [node.target]
                        names = [getattr(t, 'id', getattr(t, 'attr', '')) for t in targets_ast]
                        if isinstance(value, ast.Constant) and isinstance(value.value, str) and any(
                            re.search(r'(?i)(password|passwd|token|secret|api[_-]?key|connection[_-]?string)', n) for n in names
                        ):
                            literal_secret_lines.add(node.lineno)
                    if isinstance(node, ast.Dict):
                        for key, value in zip(node.keys, node.values, strict=True):
                            if (isinstance(key, ast.Constant) and isinstance(key.value, str)
                                    and isinstance(value, ast.Constant) and isinstance(value.value, str)
                                    and re.search(r'(?i)(password|token|secret|api[_-]?key)', key.value)):
                                literal_secret_lines.add(key.lineno)
            allowed_lines = None
            if changed_lines is not None:
                allowed_lines = changed_lines.get(str(path).casefold())
            is_test_file = _is_test_or_fixture(path, self.project)
            for line_number, line in enumerate(content.splitlines(), 1):
                if allowed_lines is not None and line_number not in allowed_lines:
                    continue
                secret_match = secret_pattern.search(line)
                placeholder = re.search(r'''(?i)["'](?:changeme|change-me|example|dummy|placeholder|your[_-][\w-]+|\[REDACTED\])["']''', line)
                secret_value = secret_match.group(0).split("=", 1)[-1].split(":", 1)[-1] if secret_match else ""
                if (secret_match and not placeholder and not is_test_file
                        and is_secret_candidate(secret_value)
                        and not line.lstrip().startswith(('#', '//'))
                        and (literal_secret_lines is None or line_number in literal_secret_lines)):
                    result.findings.append(NormalizedFinding(
                        Severity.HIGH.value, scanner, "hardcoded-secret", str(path), line_number,
                        "Possible hardcoded credential", "Sensitive value detected; value [REDACTED]",
                        "Remove it from source, rotate it if real, and use a secret store or environment variable.",
                        confidence=90 if re.fullmatch(r"(?:gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16})",
                                                       secret_value.strip().strip("'\"")) else 65,
                    ))
                exposed = re.search(r"(?i)(?:host\s*[:=]\s*['\"]0\.0\.0\.0['\"]|--host\s+0\.0\.0\.0)", line)
                if (path.suffix.lower() != ".py" and not is_test_file and exposed
                        and not line.lstrip().startswith(("#", "//")) and "re.compile" not in line):
                    result.findings.append(NormalizedFinding(
                        Severity.MEDIUM.value, scanner, "network-all-interfaces", str(path), line_number,
                        "Service may be exposed on all network interfaces",
                        "Wildcard bind address detected; surrounding configuration omitted.",
                        "Bind to localhost unless remote access is explicitly required.",
                    ))
            if path.suffix.lower() == ".py" and not is_test_file:
                self._native_python_ast(path, content, result, allowed_lines)
            privileged = re.search(r'(?im)^\s*privileged:\s*true\s*(?:#.*)?$|"privileged"\s*:\s*true\b', content)
            if path.name.lower() in PRIORITY_NAMES and privileged:
                line = content[:privileged.start()].count('\n') + 1
                result.findings.append(NormalizedFinding(
                    Severity.HIGH.value, scanner, "docker-privileged", str(path), line,
                    "Privileged mode declared in configuration", "Configuration allows privileged mode; running container not verified.",
                    "Remove privileged mode and grant only the capabilities the workload needs.",
                ))
            if path.name.lower() == "dockerfile" and not re.search(r"(?im)^\s*USER\s+(?!root\b|0\b)\S+", content):
                result.findings.append(NormalizedFinding(
                    Severity.MEDIUM.value, scanner, "docker-root-user", str(path), None,
                    "Container may run as root", "No explicit non-root USER directive found.",
                    "Create a dedicated user and set USER near the end of the Dockerfile.",
                ))
        self._availability(result, scanner, True, "built-in")

    @staticmethod
    def _native_python_ast(
        path: Path, content: str, result: CodeScanResult, allowed_lines: set[int] | None,
    ) -> None:
        """Find executable Python constructs without matching comments or strings."""
        try:
            tree = ast.parse(content, filename=str(path))
        except (SyntaxError, ValueError):
            return
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if (any(isinstance(target, ast.Name) and target.id.casefold() in {"host", "bind", "address"}
                        for target in targets) and isinstance(node.value, ast.Constant)
                        and node.value.value == "0.0.0.0"):
                    result.findings.append(NormalizedFinding(
                        Severity.MEDIUM.value, "ATLAS Native", "network-all-interfaces", str(path), node.lineno,
                        "Service may be exposed on all network interfaces",
                        "Wildcard bind assignment detected; runtime and firewall not verified.",
                        "Confirm whether external access is intended and restrict network exposure if unnecessary.",
                        confidence=70,
                    ))
            if not isinstance(node, ast.Call):
                continue
            line = getattr(node, "lineno", None)
            if allowed_lines is not None and line not in allowed_lines:
                continue
            if any(keyword.arg in {"host", "bind", "address"}
                   and isinstance(keyword.value, ast.Constant) and keyword.value.value == "0.0.0.0"
                   for keyword in node.keywords):
                result.findings.append(NormalizedFinding(
                    Severity.MEDIUM.value, "ATLAS Native", "network-all-interfaces", str(path), line,
                    "Service may be exposed on all network interfaces",
                    "Wildcard bind argument detected; runtime and firewall not verified.",
                    "Confirm whether external access is intended and restrict network exposure if unnecessary.",
                    confidence=70,
                ))
            if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
                result.findings.append(NormalizedFinding(
                    Severity.HIGH.value, "ATLAS Native", "python-eval", str(path), line,
                    "Dynamic code execution detected", "Executable AST call detected; arguments omitted.",
                    "Avoid eval/exec; parse and validate structured input.",
                ))
            if (isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "subprocess"
                    and node.func.attr in {"run", "Popen", "call", "check_output"}
                    and any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant)
                            and keyword.value.value is True for keyword in node.keywords)):
                result.findings.append(NormalizedFinding(
                    Severity.HIGH.value, "ATLAS Native", "python-shell-true", str(path), line,
                    "Subprocess with shell=True may allow command injection",
                    "Executable AST call uses shell=True; arguments omitted.",
                    "Pass an argument list and keep shell=False.",
                ))

    def _semgrep(self, targets: list[Path], result: CodeScanResult) -> None:
        executable = shutil.which("semgrep")
        probe = _run([executable, "--version"], self.project, 20) if executable else None
        available = bool(executable and probe and probe.returncode == 0)
        detail = "" if available or probe is None else (probe.stderr or probe.stdout)[:240]
        self._availability(result, "Semgrep", available, detail)
        if not available or not executable or not targets:
            return
        command = [executable, "scan", "--json", "--quiet", "--metrics", "off", "--config", "auto", *map(str, targets)]
        process = _run(command, self.project)
        payload = _json(process.stdout)
        if (process.returncode != 0 or not isinstance(payload, dict)
                or not isinstance(payload.get("results"), list) or payload.get("errors")):
            self._process_failure(result, "Semgrep", process)
            return
        scanned = (payload.get("paths") or {}).get("scanned")
        if not isinstance(scanned, list):
            execution = next(item for item in result.availability if item.name == "Semgrep")
            execution.reason = "Scanner did not report the files it analyzed."
            return
        self._process_success(result, "Semgrep", process)
        result.coverage["Semgrep"] = {
            str((self.project / path).resolve()).casefold() for path in scanned if isinstance(path, str)
        }
        for item in payload.get("results", []):
            extra = item.get("extra") or {}
            metadata = extra.get("metadata") or {}
            result.findings.append(NormalizedFinding(
                metadata.get("impact") or extra.get("severity") or "MEDIUM", "Semgrep", item.get("check_id", "unknown"),
                item.get("path", "unknown"), (item.get("start") or {}).get("line"),
                extra.get("message") or "Semgrep finding", "Matched code omitted to protect sensitive data.",
                metadata.get("fix") or metadata.get("recommendation") or "Review the matched code and apply the rule guidance.",
            ))

    def _bandit(self, targets: list[Path], result: CodeScanResult) -> None:
        executable = shutil.which("bandit")
        self._availability(result, "Bandit", bool(executable))
        python_files = [path for path in targets if path.suffix.lower() == ".py"]
        if not executable or not python_files:
            return
        process = _run([executable, "-q", "-f", "json", *map(str, python_files)], self.project)
        payload = _json(process.stdout)
        if (process.returncode not in {0, 1} or not isinstance(payload, dict)
                or not isinstance(payload.get("results"), list) or not isinstance(payload.get("errors", []), list)):
            self._process_failure(result, "Bandit", process)
            return
        failed_files = {
            str((self.project / error.get("filename", "")).resolve()).casefold()
            for error in payload.get("errors", []) if isinstance(error, dict) and error.get("filename")
        }
        self._process_success(result, "Bandit", process)
        result.coverage["Bandit"] = {
            str(path.resolve()).casefold() for path in python_files
            if str(path.resolve()).casefold() not in failed_files
        } if not payload.get("errors") or failed_files else set()
        for item in payload.get("results", []):
            rule_id = item.get("test_id", "unknown")
            filename = Path(item.get("filename", "unknown"))
            # Test assertions and subprocess imports alone are not vulnerabilities.
            if rule_id == "B404":
                continue
            if rule_id == "B101" and any(part.casefold() in {"test", "tests"} for part in filename.parts):
                continue
            result.findings.append(NormalizedFinding(
                item.get("issue_severity", "MEDIUM"), "Bandit", rule_id,
                item.get("filename", "unknown"), item.get("line_number"), item.get("issue_text", "Bandit finding"),
                "Matched code omitted to protect sensitive data.", "Review Bandit's rule guidance and use a safer API or validated input.",
            ))

    def _pip_audit(self, changed: list[Path] | None, result: CodeScanResult) -> None:
        executable = shutil.which("pip-audit")
        self._availability(result, "pip-audit", bool(executable))
        manifests = [self.project / name for name in ("requirements.txt", "requirements-dev.txt")
                     if (self.project / name).is_file()]
        if changed is not None:
            changed_paths = {path.resolve() for path in changed}
            manifests = [path for path in manifests if path.resolve() in changed_paths]
        if not executable or not manifests:
            return
        covered: set[str] = set()
        for manifest in manifests:
            process = _run([executable, "--format", "json", "--progress-spinner", "off", "-r", str(manifest)],
                           self.project, 25)
            payload = _json(process.stdout)
            valid_payload = (isinstance(payload, list) or
                             isinstance(payload, dict) and isinstance(payload.get("dependencies"), list))
            if process.returncode not in {0, 1} or not valid_payload:
                self._process_failure(result, "pip-audit", process)
                continue
            self._process_success(result, "pip-audit", process)
            covered.add(str(manifest.resolve()).casefold())
            dependencies = payload.get("dependencies", []) if isinstance(payload, dict) else payload
            for dependency in dependencies:
                if not isinstance(dependency, dict):
                    continue
                for vulnerability in dependency.get("vulns", []):
                    result.findings.append(NormalizedFinding(
                        Severity.HIGH.value, "pip-audit", vulnerability.get("id", "unknown"),
                        str(manifest), None,
                        f"Vulnerable Python dependency: {dependency.get('name', 'unknown')} {dependency.get('version', '')}",
                        f"Advisory {vulnerability.get('id', 'unknown')}; dependency details only.",
                        f"Upgrade to a fixed version: {', '.join(vulnerability.get('fix_versions') or []) or 'consult the advisory'}.",
                    ))
        if covered:
            result.coverage["pip-audit"] = covered

    def _npm_audit(self, changed: list[Path] | None, result: CodeScanResult) -> None:
        executable = shutil.which("npm")
        self._availability(result, "npm audit", bool(executable))
        package = self.project / "package.json"
        relevant = changed is None or any(path.name.lower() in {"package.json", "package-lock.json", "npm-shrinkwrap.json"} for path in changed)
        if not executable or not package.exists() or not relevant:
            return
        process = _run([executable, "audit", "--json", "--omit", "dev"], self.project, 25)
        payload = _json(process.stdout)
        if (process.returncode not in {0, 1} or not isinstance(payload, dict)
                or not isinstance(payload.get("auditReportVersion"), int)
                or not isinstance(payload.get("vulnerabilities"), dict) or payload.get("error")):
            self._process_failure(result, "npm audit", process)
            return
        self._process_success(result, "npm audit", process)
        result.coverage["npm audit"] = None
        for name, item in (payload.get("vulnerabilities") or {}).items():
            via = item.get("via") or []
            advisory = next((entry for entry in via if isinstance(entry, dict)), {})
            result.findings.append(NormalizedFinding(
                item.get("severity", "MEDIUM"), "npm audit", str(advisory.get("source") or advisory.get("url") or name),
                str(package), None, advisory.get("title") or f"Vulnerable npm dependency: {name}",
                f"Dependency {name}; advisory details only.", "Update the dependency and regenerate the lockfile after reviewing compatibility.",
            ))

    def _psscriptanalyzer(self, targets: list[Path], result: CodeScanResult) -> None:
        pwsh = shutil.which("pwsh") or shutil.which("powershell")
        available = False
        if pwsh:
            probe = _run([pwsh, "-NoProfile", "-NonInteractive", "-Command", "if (Get-Module -ListAvailable PSScriptAnalyzer) { 'yes' }"], self.project, 20)
            available = probe.stdout.strip() == "yes"
        self._availability(result, "PSScriptAnalyzer", available)
        scripts = [path for path in targets if path.suffix.lower() == ".ps1"]
        if not available or not scripts or not pwsh:
            return
        scope: set[str] = set()
        for script in scripts:
            escaped = str(script).replace("'", "''")
            command = f"ConvertTo-Json -InputObject @(Invoke-ScriptAnalyzer -Path '{escaped}' | Select-Object RuleName,Severity,Message,Line) -Depth 3 -Compress"
            process = _run([pwsh, "-NoProfile", "-NonInteractive", "-Command", command], self.project)
            payload = _json(process.stdout)
            if (process.returncode != 0 or not isinstance(payload, list)
                    or not all(isinstance(item, dict) for item in payload)):
                self._process_failure(result, "PSScriptAnalyzer", process)
                continue
            self._process_success(result, "PSScriptAnalyzer", process)
            scope.add(str(script).casefold())
            for item in payload:
                result.findings.append(NormalizedFinding(
                    item.get("Severity", "WARNING"), "PSScriptAnalyzer", item.get("RuleName", "unknown"),
                    str(script), item.get("Line"), item.get("Message", "PowerShell analyzer finding"),
                    "Matched script content omitted.", "Apply the PSScriptAnalyzer rule guidance.",
                ))
        result.coverage["PSScriptAnalyzer"] = scope

    def _trivy(self, changed: list[Path] | None, result: CodeScanResult) -> None:
        executable = shutil.which("trivy")
        probe = _run([executable, "--version"], self.project, 20) if executable else None
        available = bool(executable and probe and probe.returncode == 0)
        detail = "" if available or probe is None else (probe.stderr or probe.stdout)[:240]
        self._availability(result, "Trivy", available, detail)
        relevant_names = {"dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml", "package-lock.json", "requirements.txt", "pyproject.toml"}
        relevant = changed is None or any(path.name.lower() in relevant_names for path in changed)
        if not available or not executable or not relevant:
            return
        process = _run([executable, "fs", "--format", "json", "--scanners", "vuln,misconfig,secret", "--quiet", str(self.project)], self.project, 90)
        payload = _json(process.stdout)
        if process.returncode != 0 or not isinstance(payload, dict) or not isinstance(payload.get("Results"), list):
            self._process_failure(result, "Trivy", process)
            return
        if payload.get("Errors"):
            self._process_failure(result, "Trivy", process)
            return
        self._process_success(result, "Trivy", process)
        result.coverage["Trivy"] = None
        for section in payload.get("Results", []):
            target = section.get("Target") or str(self.project)
            for item in section.get("Vulnerabilities") or []:
                result.findings.append(NormalizedFinding(
                    item.get("Severity", "HIGH"), "Trivy", item.get("VulnerabilityID", "unknown"), target, None,
                    item.get("Title") or f"Vulnerable dependency {item.get('PkgName', '')}",
                    f"Advisory {item.get('VulnerabilityID', 'unknown')}; package details only.",
                    f"Upgrade to {item.get('FixedVersion') or 'a vendor-fixed version'}.",
                ))
            for item in section.get("Misconfigurations") or []:
                cause = item.get("CauseMetadata") or {}
                result.findings.append(NormalizedFinding(
                    item.get("Severity", "MEDIUM"), "Trivy", item.get("ID", "unknown"), target,
                    (cause.get("StartLine") if isinstance(cause, dict) else None), item.get("Title") or "Container misconfiguration",
                    "Matched configuration omitted.", item.get("Resolution") or "Apply the Trivy remediation guidance.",
                ))
            for item in section.get("Secrets") or []:
                result.findings.append(NormalizedFinding(
                    item.get("Severity", "HIGH"), "Trivy", item.get("RuleID", "secret"), target, item.get("StartLine"),
                    item.get("Title") or "Possible exposed secret", "Sensitive value [REDACTED]",
                    "Remove and rotate the secret, then use an approved secret store.",
                ))


def _suppression_active(entry: dict[str, str]) -> bool:
    try:
        expires = datetime.fromisoformat(entry["expires_at"])
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        return expires > datetime.now(UTC)
    except (KeyError, TypeError, ValueError):
        return False
