from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shutil
import subprocess
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from atlas.config import Settings
from atlas.file_scope import ignored_name, scoped_files
from atlas.models import Severity
from atlas.security import redact
from atlas.security_guard import LEVELS, assess_untrusted

IGNORED_DIRS = {
    ".git", ".hg", ".svn", ".tox", ".nox", "node_modules", "venv", ".venv",
    "__pycache__", "_pycache_", "site-packages", "dist", "build", "appdata",
    ".vscode", ".idea", "docs", "documentation", "examples", "vendor", "third_party", "generated",
}
PRIORITY_SUFFIXES = {".py", ".js", ".ts", ".tsx", ".jsx", ".html", ".ps1", ".bat", ".json", ".yaml", ".yml", ".toml"}
PRIORITY_NAMES = {"dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
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
        identity = f"{self.scanner.casefold()}|{self.rule_id.casefold()}|{relative.casefold()}|{self.line or 0}"
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
        }


@dataclass(slots=True)
class ScannerAvailability:
    name: str
    available: bool
    install: str
    detail: str = ""


@dataclass(slots=True)
class CodeScanResult:
    findings: list[NormalizedFinding] = field(default_factory=list)
    availability: list[ScannerAvailability] = field(default_factory=list)
    coverage: dict[str, set[str] | None] = field(default_factory=dict)
    files_analyzed: int = 0


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
    return path.suffix.lower() in PRIORITY_SUFFIXES or path.name.lower() in PRIORITY_NAMES


def discover_files(project: Path) -> list[Path]:
    found: list[Path] = []
    try:
        candidates = scoped_files(project, IGNORED_DIRS)
        for path in candidates:
            try:
                if path.is_file() and is_priority_file(path) and not is_ignored(path, project):
                    found.append(path.resolve())
            except OSError:
                continue
    except OSError:
        pass
    return found


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
            targets = discover_files(self.project)
        else:
            targets = []
            for item in changed:
                path = item.expanduser().resolve()
                if path.exists() and path.is_file() and is_priority_file(path) and not is_ignored(path, self.project):
                    targets.append(path)
        result = CodeScanResult(files_analyzed=len(targets))
        self._native(targets, result, changed_lines=changed_lines)
        self._security_guard(targets, result, changed_lines=changed_lines)
        self._syntax(targets, result)
        self._ruff(targets, result)
        self._semgrep(targets, result)
        self._bandit(targets, result)
        self._pip_audit(changed, result)
        self._npm_audit(changed, result)
        self._psscriptanalyzer(targets, result)
        self._trivy(changed, result)
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
            unique[item.fingerprint] = item
        result.findings = list(unique.values())
        return result

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
            return
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
        result.availability.append(ScannerAvailability(name, available, INSTALL_HINTS.get(name, "Built into ATLAS"), redact(detail)))

    def _security_guard(
        self, targets: list[Path], result: CodeScanResult, changed_lines: dict[str, set[int]] | None = None,
    ) -> None:
        scanner = "ATLAS Security Guard"
        coverage: set[str] = set()
        severity = {"SUSPICIOUS": "LOW", "HIGH_RISK": "HIGH", "CRITICAL": "CRITICAL"}
        for path in targets:
            try:
                relative_parts = {part.casefold() for part in path.relative_to(self.project).parts}
            except ValueError:
                continue
            is_test_fixture = "tests" in relative_parts or path.name.casefold().startswith(("test_", "spec."))
            if is_test_fixture:
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
        result.coverage[scanner] = {str(path.resolve()).casefold() for path in targets}
        secret_pattern = re.compile(
            r"(?i)\b(password|passwd|token|secret|api[_-]?key|connection[_-]?string)\s*[:=]\s*"
            r"(?:['\"][A-Za-z0-9_./+:-]{6,}['\"]|[A-Za-z0-9_./+:-]{12,})"
        )
        for path in targets:
            try:
                if path.stat().st_size > 2_000_000:
                    continue
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            allowed_lines = None
            if changed_lines is not None:
                allowed_lines = changed_lines.get(str(path).casefold())
            for line_number, line in enumerate(content.splitlines(), 1):
                if allowed_lines is not None and line_number not in allowed_lines:
                    continue
                if secret_pattern.search(line):
                    result.findings.append(NormalizedFinding(
                        Severity.HIGH.value, scanner, "hardcoded-secret", str(path), line_number,
                        "Possible hardcoded credential", "Sensitive value detected; value [REDACTED]",
                        "Remove it from source, rotate it if real, and use a secret store or environment variable.",
                    ))
                exposed = re.search(r"(?i)(?:host\s*[:=]\s*['\"]0\.0\.0\.0['\"]|--host\s+0\.0\.0\.0)", line)
                if exposed and "re.compile" not in line:
                    result.findings.append(NormalizedFinding(
                        Severity.MEDIUM.value, scanner, "network-all-interfaces", str(path), line_number,
                        "Service may be exposed on all network interfaces",
                        "Wildcard bind address detected; surrounding configuration omitted.",
                        "Bind to localhost unless remote access is explicitly required.",
                    ))
            if path.suffix.lower() == ".py":
                self._native_python_ast(path, content, result, allowed_lines)
            lower = content.lower()
            if path.name.lower() in PRIORITY_NAMES and ("privileged: true" in lower or '"privileged": true' in lower):
                line = lower[:lower.index("privileged: true")].count("\n") + 1 if "privileged: true" in lower else None
                result.findings.append(NormalizedFinding(
                    Severity.CRITICAL.value, scanner, "docker-privileged", str(path), line,
                    "Privileged container enabled", "privileged mode is enabled; surrounding configuration omitted.",
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
            if not isinstance(node, ast.Call):
                continue
            line = getattr(node, "lineno", None)
            if allowed_lines is not None and line not in allowed_lines:
                continue
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
        if not isinstance(payload, dict):
            return
        result.coverage["Semgrep"] = {str(path).casefold() for path in targets}
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
        if not isinstance(payload, dict):
            return
        result.coverage["Bandit"] = {str(path).casefold() for path in python_files}
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
        manifests = [self.project / name for name in ("requirements.txt", "requirements-dev.txt") if (self.project / name).exists()]
        pyproject = self.project / "pyproject.toml"
        relevant = changed is None or any(path.name.lower() in {"requirements.txt", "requirements-dev.txt", "pyproject.toml"} for path in changed)
        if not executable or not relevant or (not manifests and not pyproject.exists()):
            return
        command = [executable, "--format", "json", "--progress-spinner", "off"]
        if manifests:
            command.extend(["-r", str(manifests[0])])
        else:
            command.append(str(self.project))
        process = _run(command, self.project, 25)
        payload = _json(process.stdout)
        if not isinstance(payload, (dict, list)):
            return
        result.coverage["pip-audit"] = None
        dependencies = payload.get("dependencies", []) if isinstance(payload, dict) else payload
        for dependency in dependencies:
            for vulnerability in dependency.get("vulns", []):
                result.findings.append(NormalizedFinding(
                    Severity.HIGH.value, "pip-audit", vulnerability.get("id", "unknown"),
                    str(manifests[0] if manifests else pyproject), None,
                    f"Vulnerable Python dependency: {dependency.get('name', 'unknown')} {dependency.get('version', '')}",
                    f"Advisory {vulnerability.get('id', 'unknown')}; dependency details only.",
                    f"Upgrade to a fixed version: {', '.join(vulnerability.get('fix_versions') or []) or 'consult the advisory'}.",
                ))

    def _npm_audit(self, changed: list[Path] | None, result: CodeScanResult) -> None:
        executable = shutil.which("npm")
        self._availability(result, "npm audit", bool(executable))
        package = self.project / "package.json"
        relevant = changed is None or any(path.name.lower() in {"package.json", "package-lock.json", "npm-shrinkwrap.json"} for path in changed)
        if not executable or not package.exists() or not relevant:
            return
        process = _run([executable, "audit", "--json", "--omit", "dev"], self.project, 25)
        payload = _json(process.stdout)
        if not isinstance(payload, dict):
            return
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
            command = f"Invoke-ScriptAnalyzer -Path '{escaped}' | Select-Object RuleName,Severity,Message,Line | ConvertTo-Json -Depth 3"
            process = _run([pwsh, "-NoProfile", "-NonInteractive", "-Command", command], self.project)
            if process.returncode != 0:
                continue
            scope.add(str(script).casefold())
            payload = _json(process.stdout)
            rows = payload if isinstance(payload, list) else [payload] if isinstance(payload, dict) else []
            for item in rows:
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
        if not isinstance(payload, dict):
            return
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
