from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from atlas.code_scanners import INSTALL_HINTS, ScannerAvailability
from atlas.config import DB_PATH, Settings
from atlas.security import redact

OPTIONAL_SCANNERS = {
    "Ruff": "ruff",
    "Semgrep": "semgrep",
    "Bandit": "bandit",
    "pip-audit": "pip-audit",
    "npm audit": "npm",
    "PSScriptAnalyzer": "pwsh",
    "Trivy": "trivy",
}
MINIMUM_PYTHON = (3, 11)


@dataclass(slots=True)
class Check:
    name: str
    ok: bool
    detail: str
    fix: str = ""
    warning: bool = False


def _scanner_checks() -> list[Check]:
    checks: list[Check] = [Check("Scanner nativo ATLAS", True, "Sempre disponível")]
    for name, executable in OPTIONAL_SCANNERS.items():
        available = bool(shutil.which(executable))
        availability = ScannerAvailability(
            name, available, INSTALL_HINTS.get(name, "Built into ATLAS"),
            status="READY" if available else "NOT_INSTALLED",
        )
        checks.append(Check(
            f"Scanner opcional: {name}", available,
            "disponível" if available else "não instalado",
            fix="" if available else availability.install, warning=not available,
        ))
    return checks


def _python_check() -> Check:
    ok = sys.version_info >= MINIMUM_PYTHON
    version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    return Check(
        "Python", ok, f"versão {version}",
        fix="Instale Python 3.11+ em https://www.python.org/downloads/", warning=not ok,
    )


def _ollama_check() -> Check:
    installed = bool(shutil.which("ollama"))
    running = False
    try:
        with socket.create_connection(("127.0.0.1", 11434), timeout=0.3):
            running = True
    except OSError:
        running = False
    if running:
        return Check("Ollama (IA local)", True, "serviço ativo em 127.0.0.1:11434")
    if installed:
        return Check("Ollama (IA local)", False, "instalado, mas o serviço está parado",
                     fix="ollama serve", warning=True)
    return Check("Ollama (IA local)", False, "não instalado — recursos de IA ficam desativados",
                 fix="winget install Ollama.Ollama", warning=True)


def _monitor_check() -> Check:
    from atlas.monitor import is_running, read_state
    if is_running():
        roots = read_state().get("roots") or []
        return Check("Monitor residente", True, f"ativo · {len(roots)} caminho(s)")
    return Check("Monitor residente", False, "parado",
                 fix="atlas monitor start", warning=True)


def _login_task_check() -> Check:
    if os.name != "nt":
        return Check("Tarefa de login", False, "disponível apenas no Windows", warning=True)
    result = subprocess.run(["schtasks", "/Query", "/TN", "ATLAS-Monitor"],
                            text=True, capture_output=True, check=False)
    if result.returncode == 0:
        return Check("Tarefa de login", True, "ATLAS-Monitor registrada")
    return Check("Tarefa de login", False, "ATLAS-Monitor não registrada",
                 fix="atlas monitor install", warning=True)


def _database_check() -> Check:
    try:
        from atlas.database import Database
        database = Database()
        database.latest_scan()
        size = DB_PATH.stat().st_size if DB_PATH.exists() else 0
        return Check("Banco de dados local", True, f"{DB_PATH} ({size} bytes)")
    except Exception as exc:
        return Check("Banco de dados local", False, redact(f"{type(exc).__name__}: {exc}"),
                     fix="Verifique permissões em %LOCALAPPDATA%\\ATLAS")


def collect_checks() -> list[Check]:
    checks = [_python_check()]
    checks.extend(_scanner_checks())
    checks.extend([_ollama_check(), _monitor_check(), _login_task_check(), _database_check()])
    return checks


def _apply_fix(check: Check) -> str:
    command = check.fix.strip()
    if not command:
        return "sem correção automática"
    if command.startswith("atlas "):
        return f"execute manualmente: {command}"
    lowered = command.lower()
    if lowered.startswith(("python -m pip", "py -m pip", "pip ", "install-module")):
        shell = ["powershell", "-NoProfile", "-Command", command] if sys.platform == "win32" else ["bash", "-lc", command]
        result = subprocess.run(shell, text=True, capture_output=True, check=False)
        return "aplicado" if result.returncode == 0 else "falhou — execute manualmente"
    return f"execute manualmente: {command}"


def run_doctor(interactive: bool = True, console=None) -> tuple[int, int]:
    from rich.console import Console
    from rich.table import Table

    console = console or Console()
    checks = collect_checks()
    failures = warnings = 0
    table = Table(title="ATLAS · Diagnóstico", show_lines=False)
    table.add_column("Status")
    table.add_column("Verificação")
    table.add_column("Detalhe")
    for check in checks:
        if check.ok:
            mark = "[green]OK[/green]"
        elif check.warning:
            mark = "[yellow]AVISO[/yellow]"
            warnings += 1
        else:
            mark = "[red]FALHA[/red]"
            failures += 1
        table.add_row(mark, check.name, check.detail)
    console.print(table)

    fixable = [check for check in checks if not check.ok and check.fix]
    if not fixable:
        console.print("[green]Nada a corrigir.[/green]")
        return failures, warnings
    if not interactive:
        console.print("[dim]Correções sugeridas:[/dim]")
        for check in fixable:
            console.print(f"  · {check.name}: [b]{check.fix}[/b]")
        return failures, warnings
    for check in fixable:
        if not check.fix.startswith("atlas "):
            console.print(f"[cyan]{check.name}[/]: [b]{check.fix}[/b]")
            continue
        if check.name == "Monitor residente":
            from atlas.monitor import start_background
            roots = [Path(item) for item in (Settings.load().watch_paths or [])]
            if roots and console.input(f"Corrigir “[b]{check.name}[/b]”? [s/N] ").strip().lower() in {"s", "y", "sim"}:
                start_background(roots)
                console.print("[green]Monitor iniciado.[/green]")
        elif check.name == "Tarefa de login":
            from atlas.monitor import install_startup
            roots = [Path(item) for item in (Settings.load().watch_paths or [])]
            if roots and console.input(f"Corrigir “[b]{check.name}[/b]”? [s/N] ").strip().lower() in {"s", "y", "sim"}:
                installed, detail = install_startup(roots)
                console.print("[green]Tarefa registrada.[/green]" if installed else f"[red]{detail}[/red]")
    return failures, warnings
