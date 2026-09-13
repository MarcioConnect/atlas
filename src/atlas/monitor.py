from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

import psutil
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from atlas.config import Settings, data_dir
from atlas.database import Database
from atlas.models import MonitorEvent, Severity
from atlas.security import SecurityScanner, redact
from atlas.system import docker_inventory, services

STATE_PATH = data_dir() / "monitor.json"
STOP_PATH = data_dir() / "monitor.stop"
START_LOCK_PATH = data_dir() / "monitor.start.lock"
SKIP_PARTS = {
    ".git", ".hg", ".svn", ".cache", ".pytest_cache", "__pycache__", "node_modules",
    ".venv", "venv", "AppData", "$Recycle.Bin", "System Volume Information",
    ".review-",
}
SENSITIVE_NAMES = {".env", "id_rsa", "id_ed25519", "credentials", "secrets", "tokens"}
RISK_EXTENSIONS = {".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".py", ".service"}


def _fingerprint(kind: str, component: str, detail: str) -> str:
    return hashlib.sha256(f"{kind}|{component}|{detail}".encode("utf-8", "replace")).hexdigest()


def _safe_path(value: str) -> str:
    path = Path(value)
    if path.name.lower() in SENSITIVE_NAMES or any(marker in path.name.lower() for marker in ("secret", "token", "password")):
        return redact(str(path.parent / "[SENSITIVE_FILE]"))[:255]
    return redact(str(path))[:255]


def _state_payload(pid: int, roots: list[Path], status: str = "running") -> dict:
    return {
        "pid": pid,
        "status": status,
        "roots": [str(root) for root in roots],
        "heartbeat": datetime.now(UTC).isoformat(),
    }


def read_state() -> dict:
    try:
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {"status": "stopped", "pid": None, "roots": []}


def is_running() -> bool:
    state = read_state()
    pid = state.get("pid")
    if not isinstance(pid, int) or not psutil.pid_exists(pid):
        return False
    try:
        heartbeat = datetime.fromisoformat(str(state.get("heartbeat")))
        return (datetime.now(UTC) - heartbeat).total_seconds() < 20
    except (TypeError, ValueError):
        return False


class ChangeHandler(FileSystemEventHandler):
    def __init__(self, database: Database) -> None:
        self.database = database
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def on_any_event(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        source = str(getattr(event, "dest_path", "") or event.src_path)
        try:
            parts = Path(source).parts
        except (OSError, ValueError):
            return
        if any(part in SKIP_PARTS or (".review-" in SKIP_PARTS and part.casefold().startswith(".review-"))
               or (part.casefold().startswith(".pytest") and ".pytest_cache" in SKIP_PARTS) for part in parts):
            return
        kind = str(event.event_type)
        key = f"{kind}:{source.lower()}"
        now = time.monotonic()
        with self._lock:
            if now - self._seen.get(key, 0) < 1.5:
                return
            self._seen[key] = now
            if len(self._seen) > 5000:
                self._seen = {item: stamp for item, stamp in self._seen.items() if now - stamp < 60}
        name = Path(source).name.lower()
        if name in SENSITIVE_NAMES or any(marker in name for marker in ("secret", "token", "password")):
            severity, risk = Severity.HIGH, "Arquivo potencialmente sensível foi alterado; o conteúdo não foi lido."
        elif Path(source).suffix.lower() in RISK_EXTENSIONS:
            severity, risk = Severity.MEDIUM, "Código executável ou configuração ativa foi alterado."
        else:
            severity, risk = Severity.INFO, "Mudança de arquivo observada."
        self.database.add_monitor_event(MonitorEvent(
            kind="file", severity=severity.value, component=_safe_path(source), detail=kind,
            risk=risk, fingerprint=_fingerprint("file", source, kind),
        ))


class MonitorService:
    def __init__(self, roots: list[Path], database: Database | None = None) -> None:
        requested = [root.expanduser().resolve() for root in roots if root.exists()]
        self.roots: list[Path] = []
        for root in requested:
            # Alguns perfis Windows negam FILE_LIST_DIRECTORY na raiz do usuário,
            # embora suas pastas reais sejam acessíveis. Nesse caso observamos cada
            # pasta de trabalho e ignoramos junctions/caches protegidos.
            if os.name == "nt" and root == Path.home().resolve():
                try:
                    children = list(root.iterdir())
                except OSError:
                    children = []
                for child in children:
                    try:
                        if (child.is_dir() and not child.is_symlink() and child.name not in SKIP_PARTS
                                and not child.name.startswith(".")):
                            self.roots.append(child.resolve())
                    except OSError:
                        continue
            else:
                self.roots.append(root)
        self.database = database or Database()
        self.settings = Settings.load()
        self.observers: list[Observer] = []
        self._processes: set[tuple[int, float]] = set()
        self._listeners: set[tuple[str, int, int | None]] = set()
        self._services: dict[str, str] = {}
        self._containers: dict[str, str] = {}
        self._firewall: dict[str, bool] = {}

    def record(self, kind: str, severity: Severity, component: str, detail: str, risk: str = "") -> None:
        self.database.add_monitor_event(MonitorEvent(
            kind=kind, severity=severity.value, component=redact(component)[:255], detail=redact(detail),
            risk=redact(risk), fingerprint=_fingerprint(kind, component, detail),
        ))

    def _snapshot_processes(self, initial: bool = False) -> None:
        current: set[tuple[int, float]] = set()
        names: dict[tuple[int, float], str] = {}
        for proc in psutil.process_iter(["pid", "name", "create_time"]):
            try:
                identity = (proc.info["pid"], float(proc.info["create_time"] or 0))
                current.add(identity)
                names[identity] = str(proc.info["name"] or "process")
            except (psutil.Error, TypeError, ValueError):
                continue
        if not initial:
            for identity in current - self._processes:
                pid, _ = identity
                self.record("process", Severity.INFO, names[identity], f"processo iniciado · pid={pid}")
            for identity in self._processes - current:
                pid, _ = identity
                self.record("process", Severity.INFO, "process", f"processo encerrado - pid={pid}")
        self._processes = current

    def _snapshot_listeners(self, initial: bool = False) -> None:
        current: set[tuple[str, int, int | None]] = set()
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.Error, OSError, RuntimeError):
            return
        for conn in connections:
            if conn.status != psutil.CONN_LISTEN or not conn.laddr:
                continue
            identity = (str(conn.laddr.ip), int(conn.laddr.port), conn.pid)
            current.add(identity)
        if not initial:
            for address, port, pid in current - self._listeners:
                # Compare observed listeners; this does not bind a socket.
                exposed = address in {"0.0.0.0", "::"}  # nosec B104
                self.record(
                    "network", Severity.MEDIUM if exposed else Severity.INFO, f"{address}:{port}",
                    f"nova porta em escuta · pid={pid or 'desconhecido'}",
                    "Novo serviço acessível pela rede." if exposed else "Listener restrito ao host local.",
                )
        self._listeners = current

    def _snapshot_services(self, initial: bool = False) -> None:
        current = {item["name"]: item["status"] for item in services()}
        if not initial:
            for name, status in current.items():
                previous = self._services.get(name)
                if previous is not None and previous != status:
                    self.record("service", Severity.MEDIUM, name, f"status {previous} -> {status}", "Serviço mudou de estado.")
        self._services = current

    def _snapshot_docker(self, initial: bool = False) -> None:
        inventory = docker_inventory()
        current = {str(item.get("name") or item.get("id")): str(item.get("status")) for item in inventory.get("containers", [])}
        if not initial:
            for name, status in current.items():
                previous = self._containers.get(name)
                if previous != status:
                    self.record("container", Severity.MEDIUM, name, f"status {previous or 'novo'} -> {status}", "Container criado ou alterado.")
        self._containers = current

    def _snapshot_firewall(self, initial: bool = False) -> None:
        """Track Windows Defender Firewall profile changes without admin rights."""
        if os.name != "nt":
            return
        command = ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                   "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress"]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=8,
                                    encoding="utf-8", errors="replace", check=False)
            payload = json.loads(result.stdout or "[]")
            if isinstance(payload, dict):
                payload = [payload]
            current = {str(item.get("Name")): bool(item.get("Enabled")) for item in payload if isinstance(item, dict)}
        except (OSError, subprocess.SubprocessError, ValueError, TypeError):
            return
        if not current:
            return
        if not initial:
            for profile, enabled in current.items():
                previous = self._firewall.get(profile)
                if previous is not None and previous != enabled:
                    self.record(
                        "firewall", Severity.HIGH if not enabled else Severity.INFO,
                        profile, f"firewall {'ativado' if enabled else 'desativado'}",
                        "A superfície de rede mudou; confirme a política aplicada.",
                    )
        self._firewall = current

    def run(self) -> None:
        STOP_PATH.unlink(missing_ok=True)
        handler = ChangeHandler(self.database)
        for root in self.roots:
            observer = Observer()
            observer.schedule(handler, str(root), recursive=root.is_dir())
            try:
                observer.start()
            except (OSError, PermissionError):
                continue
            self.observers.append(observer)
        if not self.observers:
            raise RuntimeError("Nenhum caminho pôde ser observado com as permissões atuais")
        self._snapshot_processes(initial=True)
        self._snapshot_listeners(initial=True)
        self._snapshot_services(initial=True)
        self._snapshot_docker(initial=True)
        self._snapshot_firewall(initial=True)
        self.record("monitor", Severity.INFO, "ATLAS", f"monitor iniciado em {len(self.roots)} caminho(s)")
        last_services = last_docker = last_scan = time.monotonic()
        failure = ""
        try:
            while not STOP_PATH.exists():
                started = time.monotonic()
                for collector in (self._snapshot_processes, self._snapshot_listeners, self._snapshot_firewall):
                    try:
                        collector()
                    except Exception as exc:
                        self.record("monitor-error", Severity.LOW, collector.__name__, type(exc).__name__)
                if started - last_services >= 15:
                    try:
                        self._snapshot_services()
                    except Exception as exc:
                        self.record("monitor-error", Severity.LOW, "services", type(exc).__name__)
                    last_services = started
                if started - last_docker >= 30:
                    try:
                        self._snapshot_docker()
                    except Exception as exc:
                        self.record("monitor-error", Severity.LOW, "docker", type(exc).__name__)
                    last_docker = started
                if started - last_scan >= self.settings.monitor_security_interval_seconds:
                    try:
                        SecurityScanner(self.database).scan(self.roots)
                    except Exception as exc:
                        self.record("monitor-error", Severity.LOW, "security-scan", type(exc).__name__)
                    last_scan = started
                STATE_PATH.write_text(json.dumps(_state_payload(os.getpid(), self.roots)), encoding="utf-8")
                time.sleep(max(1.0, self.settings.monitor_interval_seconds))
        except Exception as exc:
            failure = type(exc).__name__
            self.record("monitor-error", Severity.MEDIUM, "daemon", failure, "O monitor encontrou um erro e foi encerrado.")
        finally:
            for observer in self.observers:
                observer.stop()
            for observer in self.observers:
                observer.join(timeout=5)
            self.record("monitor", Severity.INFO, "ATLAS", "monitor finalizado")
            final = _state_payload(os.getpid(), self.roots, "error" if failure else "stopped")
            if failure:
                final["error"] = failure
            STATE_PATH.write_text(json.dumps(final), encoding="utf-8")
            STOP_PATH.unlink(missing_ok=True)


def _atlas_command(*arguments: str) -> list[str]:
    """Build a self-relaunch command for source and frozen installations."""
    if getattr(sys, "frozen", False):
        return [sys.executable, *arguments]
    return [sys.executable, "-m", "atlas", *arguments]


def start_background(roots: list[Path]) -> int:
    if is_running():
        return int(read_state()["pid"])
    # Prevent two nearly simultaneous ``atlas agent``/``monitor start`` calls
    # from spawning duplicate resident monitors (and, on some shells, extra
    # console windows).  The lock is deliberately tiny and recreated per
    # launch; stale locks are safe to remove when no monitor is alive.
    try:
        lock_fd = os.open(START_LOCK_PATH, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(lock_fd, str(os.getpid()).encode("ascii", "replace"))
        os.close(lock_fd)
    except FileExistsError:
        if is_running():
            return int(read_state()["pid"])
        try:
            START_LOCK_PATH.unlink(missing_ok=True)
        except OSError:
            pass
        return start_background(roots)
    try:
        STOP_PATH.unlink(missing_ok=True)
        command = _atlas_command("_monitor-run")
        for root in roots:
            command.extend(["--watch", str(root.resolve())])
        flags = 0
        child_env = os.environ.copy()
        if getattr(sys, "frozen", False):
            child_env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
        if os.name == "nt":
            flags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS | subprocess.CREATE_NO_WINDOW
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   close_fds=True, creationflags=flags, env=child_env)
        STATE_PATH.write_text(json.dumps(_state_payload(process.pid, roots, "starting")), encoding="utf-8")
        return process.pid
    finally:
        START_LOCK_PATH.unlink(missing_ok=True)


def stop_background(timeout: float = 10.0) -> bool:
    if not is_running():
        return False
    STOP_PATH.touch()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and is_running():
        time.sleep(0.25)
    return not is_running()


def install_startup(roots: list[Path]) -> tuple[bool, str]:
    if os.name != "nt":
        return False, "Instalação automática está disponível neste MVP apenas no Windows."
    arguments = " ".join(f'--watch "{root.resolve()}"' for root in roots)
    if getattr(sys, "frozen", False):
        task_command = f'"{sys.executable}" monitor start {arguments}'
    else:
        pythonw = Path(sys.executable).with_name("pythonw.exe")
        executable = pythonw if pythonw.exists() else Path(sys.executable)
        task_command = f'"{executable}" -m atlas monitor start {arguments}'
    result = subprocess.run(["schtasks", "/Create", "/SC", "ONLOGON", "/TN", "ATLAS-Monitor",
                             "/TR", task_command, "/F"], text=True, capture_output=True, check=False)
    if result.returncode == 0:
        return True, (result.stdout or "Tarefa ATLAS-Monitor criada.").strip()

    # Ambientes corporativos frequentemente bloqueiam schtasks para usuários comuns.
    # A pasta Startup é o fallback oficial por usuário e não requer elevação.
    appdata = os.environ.get("APPDATA", "").strip()
    if not appdata:
        return False, (result.stderr or result.stdout).strip()
    startup = Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    startup.mkdir(parents=True, exist_ok=True)
    launcher = startup / "ATLAS-Monitor.cmd"
    launcher.write_text(f'@echo off\r\nstart "" /b {task_command}\r\n', encoding="utf-8")
    return True, f"Inicialização por usuário instalada em {launcher}"
