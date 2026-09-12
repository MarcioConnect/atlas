from __future__ import annotations

import json
import os
import platform
import shutil
import socket
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import psutil


@dataclass(slots=True)
class CommandResult:
    ok: bool
    stdout: str = ""
    stderr: str = ""
    returncode: int = -1


def run_readonly(command: list[str], timeout: float = 5.0) -> CommandResult:
    """Run a fixed read-only command without invoking a shell."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            errors="replace",
            timeout=timeout,
            shell=False,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        return CommandResult(result.returncode == 0, result.stdout.strip(), result.stderr.strip(), result.returncode)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return CommandResult(False, stderr=str(exc))


def powershell(script: str, timeout: float = 8.0) -> CommandResult:
    executable = shutil.which("powershell") or shutil.which("pwsh")
    if not executable:
        return CommandResult(False, stderr="PowerShell indisponivel")
    return run_readonly([executable, "-NoProfile", "-NonInteractive", "-Command", script], timeout)


def host_overview() -> dict[str, Any]:
    boot = datetime.fromtimestamp(psutil.boot_time(), UTC)
    uptime = datetime.now(UTC) - boot
    return {
        "hostname": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "uptime": human_duration(uptime),
        "boot_time": boot,
        "cpu_percent": psutil.cpu_percent(interval=0.05),
        "memory_percent": psutil.virtual_memory().percent,
    }


def human_duration(value: timedelta) -> str:
    seconds = max(0, int(value.total_seconds()))
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, _ = divmod(seconds, 60)
    if days:
        return f"{days}d {hours}h {minutes}m"
    return f"{hours}h {minutes}m"


def listening_ports() -> list[dict[str, Any]]:
    listeners: list[dict[str, Any]] = []
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError):
        return listeners
    for conn in connections:
        if conn.type != socket.SOCK_STREAM or conn.status != psutil.CONN_LISTEN or not conn.laddr:
            continue
        host, port = conn.laddr.ip, conn.laddr.port
        process = "unknown"
        if conn.pid:
            try:
                process = psutil.Process(conn.pid).name()
            except (psutil.Error, OSError):
                pass
        listeners.append({"host": host, "port": port, "pid": conn.pid, "process": process})
    return sorted(listeners, key=lambda item: (item["port"], item["host"]))


def services() -> list[dict[str, str]]:
    if os.name == "nt":
        try:
            return [
                {"name": svc.name(), "display_name": svc.display_name(), "status": svc.status()}
                for svc in psutil.win_service_iter()
            ]
        except (psutil.Error, OSError):
            return []
    result = run_readonly(
        ["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager", "--plain"],
        timeout=8,
    )
    found: list[dict[str, str]] = []
    if result.ok:
        for line in result.stdout.splitlines():
            parts = line.split(None, 4)
            if len(parts) >= 4:
                found.append({"name": parts[0], "display_name": parts[4] if len(parts) > 4 else parts[0], "status": parts[3]})
    return found


def docker_inventory() -> dict[str, Any]:
    docker = shutil.which("docker")
    if not docker:
        return {"available": False, "reason": "CLI Docker nao encontrado", "containers": []}
    probe = run_readonly([docker, "info", "--format", "{{json .ServerVersion}}"], timeout=6)
    if not probe.ok:
        return {"available": False, "reason": "Docker daemon inacessivel", "containers": []}
    listed = run_readonly([docker, "ps", "-a", "--no-trunc", "--format", "{{json .}}"], timeout=8)
    containers: list[dict[str, Any]] = []
    if listed.ok:
        for line in listed.stdout.splitlines():
            try:
                item = json.loads(line)
                containers.append(
                    {
                        "id": item.get("ID", "")[:12],
                        "name": item.get("Names", ""),
                        "image": item.get("Image", ""),
                        "status": item.get("Status", ""),
                        "ports": item.get("Ports", ""),
                    }
                )
            except json.JSONDecodeError:
                continue
    return {"available": True, "version": probe.stdout.strip('"'), "containers": containers}


def docker_inspect() -> list[dict[str, Any]]:
    docker = shutil.which("docker")
    if not docker:
        return []
    ids = run_readonly([docker, "ps", "-aq"], timeout=6)
    if not ids.ok or not ids.stdout:
        return []
    result = run_readonly([docker, "inspect", *ids.stdout.splitlines()], timeout=10)
    if not result.ok:
        return []
    try:
        parsed = json.loads(result.stdout)
        return parsed if isinstance(parsed, list) else []
    except json.JSONDecodeError:
        return []


def common_server_configs() -> list[Path]:
    paths = [
        Path("/etc/ssh/sshd_config"),
        Path("/etc/nginx/nginx.conf"),
        Path("/etc/apache2/apache2.conf"),
        Path("/etc/httpd/conf/httpd.conf"),
    ]
    if os.name == "nt":
        program_data = Path(os.environ.get("PROGRAMDATA", "C:/ProgramData"))
        paths.extend(
            [
                program_data / "ssh" / "sshd_config",
                Path("C:/nginx/conf/nginx.conf"),
                Path("C:/Apache24/conf/httpd.conf"),
            ]
        )
    return [path for path in paths if path.exists()]
