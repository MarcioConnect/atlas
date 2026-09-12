from __future__ import annotations

import json
import os
import shlex
import shutil
import socket
import subprocess
import sys
import uuid
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select

from atlas.config import data_dir
from atlas.database import Database
from atlas.models import Event, OperationSession, Snapshot
from atlas.security import redact
from atlas.system import docker_inspect, services

SAFE_ARGUMENT_COMMANDS = {
    "cd", "dir", "ls", "pwd", "whoami", "hostname", "ipconfig", "ifconfig", "get-service",
}
SENSITIVE_MARKERS = {"password", "passwd", "token", "secret", "api-key", "apikey", "key", "credential"}
SNAPSHOT_LIMIT = 5000
SNAPSHOT_SKIP = {".git", ".venv", "venv", "node_modules", "__pycache__", ".cache", "AppData"}


def safe_command_metadata(command: str) -> tuple[str, str, str]:
    try:
        parts = shlex.split(command, posix=os.name != "nt")
    except ValueError:
        parts = command.strip().split()
    if not parts:
        return "command", "[REDACTED]", "command"
    executable = Path(parts[0].strip("'\"")).name.lower()
    kind, component = _structured_action(executable, parts)
    if kind in {"service", "container"}:
        verb = parts[1].lower() if executable in {"systemctl", "docker"} and len(parts) > 1 else executable
        return executable, f"{executable} {verb} {component}", f"{kind}:{component}"
    safe_parts = [parts[0]]
    redact_next = False
    allow_args = executable in SAFE_ARGUMENT_COMMANDS
    for part in parts[1:]:
        lower = part.lower().lstrip("-")
        if redact_next:
            safe_parts.append("[REDACTED]")
            redact_next = False
            continue
        if any(marker in lower for marker in SENSITIVE_MARKERS):
            if "=" in part:
                safe_parts.append(part.split("=", 1)[0] + "=[REDACTED]")
            else:
                safe_parts.append(part)
                redact_next = True
            continue
        safe_parts.append(part if allow_args else "[REDACTED]")
    detail = redact(" ".join(safe_parts))
    return executable or "command", detail, f"{kind}:{component}"


def _structured_action(executable: str, parts: list[str]) -> tuple[str, str]:
    lowered = [part.lower() for part in parts]
    service_verbs = {"restart", "start", "stop"}
    if executable == "systemctl" and len(parts) >= 3 and lowered[1] in service_verbs:
        return "service", Path(parts[2]).name[:100]
    if executable in {"restart-service", "start-service", "stop-service"} and len(parts) >= 2:
        return "service", Path(parts[-1]).name[:100]
    if executable == "docker" and len(parts) >= 3 and lowered[1] in {"start", "stop", "restart", "rm", "run"}:
        return "container", Path(parts[2]).name[:100]
    return "command", executable[:100]


class SessionManager:
    def __init__(self, database: Database | None = None) -> None:
        self.database = database or Database()

    def create(self, working_directory: Path, shell: str) -> OperationSession:
        active = self.database.active_session()
        if active:
            raise RuntimeError(f"Ja existe uma sessao ativa: {active.id}")
        resolved_directory = str(working_directory.resolve())
        if redact(resolved_directory) != resolved_directory:
            raise RuntimeError("O caminho observado parece conter um segredo e nao pode ser persistido")
        operation = OperationSession(
            id=str(uuid.uuid4()),
            hostname=socket.gethostname(),
            # This is persisted metadata, not a subprocess execution flag.
            shell=shell,  # nosec B604
            working_directory=resolved_directory,
        )
        with self.database.session() as db:
            db.add(operation)
            db.commit()
        self._save_snapshots(operation.id, "before", working_directory)
        return operation

    def record_command(self, session_id: str, command: str, exit_code: int | None) -> None:
        executable, detail, action = safe_command_metadata(command)
        action_kind, _, action_component = action.partition(":")
        kind = action_kind if action_kind in {"service", "container"} else "command"
        result = "ok" if exit_code in {None, 0} else f"error:{exit_code}"
        with self.database.session() as db:
            operation = db.get(OperationSession, session_id)
            if not operation or operation.status != "active":
                return
            db.add(Event(session_id=session_id, kind=kind, component=redact(action_component or executable)[:255], detail=detail, result=result))
            db.commit()

    def stop(self, session_id: str | None = None) -> OperationSession | None:
        operation = self.database.session_detail(session_id) if session_id else self.database.active_session()
        if not operation or operation.status != "active":
            return operation
        root = Path(operation.working_directory)
        self._save_snapshots(operation.id, "after", root)
        self._record_snapshot_diffs(operation.id)
        with self.database.session() as db:
            current = db.get(OperationSession, operation.id)
            if not current:
                return None
            current.status = "completed"
            current.ended_at = datetime.now(UTC)
            db.flush()
            counts = Counter(db.scalars(select(Event.kind).where(Event.session_id == operation.id)).all())
            errors = db.scalar(select(Event).where(Event.session_id == operation.id, Event.result.like("error:%")).limit(1))
            current.summary = (
                f"Sessao concluida: {counts['command']} comandos, {counts['file']} arquivos alterados, "
                f"{counts['service']} eventos de servico e {counts['container']} eventos de container. "
                f"Erros registrados: {'sim' if errors else 'nao'}."
            )
            db.commit()
            db.refresh(current)
            return current

    def run_controlled_shell(self, watch_path: Path) -> int:
        if os.name == "nt":
            shell = shutil.which("powershell") or shutil.which("pwsh")
            shell_name = "PowerShell"
        else:
            shell = shutil.which("bash")
            shell_name = "Bash"
        if not shell:
            raise RuntimeError("Nenhum shell compativel foi encontrado")
        operation = self.create(watch_path, shell_name)
        profile = self._write_shell_profile(operation.id, shell_name)
        env = os.environ.copy()
        env["ATLAS_SESSION_ID"] = operation.id
        env["ATLAS_PYTHON"] = sys.executable
        try:
            if os.name == "nt":
                command = [shell, "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-NoExit", "-File", str(profile)]
            else:
                command = [shell, "--noprofile", "--rcfile", str(profile)]
            return subprocess.call(command, cwd=watch_path, env=env)
        finally:
            self.stop(operation.id)
            try:
                profile.unlink(missing_ok=True)
            except OSError:
                pass

    def _write_shell_profile(self, session_id: str, shell_name: str) -> Path:
        suffix = ".ps1" if shell_name == "PowerShell" else ".bashrc"
        path = data_dir() / f"session-{session_id}{suffix}"
        if shell_name == "PowerShell":
            content = r'''$global:AtlasLastHistoryId = 0
function global:prompt {
    $atlasSuccess = $?
    $atlasExit = if ($atlasSuccess) { if ($null -ne $global:LASTEXITCODE) { $global:LASTEXITCODE } else { 0 } } else { 1 }
    $atlasHistory = Get-History -Count 1 -ErrorAction SilentlyContinue
    if ($atlasHistory -and $atlasHistory.Id -gt $global:AtlasLastHistoryId) {
        $global:AtlasLastHistoryId = $atlasHistory.Id
        $atlasPayload = @{session_id=$env:ATLAS_SESSION_ID; command=$atlasHistory.CommandLine; exit_code=$atlasExit} | ConvertTo-Json -Compress
        $atlasPayload | & $env:ATLAS_PYTHON -m atlas _record-command 2>$null
    }
    "ATLAS [$($executionContext.SessionState.Path.CurrentLocation)]> "
}
function global:atlas {
    param([Parameter(ValueFromRemainingArguments=$true)][string[]]$AtlasArgs)
    & $env:ATLAS_PYTHON -m atlas @AtlasArgs
    if ($AtlasArgs.Count -gt 0 -and $AtlasArgs[0] -eq 'stop') { exit }
}
Write-Host "ATLAS session active. Use 'atlas stop' to finish." -ForegroundColor Cyan
'''
        else:
            content = r'''_atlas_last_history=""
_atlas_prompt_hook() {
  _atlas_status=$?
  _atlas_cmd="$(history 1 | sed -E 's/^ *[0-9]+ +//')"
  if [ -n "$_atlas_cmd" ] && [ "$_atlas_cmd" != "$_atlas_last_history" ]; then
    _atlas_last_history="$_atlas_cmd"
    ATLAS_COMMAND="$_atlas_cmd" ATLAS_EXIT="$_atlas_status" "$ATLAS_PYTHON" -m atlas _record-env >/dev/null 2>&1
  fi
}
atlas() {
  "$ATLAS_PYTHON" -m atlas "$@"
  if [ "$1" = "stop" ]; then exit; fi
}
PROMPT_COMMAND=_atlas_prompt_hook
PS1='ATLAS [\w]> '
echo "ATLAS session active. Use 'atlas stop' to finish."
'''
        path.write_text(content, encoding="utf-8")
        return path

    def _save_snapshots(self, session_id: str, phase: str, root: Path) -> None:
        states: list[tuple[str, str, str]] = []
        for identity, state in snapshot_files(root).items():
            states.append(("file", identity, state))
        for service in services():
            states.append(("service", service["name"], service["status"]))
        for container in docker_inspect():
            container_state = container.get("State") or {}
            config = container.get("Config") or {}
            state = json.dumps(
                {
                    "image": config.get("Image"),
                    "running": container_state.get("Running"),
                    "started_at": container_state.get("StartedAt"),
                    "restart_count": container.get("RestartCount"),
                },
                sort_keys=True,
            )
            identity = str(container.get("Name") or container.get("Id") or "unknown").lstrip("/")
            states.append(("container", identity, state))
        with self.database.session() as db:
            db.add_all(Snapshot(session_id=session_id, phase=phase, category=category, identity=redact(identity), state=redact(state)) for category, identity, state in states)
            db.commit()

    def _record_snapshot_diffs(self, session_id: str) -> None:
        with self.database.session() as db:
            snapshots = db.scalars(select(Snapshot).where(Snapshot.session_id == session_id)).all()
            before = {(row.category, row.identity): row.state for row in snapshots if row.phase == "before"}
            after = {(row.category, row.identity): row.state for row in snapshots if row.phase == "after"}
            events: list[Event] = []
            for key in sorted(set(before) | set(after)):
                if before.get(key) == after.get(key):
                    continue
                category, identity = key
                transition = "created" if key not in before else "removed" if key not in after else "changed"
                events.append(Event(session_id=session_id, kind=category, component=identity[:255], detail=transition, result="observed"))
            db.add_all(events)
            db.commit()


def snapshot_files(root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    if not root.exists():
        return result
    root_resolved = root.resolve()
    candidates = [root] if root.is_file() else root.rglob("*")
    for path in candidates:
        if len(result) >= SNAPSHOT_LIMIT:
            break
        try:
            resolved = path.resolve()
            relative_parts = resolved.relative_to(root_resolved).parts
            if not path.is_file() or any(part in SNAPSHOT_SKIP for part in relative_parts):
                continue
            stat_result = path.stat()
            result[str(resolved)] = json.dumps(
                {"size": stat_result.st_size, "mtime_ns": stat_result.st_mtime_ns, "mode": stat_result.st_mode},
                sort_keys=True,
            )
        except OSError:
            continue
    return result
