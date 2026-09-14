from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from atlas.security import redact


@dataclass(slots=True)
class DefenderSnapshot:
    available: bool
    status: dict[str, Any]
    detections: list[dict[str, Any]]
    detail: str = ""


def _powershell_json(script: str, timeout: int = 20) -> Any:
    if os.name != "nt":
        raise OSError("Microsoft Defender integration requires Windows")
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    process = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=timeout, check=False, shell=False, creationflags=flags,
    )
    if process.returncode != 0:
        failure = (process.stderr + process.stdout).casefold()
        if "0x80041003" in failure or "access denied" in failure or "acesso negado" in failure:
            raise PermissionError("Administrator permission required for Defender telemetry")
        raise OSError("Defender information unavailable")
    return json.loads(process.stdout or "null")


def defender_snapshot() -> DefenderSnapshot:
    try:
        status = _powershell_json(
            "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,AntispywareEnabled,"
            "BehaviorMonitorEnabled,IoavProtectionEnabled,RealTimeProtectionEnabled,AntivirusSignatureAge,"
            "AntispywareSignatureAge,QuickScanAge,FullScanAge | ConvertTo-Json -Compress"
        )
        detections = _powershell_json(
            "@(Get-MpThreatDetection | Select-Object ThreatID,ActionSuccess,InitialDetectionTime,Resources) | "
            "ConvertTo-Json -Compress"
        )
        if isinstance(detections, dict):
            detections = [detections]
        if not isinstance(status, dict) or not isinstance(detections, list):
            raise TypeError("invalid Defender response")
        safe_detections = []
        for item in detections[:100]:
            if not isinstance(item, dict):
                continue
            resources = item.get("Resources") or []
            safe_detections.append({
                "ThreatID": item.get("ThreatID"),
                "ActionSuccess": bool(item.get("ActionSuccess")),
                "InitialDetectionTime": str(item.get("InitialDetectionTime") or ""),
                "Resources": [redact(Path(str(value)).name) for value in resources[:5]],
            })
        return DefenderSnapshot(True, status, safe_detections)
    except (OSError, ValueError, TypeError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        detail = str(exc) if isinstance(exc, PermissionError) else type(exc).__name__
        return DefenderSnapshot(False, {}, [], detail)


def find_mpcmdrun() -> Path | None:
    candidates: list[Path] = []
    platform = Path(os.environ.get("ProgramData", "C:/ProgramData")) / "Microsoft/Windows Defender/Platform"
    if platform.is_dir():
        try:
            candidates.extend(sorted(platform.glob("*/MpCmdRun.exe"), reverse=True))
        except OSError:
            pass
    candidates.append(Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Windows Defender/MpCmdRun.exe")
    return next((path for path in candidates if path.is_file()), None)


def scan_with_defender(path: Path, timeout: int = 900) -> tuple[bool, str]:
    target = path.expanduser().resolve()
    if not target.exists():
        return False, "Path does not exist"
    executable = find_mpcmdrun()
    if executable is None:
        return False, "Microsoft Defender command-line scanner unavailable"
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    try:
        process = subprocess.run(
            [str(executable), "-Scan", "-ScanType", "3", "-File", str(target), "-DisableRemediation"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, check=False, shell=False, creationflags=flags,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, type(exc).__name__
    output = redact((process.stdout + "\n" + process.stderr).strip())[-3000:]
    return process.returncode == 0, output or f"Defender exit code: {process.returncode}"
