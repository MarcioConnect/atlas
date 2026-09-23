from __future__ import annotations

import hashlib
import importlib
import json
import os
import subprocess
import time
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


def inspect_executable(path: Path, timeout: int = 15) -> dict[str, Any]:
    """Return a streaming SHA-256 and Authenticode status without executing a file."""
    target = path.expanduser().resolve(strict=True)
    if not target.is_file():
        raise ValueError("Target must be a regular file")
    digest = hashlib.sha256()
    size = 0
    with target.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    result: dict[str, Any] = {
        "name": redact(target.name), "size_bytes": size, "sha256": digest.hexdigest(),
        "authenticode": {"available": False, "status": "NOT_CHECKED", "signer": "", "detail": ""},
    }
    if os.name != "nt":
        result["authenticode"]["detail"] = "Authenticode is available only on Windows"
        return result
    environment = dict(os.environ, ATLAS_INSPECT_PATH=str(target))
    script = (
        "$s=Get-AuthenticodeSignature -LiteralPath $env:ATLAS_INSPECT_PATH; "
        "$s | Select-Object Status,StatusMessage,@{n='Signer';e={$_.SignerCertificate.Subject}} | "
        "ConvertTo-Json -Compress"
    )
    try:
        process = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, check=False, shell=False, env=environment,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if process.returncode == 0:
            signature = json.loads(process.stdout or "{}")
            if isinstance(signature, dict):
                result["authenticode"] = {
                    "available": True,
                    "status": redact(str(signature.get("Status") or "UNKNOWN"))[:40],
                    "signer": redact(str(signature.get("Signer") or ""))[:240],
                    "detail": redact(str(signature.get("StatusMessage") or ""))[:300],
                }
        else:
            result["authenticode"]["detail"] = "Signature status unavailable"
    except (OSError, ValueError, TypeError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        result["authenticode"]["detail"] = type(exc).__name__
    return result


def scan_with_yara(
    target: Path, rules_dir: Path, *, timeout: float = 90.0, max_rules: int = 20,
    max_files: int = 2000, max_file_bytes: int = 10_000_000,
) -> dict[str, Any]:
    """Scan a selected path with local YARA rules under resource limits."""
    try:
        yara = importlib.import_module("yara")
    except ImportError:
        return {"available": False, "complete": False, "matches": [],
                "detail": "YARA unavailable; optional install: py -m pip install 'atlas-security-agent[yara]'"}
    scan_target = target.expanduser().resolve(strict=True)
    rule_root = rules_dir.expanduser().resolve(strict=True)
    if not rule_root.is_dir() or not (scan_target.is_file() or scan_target.is_dir()):
        raise ValueError("Target must be a file/directory and rules path must be a directory")
    rule_files = []
    for candidate in rule_root.rglob("*"):
        if candidate.suffix.casefold() not in {".yar", ".yara"} or candidate.is_symlink():
            continue
        try:
            candidate.resolve().relative_to(rule_root)
        except ValueError:
            continue
        rule_files.append(candidate)
        if len(rule_files) >= max_rules:
            break
    if not rule_files:
        return {"available": True, "complete": True, "matches": [], "detail": "No YARA rule files found"}
    paths = [scan_target] if scan_target.is_file() else []
    if scan_target.is_dir():
        for candidate in scan_target.rglob("*"):
            if candidate.is_file() and not candidate.is_symlink():
                paths.append(candidate)
                if len(paths) > max_files:
                    break
    started = time.monotonic()
    matches: list[dict[str, str]] = []
    errors: list[str] = []
    complete = len(rule_files) < max_rules and len(paths) <= max_files
    for rule_path in rule_files:
        if time.monotonic() - started >= timeout:
            complete = False
            errors.append("total timeout reached")
            break
        try:
            rules = yara.compile(filepath=str(rule_path))
        except Exception as exc:
            complete = False
            errors.append(f"{rule_path.name}: {type(exc).__name__}")
            continue
        for file_path in paths:
            if time.monotonic() - started >= timeout:
                complete = False
                errors.append("total timeout reached")
                break
            try:
                if file_path.stat().st_size > max_file_bytes:
                    complete = False
                    continue
                remaining = max(1, int(timeout - (time.monotonic() - started)))
                found = rules.match(str(file_path), timeout=min(5, remaining))
                for item in found:
                    matches.append({"rule": redact(str(item.rule))[:120], "file": redact(file_path.name)[:255]})
            except Exception as exc:
                complete = False
                errors.append(f"{file_path.name}: {type(exc).__name__}")
        if not complete and time.monotonic() - started >= timeout:
            break
    return {
        "available": True, "complete": complete, "files_considered": min(len(paths), max_files),
        "rules_considered": len(rule_files), "matches": matches,
        "detail": "; ".join(errors[:20]) or ("Scan complete" if complete else "Resource limit reached"),
    }


def persistence_snapshot() -> list[dict[str, str]]:
    """Read selected startup Run keys and scheduled tasks without retaining commands."""
    script = r"""
$rows = [System.Collections.Generic.List[object]]::new()
$keys = @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
          'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
          'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
          'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
          'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run')
foreach ($key in $keys) {
  $properties = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
  if ($null -ne $properties) {
    foreach ($property in $properties.PSObject.Properties) {
      if ($property.Name -notlike 'PS*') {
        $rows.Add([pscustomobject]@{kind='registry-run'; name=($key + ':' + $property.Name); value=[string]$property.Value})
      }
    }
  }
}
Get-ScheduledTask -ErrorAction SilentlyContinue | Select-Object -First 500 | ForEach-Object {
  $actions = ($_.Actions | ForEach-Object { [string]$_.Execute + ' ' + [string]$_.Arguments }) -join ';'
  $rows.Add([pscustomobject]@{kind='scheduled-task'; name=([string]$_.TaskPath + [string]$_.TaskName); value=$actions})
}
ConvertTo-Json -InputObject @($rows) -Depth 4 -Compress
"""
    if os.name != "nt":
        raise OSError("Persistence inventory requires Windows")
    payload = _powershell_json(script, timeout=25)
    if isinstance(payload, dict):
        payload = [payload]
    if not isinstance(payload, list):
        raise TypeError("Invalid persistence inventory")
    inventory = []
    for row in payload[:1000]:
        if not isinstance(row, dict):
            continue
        kind = str(row.get("kind") or "startup")[:40]
        name = redact(str(row.get("name") or "unknown"))[:240]
        value = str(row.get("value") or "")
        digest = hashlib.sha256(f"{kind}|{name}|{value}".encode("utf-8", "replace")).hexdigest()
        inventory.append({"kind": kind, "name": name, "fingerprint": digest})
    return inventory
