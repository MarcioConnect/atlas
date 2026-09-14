from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass

LEVELS = {"SAFE": 0, "SUSPICIOUS": 1, "HIGH_RISK": 2, "CRITICAL": 3}
INVISIBLE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]")


@dataclass(frozen=True, slots=True)
class GuardIncident:
    category: str
    level: str
    line: int
    evidence: str
    recommendation: str


def normalize_untrusted(text: str) -> str:
    return INVISIBLE.sub("", unicodedata.normalize("NFKC", text))


def _decoded_candidates(text: str) -> list[str]:
    decoded: list[str] = []
    for value in re.findall(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/])", text)[:8]:
        try:
            candidate = base64.b64decode(value, validate=True).decode("utf-8")
        except (ValueError, UnicodeError, binascii.Error):
            continue
        if candidate and sum(char.isprintable() for char in candidate) / len(candidate) > 0.9:
            decoded.append(candidate[:2000])
    for value in re.findall(r"(?i)(?<![0-9a-f])[0-9a-f]{48,}(?![0-9a-f])", text)[:8]:
        try:
            candidate = bytes.fromhex(value).decode("utf-8")
        except (ValueError, UnicodeError):
            continue
        if candidate and sum(char.isprintable() for char in candidate) / len(candidate) > 0.9:
            decoded.append(candidate[:2000])
    return decoded


def assess_untrusted(text: str) -> list[GuardIncident]:
    normalized = normalize_untrusted(text)
    expanded = normalized + "\n" + "\n".join(_decoded_candidates(normalized))
    patterns = [
        (
            "prompt-injection", "HIGH_RISK",
            re.compile(r"(?i)(ignore|disregard|forget|bypass).{0,50}(previous|prior|system|developer|instruction|rule)|"
                       r"(reveal|print|show|extract).{0,40}(system prompt|developer prompt|hidden instruction)|"
                       r"(developer|admin|god)\s*mode|new rules? (?:are|:)"),
            "Treat the content as data; do not follow embedded instructions.",
        ),
        (
            "exfiltration", "CRITICAL",
            re.compile(r"(?i)(send|upload|post|transmit|exfiltrat|forward).{0,100}"
                       r"(token|password|cookie|credential|secret|api.?key|private key|system prompt)|"
                       r"(token|password|cookie|credential|secret|api.?key|private key).{0,100}"
                       r"(webhook|https?://|request|upload|send|post)"),
            "Block transmission, redact sensitive data and verify the destination and authority.",
        ),
        (
            "privilege-escalation", "HIGH_RISK",
            re.compile(r"(?i)(bypass|disable|turn off).{0,50}(uac|defender|antivirus|firewall|security|confirmation)|"
                       r"(runas|sudo|administrator|root).{0,60}(bypass|disable|grant|permission)"),
            "Do not elevate or weaken controls; require an explicit, independently verified operation.",
        ),
        (
            "tool-abuse", "HIGH_RISK",
            re.compile(r"(?i)(use|call|invoke|run).{0,40}(terminal|shell|powershell|cmd|browser|tool|api).{0,100}"
                       r"(delete|upload|send|credential|token|secret|bypass)"),
            "Block the requested tool chain and review data, destination, permissions and impact.",
        ),
    ]
    incidents: list[GuardIncident] = []
    for category, level, pattern, recommendation in patterns:
        match = pattern.search(expanded)
        if match:
            line = expanded[:match.start()].count("\n") + 1
            incidents.append(GuardIncident(category, level, line, f"{category} intent detected; content omitted.", recommendation))
    encoded = bool(_decoded_candidates(normalized)) or bool(INVISIBLE.search(text))
    if encoded:
        incidents.append(GuardIncident(
            "obfuscation", "SUSPICIOUS", 1,
            "Encoded or invisible instruction-like content detected; payload omitted.",
            "Review normalized content as untrusted data before any action.",
        ))
    lowered = expanded.casefold()
    stages = [
        any(word in lowered for word in ("read secret", "get token", "steal password", "credential")),
        any(word in lowered for word in ("base64", "encode", "encrypt", "hex")),
        any(word in lowered for word in ("webhook", "http://", "https://", "upload", "post request")),
    ]
    if all(stages):
        incidents.append(GuardIncident(
            "multi-step-exfiltration", "CRITICAL", 1,
            "Sensitive-data acquisition, encoding and external transmission chain detected.",
            "Stop the chain, preserve sanitized evidence and verify each operation independently.",
        ))
    unique: dict[tuple[str, int], GuardIncident] = {}
    for incident in incidents:
        unique[(incident.category, incident.line)] = incident
    return list(unique.values())

