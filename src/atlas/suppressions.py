"""Finding suppressions shared by the CLI and both Textual interfaces.

Suppressions are stored as lightweight dictionaries inside ``Settings`` so the
existing ``settings.json`` contract stays intact. Fingerprints are always
produced by the scanners; users never have to copy a hash by hand.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from atlas.config import Settings
from atlas.security import redact


def _parse_expiry(entry: dict[str, str]) -> datetime | None:
    try:
        expires = datetime.fromisoformat(str(entry["expires_at"]))
    except (KeyError, TypeError, ValueError):
        return None
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    return expires


def is_active(entry: dict[str, str]) -> bool:
    expires = _parse_expiry(entry)
    return expires is not None and expires > datetime.now(UTC)


def active_suppressions(settings: Settings) -> list[dict[str, str]]:
    return [entry for entry in settings.finding_suppressions if is_active(entry)]


def expires_in_days(entry: dict[str, str]) -> int | None:
    expires = _parse_expiry(entry)
    if expires is None:
        return None
    return max(0, (expires - datetime.now(UTC)).days)


def add_suppression(settings: Settings, fingerprint: str, reason: str, days: int = 30) -> dict[str, str]:
    """Add or refresh a suppression for ``fingerprint`` and return the entry."""
    fingerprint = fingerprint.strip()
    if len(fingerprint) != 64:
        raise ValueError("A fingerprint de supressão deve ter 64 caracteres.")
    reason = redact(reason).strip()
    if not reason:
        raise ValueError("Informe um motivo para a supressão.")
    days = max(1, min(int(days), 3650))
    expires = (datetime.now(UTC) + timedelta(days=days)).isoformat()
    entry = {"fingerprint": fingerprint, "reason": reason[:500], "expires_at": expires}
    settings.finding_suppressions = [
        item for item in settings.finding_suppressions if item.get("fingerprint") != fingerprint
    ]
    settings.finding_suppressions.append(entry)
    return entry


def remove_suppression(settings: Settings, fingerprint: str) -> bool:
    before = len(settings.finding_suppressions)
    settings.finding_suppressions = [
        item for item in settings.finding_suppressions if item.get("fingerprint") != fingerprint
    ]
    return len(settings.finding_suppressions) != before
