"""Best-effort Windows desktop notifications for new ATLAS findings."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from atlas.models import CodeFinding


def notify_new_findings(project: Path, findings: Iterable[CodeFinding]) -> bool:
    """Send a toast when an optional Windows notifier is available.

    Notification failures are deliberately swallowed: a security watcher must
    never stop scanning because a desktop integration is unavailable.
    """
    items = list(findings)
    if not items:
        return False
    try:
        from winotify import Notification  # type: ignore
    except Exception:
        return False
    try:
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        highest = min((item.severity for item in items), key=lambda value: order.get(value, 99))
        toast = Notification("ATLAS · Novo risco", f"{len(items)} finding(s) novo(s) em {project.name}")
        toast.add_actions(label=f"Severidade: {highest}", launch=str(project))
        toast.show()
        return True
    except Exception:
        return False
