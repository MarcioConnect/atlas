from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

MARKER = "Gerado pelo ATLAS"


def _git_dir(project: Path) -> Path | None:
    candidate = project / ".git"
    if (candidate / "hooks").is_dir():
        return candidate
    result = subprocess.run(["git", "-C", str(project), "rev-parse", "--git-dir"],
                            text=True, capture_output=True, check=False)
    if result.returncode == 0:
        git_dir = Path(result.stdout.strip())
        if not git_dir.is_absolute():
            git_dir = project / git_dir
        return git_dir
    return None


def _atlas_invocation(fail_on: str) -> str:
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" scan . --fail-on {fail_on}'
    return f'"{Path(sys.executable).as_posix()}" -m atlas scan . --fail-on {fail_on}'


def hook_script(fail_on: str = "HIGH") -> str:
    return (
        "#!/bin/sh\n"
        f"# {MARKER} — bloqueia commits com findings de severidade {fail_on} ou maior.\n"
        f"# Remova este arquivo para desativar a verificação.\n"
        f"{_atlas_invocation(fail_on)}\n"
    )


def install_pre_commit_hook(project: Path, fail_on: str = "HIGH", force: bool = False) -> tuple[bool, str]:
    """Install a Git pre-commit hook that runs ``atlas scan`` on the project."""
    project = project.expanduser().resolve()
    git_dir = _git_dir(project)
    if git_dir is None:
        return False, "Nenhum repositório Git encontrado. Rode `git init` no projeto primeiro."
    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_path = hooks_dir / "pre-commit"
    if hook_path.exists() and not force:
        existing = hook_path.read_text(encoding="utf-8", errors="replace")
        if MARKER not in existing:
            return False, f"Hook pre-commit já existe em {hook_path}. Use --force para substituir."
    hook_path.write_text(hook_script(fail_on), encoding="utf-8", newline="\n")
    if os.name != "nt":
        hook_path.chmod(hook_path.stat().st_mode | 0o755)
    return True, str(hook_path)
