from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_sensitive_files_are_gitignored():
    patterns = set((ROOT / ".gitignore").read_text(encoding="utf-8").splitlines())
    assert {".env", ".env.*", "*.pem", "*.key", "*.pfx", "*.db", "release/"} <= patterns


def test_repository_does_not_contain_personal_absolute_path():
    inspected = [ROOT / "src", ROOT / "tests", ROOT / "tools", ROOT / "README.md"]
    needle = ("C:" + "\\Users\\" + "mar" + "ci").casefold()
    for entry in inspected:
        paths = entry.rglob("*") if entry.is_dir() else [entry]
        for path in paths:
            if path.is_file() and path.suffix.casefold() in {".py", ".ps1", ".txt", ".md", ".json"}:
                assert needle not in path.read_text(encoding="utf-8", errors="ignore").casefold()
