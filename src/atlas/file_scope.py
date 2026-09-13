"""Pruned traversal shared by local scanners; never descend into dependencies."""
import os
from pathlib import Path

TEMP_PREFIXES = (".pytest", ".test-", ".build-", ".publish-test-", ".review-", ".diag-", ".ci-temp")


def ignored_name(name: str, excluded: set[str]) -> bool:
    return name.casefold() in excluded or name.casefold().startswith(TEMP_PREFIXES)


def scoped_files(root: Path, excluded: set[str]):
    if root.is_file():
        yield root
        return
    for directory, folders, filenames in os.walk(root, followlinks=False):
        folders[:] = [name for name in folders
                      if not ignored_name(name, excluded)
                      and not (Path(directory) / name).is_symlink()
                      and not (Path(directory) / name / "pyvenv.cfg").is_file()]
        for name in filenames:
            path = Path(directory) / name
            if not path.is_symlink():
                yield path
