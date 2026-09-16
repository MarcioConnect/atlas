"""Pruned traversal shared by local scanners; never descend into dependencies."""
import os
import stat
from pathlib import Path

TEMP_PREFIXES = (".pytest", ".test-", ".build-", ".publish-test-", ".review-", ".diag-", ".ci-temp")


def ignored_name(name: str, excluded: set[str]) -> bool:
    return name.casefold() in excluded or name.casefold().startswith(TEMP_PREFIXES)


def linked_path(path: Path) -> bool:
    try:
        return path.is_symlink() or bool(getattr(path.lstat(), 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    except OSError:
        return True


def scoped_files(root: Path, excluded: set[str]):
    if root.is_file():
        yield root
        return
    for directory, folders, filenames in os.walk(root, followlinks=False):
        folders[:] = [name for name in folders
                      if not ignored_name(name, excluded)
                      and not linked_path(Path(directory) / name)
                      and not (Path(directory) / name / "pyvenv.cfg").is_file()]
        for name in filenames:
            path = Path(directory) / name
            if not linked_path(path):
                yield path
