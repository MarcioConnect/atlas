import ast
import tomllib
from pathlib import Path

from atlas import __version__

ROOT = Path(__file__).resolve().parents[1]


def test_package_and_windows_versions_match_cli():
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert metadata["project"]["version"] == __version__
    tree = ast.parse((ROOT / "tools/windows_version_info.txt").read_text(encoding="utf-8"))
    fixed = next(node for node in ast.walk(tree)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                 and node.func.id == "FixedFileInfo")
    expected = tuple(int(part) for part in __version__.split(".")) + (0,)
    values = {item.arg: ast.literal_eval(item.value) for item in fixed.keywords}
    assert values["filevers"] == expected
    assert values["prodvers"] == expected
    strings = {ast.literal_eval(node.args[0]): ast.literal_eval(node.args[1])
               for node in ast.walk(tree)
               if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
               and node.func.id == "StringStruct"}
    assert strings["FileVersion"] == __version__
    assert strings["ProductVersion"] == __version__


def test_download_and_release_default_match_cli():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    assert f"# ATLAS v{__version__}\n" in readme
    assert f"releases/download/v{__version__}/ATLAS-Security-Agent.exe" in readme
    assert f"default: v{__version__}\n" in workflow
