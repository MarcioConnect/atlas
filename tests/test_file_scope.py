from atlas.file_scope import scoped_files


def test_prunes_dependencies_and_custom_virtualenv(tmp_path):
    for name in ("node_modules", ".ci-temp-new", "custom-env", "src"):
        folder = tmp_path / name
        folder.mkdir()
        (folder / "app.py").write_text("print('ok')")
    (tmp_path / "custom-env" / "pyvenv.cfg").write_text("include-system-site-packages = false")
    paths = list(scoped_files(tmp_path, {"node_modules"}))
    assert paths == [tmp_path / "src" / "app.py"]
