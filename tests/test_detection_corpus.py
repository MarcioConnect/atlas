"""Small synthetic corpus for native-rule precision/recall regressions.

These metrics describe only these fixtures, not real-world scanner accuracy.
"""

from pathlib import Path

import pytest

from atlas.code_scanners import LocalCodeScanners

CORPUS = [
    ("source.py", "result = eval(user_input)\n", "python-eval", True),
    ("source.py", "example = 'eval(user_input)'\n", "python-eval", False),
    ("source.py", "# eval(user_input)\n", "python-eval", False),
    ("tests/test_source.py", "assert eval('1 + 1') == 2\n", "python-eval", False),
    ("settings.py", 'API_KEY = "r8V7n2Qp4Xx9u6Lw3A"\n', "hardcoded-secret", True),
    ("settings.py", 'API_KEY = "dummy-not-real-credential"\n', "hardcoded-secret", False),
    ("settings.py", 'API_KEY = os.getenv("API_KEY")\n', "hardcoded-secret", False),
    ("docker-compose.yml", "services:\n  app:\n    privileged: true\n", "docker-privileged", True),
    ("docker-compose.yml", "# privileged: true\nservices: {}\n", "docker-privileged", False),
]


@pytest.mark.parametrize("relative,content,rule,expected", CORPUS)
def test_native_detection_corpus(tmp_path: Path, monkeypatch, relative, content, rule, expected):
    monkeypatch.setattr("atlas.code_scanners.shutil.which", lambda _name: None)
    target = tmp_path / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    result = LocalCodeScanners(tmp_path).scan([target])
    detected = any(item.scanner == "ATLAS Native" and item.rule_id == rule for item in result.findings)
    assert detected is expected


def test_fixture_corpus_metrics(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("atlas.code_scanners.shutil.which", lambda _name: None)
    tp = fp = tn = fn = 0
    for index, (relative, content, rule, expected) in enumerate(CORPUS):
        project = tmp_path / str(index)
        target = project / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        detected = any(item.scanner == "ATLAS Native" and item.rule_id == rule
                       for item in LocalCodeScanners(project).scan([target]).findings)
        if detected and expected:
            tp += 1
        elif detected:
            fp += 1
        elif expected:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0
    assert (tp, fp, tn, fn) == (3, 0, 6, 0)
    assert (precision, recall, f1) == (1.0, 1.0, 1.0)
