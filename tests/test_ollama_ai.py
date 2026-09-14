import json
from io import BytesIO

from atlas.code_scanners import NormalizedFinding
from atlas.ollama_ai import OllamaReviewer


class Response(BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def test_ollama_reviews_sanitized_local_excerpt(tmp_path):
    source = tmp_path / "app.py"
    fake_secret = "super-" + "secret-value"
    source.write_text(f"password='{fake_secret}'\neval(data)\n", encoding="utf-8")
    requests = []

    def opener(request, timeout):
        requests.append((request, timeout))
        if request.full_url.endswith("/api/tags"):
            return Response(json.dumps({"models": [{"name": "test-model:latest"}]}).encode())
        answer = {"reviews": [{
            "index": 0, "verdict": "LIKELY", "severity": "HIGH",
            "reason": "Untrusted input reaches dynamic execution.", "recommendation": "Avoid eval.",
        }]}
        return Response(json.dumps({"response": json.dumps(answer)}).encode())

    finding = NormalizedFinding(
        "HIGH", "ATLAS Native", "python-eval", str(source), 2,
        "Dynamic execution", "arguments omitted", "Remove eval",
    ).finalize(tmp_path)
    status = OllamaReviewer(tmp_path, "test-model:latest", opener=opener).review([finding])
    sent = json.loads(requests[1][0].data.decode())
    assert status.available and status.reviewed == 1
    assert fake_secret not in sent["prompt"]
    assert "[AI LIKELY]" in finding.description


def test_ollama_unavailable_is_nonfatal(tmp_path):
    def unavailable(request, timeout):
        raise OSError("offline")

    status = OllamaReviewer(tmp_path, "missing", opener=unavailable).availability()
    assert not status.available
    assert "Ollama unavailable" in status.detail
