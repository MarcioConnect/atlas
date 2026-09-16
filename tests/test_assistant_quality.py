import json
from types import SimpleNamespace
from urllib.error import URLError

import pytest

from atlas.assistant import ProjectAssistant
from atlas.ollama_ai import AIReviewStatus, LocalOnlyRedirect, OllamaReviewer
from atlas.privacy import sanitize_source, sanitize_text
from atlas.project_context import ProjectContext, context_prompt
from tests.test_ollama_ai import Response


def test_security_question_is_not_redacted():
    question = 'Como proteger tokens e passwords no meu código?'
    assert sanitize_text(question) == question


def test_auth_function_names_survive_source_redaction():
    source = 'def validate_token(token):\n    return check_signature(token)'
    assert sanitize_source(source) == source


def test_standalone_jwt_is_redacted():
    fixture = 'eyJ' + 'x' * 16 + '.' + 'y' * 16 + '.' + 'z' * 16
    assert fixture not in sanitize_source('value = "' + fixture + '"')


@pytest.mark.parametrize('wrapper', ['password = "{}"', '{{"api_key": "{}"}}',
                                   "secret = '''{}'''", 'Authorization: Bearer {}'])
def test_quoted_and_multiline_credentials_never_reach_context(wrapper):
    value = 'test-only-value with spaces'
    if 'Bearer' in wrapper:
        value = 'test-only-value'
    text = wrapper.format(value)
    assert value not in sanitize_text(text)


def test_multiline_redaction_preserves_line_numbers():
    text = 'secret = """first\nsecond\nthird"""\nprint(42)'
    output = sanitize_source(text)
    assert 'second' not in output
    assert output.splitlines()[3] == 'print(42)'


def test_source_after_private_key_keeps_line_number():
    text = '-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\nprint(42)'
    assert sanitize_source(text).splitlines()[3] == 'print(42)'


def test_deep_source_search_and_cache_refresh(tmp_path):
    path = tmp_path / 'app.py'
    path.write_text('# filler\n' * 180 + 'def calculate_invoice(): return 42\n')
    index = ProjectContext(tmp_path)
    first = index.collect('calculate_invoice')
    assert '181: def calculate_invoice' in first['files'][0]['excerpt']
    assert index.collect('calculate_invoice')['cache_hits'] == 1
    path.write_text('# filler\n' * 180 + 'def calculate_invoice(): return 99\n')
    assert 'return 99' in index.collect('calculate_invoice')['files'][0]['excerpt']
    path.unlink()
    assert index.collect('calculate_invoice')['files_read'] == 0


def test_explicit_line_and_security_filename(tmp_path):
    path = tmp_path / 'token_manager.py'
    path.write_text('# filler\n' * 90 + 'def validate(): return True\n')
    prompt, count = context_prompt(tmp_path, 'Analise token_manager.py:91', '')
    assert count == 1
    assert '91: def validate()' in prompt
    assert 'Analise token_manager.py:91' in json.loads(prompt)['question']


def test_missing_ollama_is_not_reported_as_completed_analysis(tmp_path, monkeypatch):
    (tmp_path / 'app.py').write_text('print(1)')
    monkeypatch.setattr('atlas.assistant.ensure_local_service', lambda: False)
    monkeypatch.setattr('atlas.assistant.OllamaReviewer.availability', lambda self: AIReviewStatus(False, 'offline'))
    reply = ProjectAssistant(tmp_path, SimpleNamespace(code_findings=lambda path: [])).ask('analise')
    assert not reply.used_ai
    assert 'não foi analisado' in reply.text


def test_assistant_isolates_project_and_keeps_safe_history(tmp_path, monkeypatch):
    (tmp_path / 'app.py').write_text('print(1)')
    requested = []
    payloads = []
    database = SimpleNamespace(code_findings=lambda path: requested.append(path) or [])
    monkeypatch.setattr('atlas.assistant.ensure_local_service', lambda: True)
    monkeypatch.setattr('atlas.assistant.OllamaReviewer.availability', lambda self: AIReviewStatus(True, 'ok'))

    def request(self, endpoint, payload):
        payloads.append(json.loads(payload['prompt']))
        return {'response': 'app.py:1 imprime um número.'}

    monkeypatch.setattr('atlas.assistant.OllamaReviewer._request', request)
    assistant = ProjectAssistant(tmp_path, database)
    assert assistant.ask('O que faz app.py?').used_ai
    assert assistant.ask('Como melhorar?').used_ai
    assert payloads[1]['recent_conversation']
    assert requested == [str(tmp_path.resolve()), str(tmp_path.resolve())]
    assistant.clear()
    assert not assistant.history and not assistant.retriever.cache


@pytest.mark.parametrize('body', ['[]', '{"models": null}', '{"models": {}}'])
def test_invalid_ollama_payload_is_nonfatal(tmp_path, body):
    reviewer = OllamaReviewer(tmp_path, 'test', opener=lambda *a, **kw: Response(body.encode()))
    assert not reviewer.availability().available


def test_ollama_redirect_cannot_send_source_to_another_host():
    with pytest.raises(URLError):
        LocalOnlyRedirect().redirect_request(None, None, 302, '', {}, 'https://example.invalid/')
