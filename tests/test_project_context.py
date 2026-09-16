from atlas.project_context import context_prompt, project_context


def test_context_reads_current_code_and_prioritizes_requested_file(tmp_path):
    source = tmp_path / 'auth.py'
    source.write_text('def login(): return False', encoding='utf-8')
    for i in range(12):
        (tmp_path / f'other{i}.py').write_text('print(1)', encoding='utf-8')
    result = project_context(tmp_path, 'analise auth.py')
    assert result['files'][0]['file'] == 'auth.py'
    assert result['files_read'] == 8
    source.write_text('def login(): return True', encoding='utf-8')
    assert 'return True' in project_context(tmp_path, 'auth.py')['files'][0]['excerpt']


def test_context_excludes_private_files_dependencies_and_redacts(tmp_path):
    fake = 'test-only-' + 'confidential-value'
    (tmp_path / '.env').write_text(fake)
    (tmp_path / 'node_modules').mkdir()
    (tmp_path / 'node_modules' / 'library.py').write_text(fake)
    (tmp_path / 'app.py').write_text('password = "' + fake + '"\nprint(123)')
    prompt, count = context_prompt(tmp_path, 'analise o projeto', '')
    assert count == 1
    assert fake not in prompt
    assert '[REDACTED]' in prompt
    assert 'print(123)' in prompt
    assert 'library.py' not in prompt


def test_context_limits_and_empty_project(tmp_path):
    assert project_context(tmp_path, 'analise')['files_read'] == 0
    (tmp_path / 'large.py').write_text('x' * 128001)
    (tmp_path / 'binary.py').write_bytes(b'abc\0def')
    (tmp_path / 'ok.py').write_text('print(1)\n' * 1000)
    result = project_context(tmp_path, 'analise')
    assert result['files_read'] == 1
    assert result['files'][0]['truncated']
    assert len(result['files'][0]['excerpt']) <= 2000


def test_context_rejects_paths_outside_project(tmp_path, monkeypatch):
    root = tmp_path / 'project'
    root.mkdir()
    outside = tmp_path / 'outside.py'
    outside.write_text('private contents')
    monkeypatch.setattr('atlas.project_context.scoped_files', lambda *args: iter([outside]))
    assert project_context(root, 'outside.py')['files_read'] == 0


def test_chat_sends_project_source_to_local_model(tmp_path, monkeypatch):
    import asyncio

    from atlas.database import Database
    from atlas.ollama_ai import AIReviewStatus
    from atlas.panel import AtlasPanel

    (tmp_path / 'app.py').write_text('def add(a, b): return a + b')
    sent = []
    monkeypatch.setattr('atlas.ollama_ai.ensure_local_service', lambda: True)
    monkeypatch.setattr('atlas.ollama_ai.OllamaReviewer.availability',
                        lambda self: AIReviewStatus(True, 'test'))

    def request(self, endpoint, payload):
        sent.append(payload)
        return {'response': 'app.py:1 soma dois valores.'}

    monkeypatch.setattr('atlas.ollama_ai.OllamaReviewer._request', request)

    async def run():
        async with AtlasPanel(Database(tmp_path / 'test.db'), tmp_path).run_test(size=(120, 40)) as pilot:
            field = pilot.app.query_one('#command')
            field.value = 'Analise app.py'
            field.focus()
            await pilot.press('enter')
            await pilot.pause(.3)
            assert len(sent) == 1
            assert 'def add(a, b)' in sent[0]['prompt']
            assert '1 arquivo(s)' in str(pilot.app.query_one('#details').render())

    asyncio.run(run())
