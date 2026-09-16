"""Bounded, read-only retrieval with fresh source and line-accurate excerpts."""
import json
import re
import time
from collections import OrderedDict
from pathlib import Path

from atlas.file_scope import linked_path, scoped_files
from atlas.privacy import sanitize_source, sanitize_text
from atlas.security import SKIP_DIRS

EXTENSIONS = {'.py', '.js', '.ts', '.tsx', '.jsx', '.ps1', '.bat', '.sh',
              '.json', '.yaml', '.yml', '.toml', '.html', '.css', '.go', '.rs', '.java', '.cs'}
PRIVATE_NAMES = {'.npmrc', '.pypirc', 'credentials', 'credentials.json', 'secrets.json',
                 'secrets.yaml', 'secrets.yml', 'id_rsa', 'id_ed25519'}
STOP_WORDS = {'analise', 'analisar', 'codigo', 'código', 'projeto', 'arquivo', 'arquivos', 'meu', 'minha',
              'para', 'quais', 'sobre', 'onde', 'como', 'que', 'dos', 'das', 'uma'}
RISK = re.compile(r'\b(?:eval|exec|subprocess|shell|pickle|yaml\.load|innerHTML|execute|verify|debug)\b')


def allowed_source(path: Path, root: Path) -> bool:
    try:
        relative = path.resolve().relative_to(root.resolve())
        return (not linked_path(path)
                and not any(linked_path(parent) for parent in path.parents if parent != root and root in parent.parents)
                and not any(p.casefold().startswith('.env') or p.casefold() in PRIVATE_NAMES
                            for p in relative.parts)
                and (path.suffix.casefold() in EXTENSIONS or path.name.casefold() == 'dockerfile')
                and path.name.casefold() not in {'package-lock.json', 'yarn.lock'})
    except (OSError, ValueError):
        return False


class ProjectContext:
    """Keep only sanitized source in a small, per-project memory cache."""

    def __init__(self, project: Path):
        self.root = project.resolve()
        self.cache: OrderedDict = OrderedDict()

    def _read(self, path: Path) -> tuple[list[str], bool]:
        if not allowed_source(path, self.root):
            raise ValueError('outside supported scope')
        stat = path.stat()
        if stat.st_size > 128_000:
            raise ValueError('file too large')
        stamp = (stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size)
        cached = self.cache.get(path)
        if cached and cached[0] == stamp:
            self.cache.move_to_end(path)
            return cached[1], True
        with path.open('rb') as stream:
            raw = stream.read(128_001)
        if len(raw) > 128_000 or b'\0' in raw:
            raise ValueError('binary or oversized file')
        lines = sanitize_source(raw.decode('utf-8', errors='replace')).splitlines()
        self.cache[path] = (stamp, lines)
        self.cache.move_to_end(path)
        while len(self.cache) > 64:
            self.cache.popitem(last=False)
        return lines, False

    def collect(self, question: str) -> dict:
        tokens = set(re.findall(r'[\w.-]{3,}', question.casefold())) - STOP_WORDS
        candidates, sources = [], []
        deadline = time.monotonic() + 3
        examined = skipped = cache_hits = 0
        limited = False
        for path in scoped_files(self.root, SKIP_DIRS | {'.ollama', '.ssh', '.aws', '.azure'}):
            examined += 1
            if examined > 2000 or time.monotonic() > deadline:
                limited = True
                break
            if not allowed_source(path, self.root):
                skipped += 1
                continue
            try:
                relative = path.resolve().relative_to(self.root).as_posix()
                relevance = sum(token in relative.casefold() for token in tokens)
                candidates.append((relevance, path.stat().st_mtime_ns, relative, path))
            except (OSError, ValueError):
                skipped += 1
        candidates.sort(key=lambda item: (-item[0], -item[1], item[2]))
        for path_score, modified, relative, path in candidates[:64]:
            if time.monotonic() > deadline:
                limited = True
                break
            try:
                lines, cached = self._read(path)
                cache_hits += int(cached)
            except (OSError, ValueError):
                skipped += 1
                continue
            matches = [i for i, line in enumerate(lines) if any(t in line.casefold() for t in tokens)]
            explicit = re.search(re.escape(relative) + r':(\d+)', question.replace('\\', '/'), re.IGNORECASE)
            focus = max(0, int(explicit[1]) - 1) if explicit else (matches[0] if matches else None)
            if focus is None:
                focus = next((i for i, line in enumerate(lines) if RISK.search(line)), 0)
            focus = min(focus, max(0, len(lines) - 1))
            score = path_score * 20 + min(len(matches), 10) + (100 if explicit else 0)
            sources.append((score, modified, relative, lines, focus))
        sources.sort(key=lambda item: (-item[0], -item[1], item[2]))
        files, remaining = [], 12_000
        for _, _, relative, lines, focus in sources[:8]:
            if remaining <= 0:
                break
            start = max(0, focus - 8)
            excerpt_lines = []
            limit = min(2000, remaining)
            for index in range(start, min(len(lines), start + 60)):
                entry = f'{index + 1}: {lines[index]}'
                used = sum(len(s) + 1 for s in excerpt_lines)
                if used + len(entry) > limit:
                    if not excerpt_lines:
                        excerpt_lines.append(entry[:limit])
                    break
                excerpt_lines.append(entry)
            excerpt = '\n'.join(excerpt_lines)
            files.append({'file': sanitize_text(relative), 'excerpt': excerpt,
                          'line_start': start + 1, 'line_end': start + len(excerpt_lines),
                          'truncated': start > 0 or len(excerpt_lines) < len(lines)
                          or any(len(line) > limit for line in lines[start:start + 1])})
            remaining -= len(excerpt)
        return {'scope': 'selected project only', 'partial': True,
                'selection': 'file names, matching source, requested lines, recent changes',
                'files': files, 'files_read': len(files), 'files_inspected': len(sources),
                'eligible_files': len(candidates), 'skipped': skipped, 'cache_hits': cache_hits,
                'discovery_limited': limited or len(candidates) > 64}


def project_context(project: Path, question: str) -> dict:
    return ProjectContext(project).collect(question)


def context_prompt(project: Path, question: str, evidence: str, *,
                   context: dict | None = None, history: list | None = None) -> tuple[str, int]:
    context = context if context is not None else project_context(project, question)
    return json.dumps({'question': sanitize_text(question, 2000),
                       'recorded_evidence': sanitize_text(evidence, 2500),
                       'recent_conversation': history or [],
                       'untrusted_project_files': context}, ensure_ascii=False), context['files_read']
