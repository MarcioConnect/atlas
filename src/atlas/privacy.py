"""Sanitize local-model input without erasing ordinary security questions."""
import re

from atlas.security import redact

SENSITIVE = r'(?:password|passwd|pwd|token|secret|api[_-]?key|cookie|authorization|connection[_-]?string)'
KEY = rf'[\w.-]*{SENSITIVE}[\w.-]*'
PRIVATE_KEY = re.compile(r'-----BEGIN[^\n]*PRIVATE KEY-----[\s\S]*?(?:-----END[^\n]*PRIVATE KEY-----|\Z)')
TRIPLE = re.compile(rf'''(?is)(?:["']?{KEY}["']?\s*[:=]\s*)(?:"""[\s\S]*?(?:"""|\Z)|''' + "'''[\\s\\S]*?(?:'''|\\Z))")
QUOTED = re.compile(rf'''(?i)(["']?{KEY}["']?\s*[:=]\s*)(["'])(?:\\.|(?!\2)[\s\S])*?\2''')


def _mask(match: re.Match) -> str:
    return '[REDACTED]' + '\n' * match.group().count('\n')


def sanitize_text(text: str, limit: int = 16_000) -> str:
    text = text[:max(limit * 2, 128_000)]
    text = PRIVATE_KEY.sub(_mask, text)
    text = TRIPLE.sub(_mask, text)
    text = QUOTED.sub(_mask, text)
    text = re.sub(r'(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*', 'Bearer [REDACTED]', text)
    text = re.sub(r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b', '[REDACTED]', text)
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    return '\n'.join(redact(line) for line in text.split('\n'))[:limit]


def sanitize_source(text: str) -> str:
    return sanitize_text(text, limit=128_000)
