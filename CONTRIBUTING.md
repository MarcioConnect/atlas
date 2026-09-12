# Contributing

Use Python 3.11 or newer on Windows. Create a virtual environment, then run:

```powershell
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check src tests
```

Keep the watcher read-only, preserve secret redaction, and ensure optional
scanner failures degrade safely. New scanner adapters must include tests for
missing executables, malformed output, and sanitized evidence.
