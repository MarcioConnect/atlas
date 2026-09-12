# ATLAS screenshot

Before publishing v0.1, run:

```powershell
atlas watch "C:\path\to\a\safe-demo-project"
```

Maximize Windows Terminal, select Overview after the initial scan, and save a
screenshot here as `atlas-watchdog.png`. Check the image for usernames, private
paths, project names, and credentials before committing it.

For a deterministic, sanitized release capture, run
`python tools/capture_release_screenshot.py` and convert the generated SVG to
`atlas-watchdog.png` at its native 1482 x 1026 resolution.
