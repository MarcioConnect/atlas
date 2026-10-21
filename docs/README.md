# Documentation map

This folder contains focused references for ATLAS. Start with the root
[`README.md`](../README.md) for installation, commands, and the user guide.

## Repository layout

- `.github/`: CI, release, security analysis, and contribution templates.
- `assets/`: repository branding used by the README and project pages.
- `src/atlas/`: application code; `assets/` and `rules/` here are packaged with
  the Python application.
- `tests/`: automated checks, named by the feature they cover.
- `tools/`: Windows executable build, version metadata, and release screenshot
  capture.
- `docs/`: focused security and operational references plus screenshots.
- Root files: package configuration (`pyproject.toml`), user guide, changelog,
  license, security policy, and implementation report.

## Topics

- [`THREAT_MODEL.md`](THREAT_MODEL.md): assets, trust boundaries, threats, and
  security assumptions.
- [`PRIVACY.md`](PRIVACY.md): data collection, storage, and sanitization.
- [`PERMISSIONS.md`](PERMISSIONS.md): permissions used by the application and
  why they are needed.
- [`SIGNING.md`](SIGNING.md): Windows executable signing and download checks.
- [`screenshots/README.md`](screenshots/README.md): how to capture and update
  interface screenshots.

Release validation details and known limitations live in the root
[`IMPLEMENTATION_REPORT.md`](../IMPLEMENTATION_REPORT.md). Contribution setup
and pull request guidance live in [`CONTRIBUTING.md`](../CONTRIBUTING.md).
