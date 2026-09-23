# Windows artifact integrity and signing

Release builds can publish a SHA-256 sidecar for integrity checking:

```powershell
Get-FileHash .\ATLAS-Security-Agent.exe -Algorithm SHA256
Get-Content .\ATLAS-Security-Agent.exe.sha256
```

Compare the digest with the sidecar obtained from the same GitHub release. This
detects accidental corruption; a checksum downloaded from the same release is
not a defense against compromise of the GitHub release account or workflow.

The current build is not Authenticode-signed. Before claiming a signed release,
the maintainer must obtain a legitimate code-signing certificate and configure a
protected signing service or hardware-backed key. Never commit a PFX, private
key, password, or long-lived signing credential. Signing should run only on a
protected release workflow after verifying the tag and artifact provenance.

ATLAS has no automatic updater. Users should download releases from the official
repository and verify the published digest. No update should execute solely
because remote metadata or a scanned file requested it.
