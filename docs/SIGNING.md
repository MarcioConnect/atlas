# Windows artifact integrity and signing

Each release can include a SHA-256 file next to the Windows executable. Use it
to check that your download matches the published artifact:

```powershell
Get-FileHash .\ATLAS-Security-Agent.exe -Algorithm SHA256
Get-Content .\ATLAS-Security-Agent.exe.sha256
```

Compare the two values. If they differ, do not run the file; download it again
or report the mismatch. This check catches accidental damage in transit. Since
the checksum comes from the same GitHub release, it cannot independently prove
who published the executable or protect against a compromised release account.

The current executable is not Authenticode-signed, so Windows may warn that the
publisher is unknown. Calling a release "signed" requires a valid code-signing
certificate and a protected signing service or hardware-backed key. Signing
credentials must never be committed to this repository. A release workflow
should sign only after checking the tag and where the build artifact came from.

ATLAS does not update itself. Download releases from this repository and check
the published digest. ATLAS will not run an update just because a remote file or
scanned project asks it to.
