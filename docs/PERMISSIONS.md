# Permissions

For regular source scans and reports, ATLAS runs as your Windows user. It does
not need administrator access to read the project you selected, save its own
settings, or take basic process and network snapshots.

Some Windows details are protected. Defender history, service inventory,
firewall settings, or persistence locations may not be visible to a standard
account. When that happens, ATLAS reports reduced coverage; it does not try to
get around Windows access controls.

The explicit `atlas malware scan PATH` command asks Microsoft Defender to scan
the path you provide, with remediation disabled. ATLAS does not turn Defender,
the firewall, or UAC on or off, and it does not change PowerShell's execution
policy.

If you start the background monitor or enable start-at-login, ATLAS creates a
process or scheduled task for your user account. It does not install a
system-wide service or request administrator privileges. Reports go to the
folder you choose (Downloads by default). An Ollama review runs only after you
ask for one.
