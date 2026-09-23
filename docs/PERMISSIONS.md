# Permission model

ATLAS runs as the current user and does not request elevation for source scans,
reports, configuration, or basic process/network snapshots. Protected Windows
Defender telemetry, service inventory, firewall details, and some persistence
locations may be unavailable under the current account; the application should
report that reduced coverage instead of attempting to bypass access controls.

The explicit `atlas malware scan PATH` command asks Microsoft Defender to scan a
user-selected target with remediation disabled. ATLAS does not disable or change
Defender, firewall, UAC, or execution policy settings.

The background monitor and login startup integration create a per-user process
or scheduled task. They do not request SYSTEM or administrator privileges.
Reports are written to the selected output directory (Downloads by default).
Ollama review uses loopback and is initiated only by an explicit user action.
