# sensors/windows

Windows telemetry. Two mechanisms: user-mode ETW (`etw/`, the base) and a kernel driver
(`driver/`, long-term — needs signing/ELAM). Most missing telemetry sources are ETW
providers, so they land as modules inside `etw/`, not new crates.

Coverage targets (from the Windows coverage audit, priority order):

| Telemetry source | Mechanism | Where |
| --- | --- | --- |
| Process create/exit (with real command line via PEB, user/SID, integrity level) | Kernel-Process ETW + token/PEB reads | `etw/` — P1/P4 |
| Registry (Run keys, Services, IFEO, Winlogon) | Kernel-Registry ETW | `etw/` — P2 |
| DNS | DNS-Client ETW | `etw/` — P3 |
| Image/DLL load | Kernel-Process EID 5 | `etw/` — P6 |
| File hash + Authenticode on exec | SHA-256 + WinVerifyTrust, cached | `etw/` — P7 |
| Script content | AMSI ETW + PowerShell script-block | `etw/` — P8 |
| WMI activity | WMI-Activity ETW | `etw/` |
| TCP in/outbound, IPv6 | Kernel-Network ETW | `etw/` |
| Listening ports (LISTENER-DRIFT baseline) | `GetExtendedTcpTable` snapshots | `sockets/` — #366 |
| Logon/session/token | Security auditing (`wevtutil` polling, not ETW — see ADR-0004) | `eventlog/` — #94 |
| File reads/deletes/renames, named pipes | minifilter | `driver/` — LT |
| Injection/memory ops | Threat-Intelligence ETW (needs PPL) | `driver/` — LT |

Sensor self-defense (randomized session name, silence heartbeat, trace re-arm — audit
P5/F-2) is part of `etw/`'s design, not a separate crate.
