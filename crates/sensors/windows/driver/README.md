# sensors/windows/driver

Windows kernel driver — the long-term item from the coverage audit. Not a workspace
member: kernel drivers have their own build/signing pipeline (WDK, EV certificate,
attestation signing; ELAM requires Microsoft Virus Initiative membership).

Planned capabilities, in order:
- Minifilter: file reads/deletes/renames (ransomware signal), named pipes, quarantine
- Kernel callbacks: process/thread/image notify with full fidelity (no ETW gaps)
- ELAM + PPL: unlocks the Threat-Intelligence ETW provider (injection, hollowing,
  RWX allocations) and protects the agent process itself

Until this exists, Windows runs user-mode only via `../etw` — the audit's P1–P8 items
all fit that architecture.
