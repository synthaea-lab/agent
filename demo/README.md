# demo — J-day Runbook

One-shot demo of Synthaea's Windows deterministic-detection surface: four
techniques from three ATT&CK tactics (Execution, Persistence) fired end-to-end
from live Windows event streams into the agent's alerting sink.

This directory is a runbook, not a scenario directory: the actual
attack-simulation scripts live in `../lab/scenarios/` and can be run
independently. What lives here is what the demo needs on top: an orchestrator
that chains them in the right order, and a precise expected-output document to
cross-check against the agent's terminal live.

## What gets demonstrated

| Step | Technique | Scenario (in `lab/scenarios/`) | What Windows writes | What the agent alerts |
| --- | --- | --- | --- | --- |
| 1 | T1059.001 Command Interpreter: PowerShell (EncodedCommand) | `encoded-powershell.ps1` | Sysmon 4104 / no persistence artifact | `T1059.001 — pid=…: encoded PowerShell command …` |
| 2 | T1053.005 Scheduled Task/Job: Scheduled Task | `scheduled-task-persistence.ps1` | Security 4698 | `T1053.005 — task=SynthaeaDemoTask<N> …` |
| 3 | T1543.003 System Process: Windows Service | `service-install-persistence.ps1` | System 7045 | `T1543.003 — service=SynthaeaDemoSvc<N> …` |
| 4 | T1136.001 Create Account: Local Account | `create-account-persistence.ps1` | Security 4720 | `T1136.001 — account=synthaea-demo-user<N> …` |

Each step runs three iterations (N ∈ {1, 2, 3}), so the reviewer sees the
rules fire on repeated events, not a single lucky one. Every artifact the
scenarios create (tasks, services, accounts) is deleted by the same script
in a `try/finally` block — no residue.

## Prerequisites

- A recent Windows build of the agent — `cargo build --release --bin agent`
  from the repo root, then `target/release/agent.exe run` referenced below.
- **Both** terminals as **Administrator**: the agent needs to read the
  Security log (Administrators only) and to enable audit subcategories via
  `auditpol`; the scenario scripts need it to create scheduled tasks, install
  services, and add local accounts.
- The built-in Windows PowerShell 5.1 (`powershell.exe`), under any locale;
  PowerShell 7+ (`pwsh`) works too. The scripts are ASCII-only and build
  locale-dependent arguments (dates) from the current culture (#433).
  `-ExecutionPolicy Bypass` is needed because a stock client's policy
  (`Restricted`) refuses to run any script.

## Run

**Terminal A** (agent, as Administrator):

```
target\release\agent.exe run
```

Wait for the four `... audit enabled` log lines to confirm the sensor
enabled its auditpol subcategories, then leave this terminal visible on
screen — this is where alerts appear.

**Terminal B** (orchestrator, as Administrator):

```
powershell -ExecutionPolicy Bypass -File demo\run-all.ps1
```

The orchestrator runs the four scenarios in the order above, with a short
pause between them so the reviewer can read the alerts as they arrive. Each
scenario is self-cleaning — the demo leaves the host in its starting state.

## What the reviewer should see

Twelve alerts total, three per technique, in the exact order and shape
listed in [`expected-alerts.md`](expected-alerts.md). Any missing or
out-of-order alert points to a specific breakage listed in that file's
troubleshooting section.

## Notes for the demo runner

- The eventlog sensor polls at a 2-second cadence, so each alert can lag its
  triggering event by up to that. The `run-all.ps1` orchestrator sleeps
  briefly between iterations so the arriving alerts stay visibly tied to
  the action that produced them, rather than piling up all at once.
- If a step fires nothing, `expected-alerts.md` has a per-technique
  troubleshooting section — check that first before re-running.
- The scenarios were written and validated as reproducible assertions, not
  choreographed demos. They fail loudly (`$ErrorActionPreference = "Stop"`)
  and roll back their artifacts in `finally` — a partial run cleans up
  correctly regardless of where it stopped.
