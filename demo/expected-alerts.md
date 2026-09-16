# Expected alerts

Reference for cross-checking the agent's terminal output against what
`demo\run-all.ps1` should trigger. Order matches the orchestrator's step
order; iteration numbers `<N>` run from 1 to 3.

Every alert line in this file is intentionally close-to-verbatim: the
alerting sink formats each `Alert` as `T<id> — <message>`, so a matching
alert differs from the line here only by concrete pid values, timestamps,
task/service/account counters, and (for T1136.001) a system-specific SID.

## Step 1 — T1059.001 · Command and Scripting Interpreter: PowerShell (EncodedCommand)

Three alerts:

```
T1059.001 — pid=<pid> comm=powershell.exe: encoded PowerShell command: powershell.exe -EncodedCommand …
T1059.001 — pid=<pid> comm=powershell.exe: encoded PowerShell command: powershell.exe -EncodedCommand …
T1059.001 — pid=<pid> comm=powershell.exe: encoded PowerShell command: powershell.exe -EncodedCommand …
```

**No fire means**: the Exec-event sensor for Windows is not wired into
`agent run`, or the `check_encoded_powershell` rule regressed. This step
does not depend on eventlog polling — an absent alert here isolates the
break to the ExecEvent pipeline.

## Step 2 — T1053.005 · Scheduled Task/Job: Scheduled Task

Three alerts, within ~5 seconds of the scenario's `iteration N done` lines
(2-second eventlog poll + `Start-Sleep -Seconds 1` between iterations):

```
T1053.005 — task=SynthaeaDemoTask1 pid=<pid>: scheduled task persistence created — action path: C:\Windows\System32\notepad.exe
T1053.005 — task=SynthaeaDemoTask2 pid=<pid>: scheduled task persistence created — action path: C:\Windows\System32\notepad.exe
T1053.005 — task=SynthaeaDemoTask3 pid=<pid>: scheduled task persistence created — action path: C:\Windows\System32\notepad.exe
```

**No fire means one of** (in order of likelihood):

1. The **"Other Object Access Events"** audit subcategory is disabled and
   the sensor's own `auditpol` call failed. Look at the agent's startup log
   for the `"Other Object Access Events" audit enabled (event 4698)` line;
   if it says `auditpol failed`, run the command it prints manually.
2. The eventlog sensor's polling thread is not running — grep the agent
   log for `scheduled-task poll started`.
3. The rule regressed.

## Step 3 — T1543.003 · Create or Modify System Process: Windows Service

Three alerts on the same cadence:

```
T1543.003 — service=SynthaeaDemoSvc1 pid=<pid>: service persistence installed — image path: C:\Windows\System32\notepad.exe
T1543.003 — service=SynthaeaDemoSvc2 pid=<pid>: service persistence installed — image path: C:\Windows\System32\notepad.exe
T1543.003 — service=SynthaeaDemoSvc3 pid=<pid>: service persistence installed — image path: C:\Windows\System32\notepad.exe
```

**No fire means** the eventlog sensor's `service-install poll started` line
never appeared in the agent log, or the rule regressed. Unlike 4698, 7045
lives in the System log and is emitted unconditionally — there is no audit
subcategory to enable, so a missing alert never points to auditpol here.

## Step 4 — T1136.001 · Create Account: Local Account

Three alerts on the same cadence. `<sid>` is
`S-1-5-21-<host-machine-sid>-<rid>`, where `<rid>` starts at whatever the
next free relative identifier is on the host and increments by 1:

```
T1136.001 — account=synthaea-demo-user1 pid=<pid>: local account persistence created — sid: <sid>
T1136.001 — account=synthaea-demo-user2 pid=<pid>: local account persistence created — sid: <sid+1>
T1136.001 — account=synthaea-demo-user3 pid=<pid>: local account persistence created — sid: <sid+2>
```

**No fire means one of**:

1. **"User Account Management"** audit subcategory is disabled and the
   sensor's `auditpol` failed. Less likely than for 4698 — UAM is enabled
   in Windows' default audit policy on both Client and Server SKUs. Check
   the `"User Account Management" audit enabled (event 4720)` line in the
   agent log.
2. `account_creations_enabled` is `false` in the policy. In this repo's
   defaults it is `true`; a locally patched agent may have flipped it.
3. The rule regressed.

## After the run

Every artifact created by the scenarios has been deleted in their
`try/finally` cleanup blocks — no scheduled tasks, no services, no local
accounts should remain. Quick spot-check commands:

```
schtasks /Query /TN SynthaeaDemoTask1 2>&1 | Select-String "cannot find"
sc.exe query SynthaeaDemoSvc1        2>&1 | Select-String "does not exist"
net user synthaea-demo-user1         2>&1 | Select-String "could not be found"
```

Each should return a match (the "not found"/"does not exist" message from
its respective tool). A missing "not found" match on any of the three
means the cleanup did not complete and the scenario needs to be re-run
(the `try/finally` is idempotent — safe to re-invoke).
