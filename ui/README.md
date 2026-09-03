# ui — Endpoint Interface

The interface shown on the endpoint itself, next to the agent — distinct from the
analyst-facing web console (`server/console`). Framework not locked yet (Tauri is the
natural candidate: Rust core, one codebase, native tray/menu-bar on all three platforms).

Planned components:

| Component | Purpose |
| --- | --- |
| Tray / menu-bar app | Agent status at a glance: protected / degraded / offline, last check-in |
| Notifications | Native notifications when a response action fires (process killed, file quarantined) |
| Status panel | Local detail view: recent detections on this host, sensor health, policy version |
| User prompts | Optional confirm/inform dialogs where policy allows user interaction |

Constraints:
- The UI is a *client* of the agent, never part of it: it talks to the agent over the
  local IPC channel (`crates/ipc`) and holds no privileges of its own. Killing the UI
  affects nothing; the agent and watchdog never depend on it.
- Read-only by default; any action it can trigger is policy-gated and audited.
- Per-platform packaging: Windows tray + MSIX, macOS menu bar + notarized app, Linux
  system tray (StatusNotifier) where a desktop exists (headless servers ship no UI).
