# crates

The library crates of the agent workspace. The binaries that compose them live in
[`apps/`](../apps) (`agent`, `watchdog`, `cli`) and [`tools/release`](../tools/release)
(`release-tool`). How the tiers fit together, and which way dependencies may point, is
described in [docs/architecture.md](../docs/architecture.md).

| Tier | Crate | Purpose |
| --- | --- | --- |
| Base | `schema` | Event types and the `Sensor`/`EventSink` contract every sensor implements |
| | `policy` | Policy types shared by the agent and the control plane |
| Sensors | [`sensors/`](sensors/README.md) | One crate per platform collection mechanism |
| | `bounded-lines` | Line reading with a byte cap, shared by the sensors that read another program's output |
| Detection | `rules` | Stateless and stateful behavioral rules |
| | `sigma` | Sigma rule parsing and compilation |
| | `yara` | YARA-X file and process-memory scanning behind a budgeted queue |
| | `intel` | IOC matching on hashes, IP addresses and domains |
| | `ml` | ONNX inference and feature extraction |
| | `enrich` | Cached SHA-256 hashing and code-signature verdicts |
| | `correlator` | Co-occurrence rules and Bayesian belief per process |
| | `verdict` | Fusion of findings from every engine into one verdict per entity |
| | `deception` | Per-host canary files and decoy credentials |
| Services | `config` | `agent.toml` discovery, loading and validation |
| | `store` | Bounded in-memory state and the durable upload spool |
| | `event-window` | The sliding window of recent events the correlator and the ML features read |
| | `transport` | mTLS client and store-and-forward upload to the control plane |
| | `sinks` | Local JSON Lines outputs |
| | `ipc` | Local control channel between the agent and `cli` |
| | `response` | Kill, quarantine, escalation and host isolation |
| | `updater` | Signed release, content and key-rotation manifests; the on-disk release layout |
| | `tamper` | Heartbeats, sensor-silence detection and integrity checks |
| | `redact` | Credential redaction for data leaving the process |
| | `inventory` | Software and asset inventory |
| | `health` | The agent health beacon: the collector thread and the counter sources it reads |
| Composition | `delivery` | What the agent sends to and fetches from the control plane: telemetry upload, signed content, releases and key rotations |
| | `pipeline` | The detection pipeline: an event in, the engines' findings, a verdict and its response out |
| Utility | `file-hash` | Streaming SHA-256 of a file or reader, shared by every crate that hashes one |
| Utility | `workers` | Worker threads done one way: named spawn, the poisoned-lock policy, bounded shutdown |
| Test support | `siblings` | Locates the sibling repositories for cross-repository contract tests (dev-dependency only) |

Some crates are still early or empty; [docs/capabilities.md](../docs/capabilities.md) records
the state of each capability.

## Adding a crate

1. Create it under `crates/<name>` (or `crates/sensors/<platform>/<mechanism>` for a sensor)
   and add it to `members` in the root [`Cargo.toml`](../Cargo.toml).
2. Add it to the dependency rules in [`tools/check-deps.py`](../tools/check-deps.py), which
   rejects a dependency that points the wrong way.
3. Open `src/lib.rs` with a `//!` comment that states the crate's purpose and boundaries, and
   add a row to the table above.
