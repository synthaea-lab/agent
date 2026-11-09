# Synthaea agent

Synthaea is an open-source endpoint detection and response (EDR) system for Linux, Windows
and macOS. This repository is the endpoint agent: the sensors that collect telemetry from the
operating system, the detection engines that evaluate it on the host, the correlator that
turns detections into scored cases, the response actions, and the channel that uploads events
and detections to the [control plane](https://github.com/synthaea-lab/server).

The agent is written in Rust. Detection runs on the endpoint and keeps working when the host
is offline; the control plane is optional for a single machine.

> [!WARNING]
> Synthaea is **alpha** software. Linux is the most complete platform, Windows follows, and
> macOS is at an early stage. Interfaces, configuration and on-disk formats change between
> versions. Run it on test machines, not on production endpoints.
> [docs/capabilities.md](docs/capabilities.md) lists what is built, partial and planned, with
> the code and tests behind each entry.

## Features

- **One sensor contract across three platforms.** Every telemetry source produces the same
  event schema, so the detection engines do not depend on the operating system.
- **Several detection engines on the host.** Stateless and stateful behavioral rules, a
  Sigma subset, YARA-X file and process-memory scanning, IOC matching on hashes, IP addresses
  and domains, and ONNX models scored on the device. Every ML score carries per-feature
  attributions.
- **Correlation instead of alert floods.** Detections are evidence: the correlator combines
  them per process tree into a Bayesian score, and a verdict is raised when the evidence
  crosses a threshold.
- **Deception.** Canary files and decoy credentials unique to each host act as tripwires
  with a near-zero false-positive rate.
- **Policy-gated response.** Process kill and file quarantine are observe-only by default and
  enabled explicitly. Every action is logged, and quarantined files can be restored.
- **Self-protection.** A watchdog supervises the agent, restarts it with backoff, detects a
  stalled or silent sensor, and rolls back an update that fails its health check.
- **Signed updates and content.** Detection content and models are distributed through
  signed manifests in staged rollout rings. Signed binary self-update with rollback is
  available on Linux.

Detection content (Sigma, YARA and IOC feeds) lives in
[synthaea-lab/rules](https://github.com/synthaea-lab/rules). The techniques it covers are
listed in [docs/attack-coverage.md](docs/attack-coverage.md).

## Platform support

| Platform | Telemetry sources | State |
| --- | --- | --- |
| Linux (x86_64) | eBPF tracepoints, BPF-LSM, uprobes (TLS, shell readline, DNS), netlink (sock_diag, conntrack, proc connector), journald, service logs; audit netlink fallback when eBPF is unavailable | Most complete. Kernel 5.8 or later with BTF. |
| Windows (x86_64) | ETW, Event Log, socket-table snapshots; file-system minifilter | Sensors built; MSI and minifilter at an early stage. |
| macOS (Apple Silicon) | EndpointSecurity, unified log, socket-table snapshots, Network Extension | Early. EndpointSecurity and Network Extension need entitlements granted by Apple. |

The per-source details and their limits are in the sensor guides for
[Linux](docs/sensors/linux/README.md), [Windows](docs/sensors/windows/README.md) and
[macOS](docs/sensors/macos/README.md).

## Getting started

No binary release has been published yet. The agent builds from source on Linux, Windows
and macOS.

### Requirements

- [rustup](https://rustup.rs). The compiler version is pinned in
  [rust-toolchain.toml](rust-toolchain.toml), and rustup installs it on the first build.
- The default build downloads a prebuilt ONNX Runtime, which needs a recent C++ runtime: it
  does not link on Debian 12 or Ubuntu 22.04. The static build that packages use is
  described in [docs/packaging.md](docs/packaging.md).
- On Linux, the eBPF probes are compiled only when the eBPF toolchain and `bpf-linker` are
  installed. [packaging/toolchain/linux-toolchain.sh](packaging/toolchain/linux-toolchain.sh)
  provisions them. Without them the build still succeeds: `agent status` reports the
  missing probes, and `agent run` falls back to the reduced-fidelity audit sensor.

### Build

```sh
git clone https://github.com/synthaea-lab/agent.git
cd agent
cargo build --release -p agent -p watchdog -p cli
```

A source build with default features embeds public test signing keys and is meant for
evaluation only. Packaged builds exclude them; see
[docs/packaging.md](docs/packaging.md#test-key-exclusion).

### Run on Linux

The agent refuses to start without a valid configuration file. The committed template runs
as shipped: its control-plane fields are placeholders, and the agent keeps detecting locally
when it cannot upload.

```sh
sudo ./target/release/agent --config crates/config/data/default-agent.toml status
sudo ./target/release/agent --config crates/config/data/default-agent.toml run --alerts alerts.ndjson
```

`status` checks that the kernel accepts the probes without attaching them. `run` starts the
sensors and the detection pipeline and appends alerts to `alerts.ndjson` until Ctrl-C.
Every key of `agent.toml`, and the paths used on Windows and macOS, are documented in
[docs/configuration.md](docs/configuration.md). Installing the agent as a service with its
watchdog is covered in [docs/packaging.md](docs/packaging.md).

## Documentation

The [technical documentation](docs/README.md) explains each mechanism with links into the
code, with reading paths for contributors, detection engineers and operators. Good starting
points:

- [Architecture](docs/architecture.md): binaries, crates and dependency rules.
- [Event lifecycle](docs/lifecycle.md): one event from the sensor to the alert log and the
  control plane.
- [Detection](docs/detection/README.md) and [correlation](docs/correlation.md): the engines
  and how their results are combined.
- [Security model](docs/security-model.md): trust boundaries, privileges and what is not
  defended.
- [Capabilities](docs/capabilities.md) and [roadmap](docs/roadmap.md): what works today and
  what comes next.

User guides for installing and operating Synthaea are published at
<https://www.synthaea.com/docs>.

## Related repositories

| Repository | Contents |
| --- | --- |
| [synthaea-lab/server](https://github.com/synthaea-lab/server) | The control plane: enrollment, ingest, fleet-wide detection and triage. |
| [synthaea-lab/rules](https://github.com/synthaea-lab/rules) | Detection content: Sigma rules, YARA rules and IOC feeds. |
| [synthaea-lab/ml](https://github.com/synthaea-lab/ml) | Training, evaluation and export of the on-device models. |
| [synthaea-lab/scenarios](https://github.com/synthaea-lab/scenarios) | Benign attack simulations that check the detections end to end. |
| [synthaea-lab/rig](https://github.com/synthaea-lab/rig) | Virtual-machine test rig that runs the scenarios against a live agent. |

Some tests in this repository check contracts shared with these repositories. They skip when
the other repository is not checked out next to this one; see
[docs/development.md](docs/development.md#sibling-repositories).

## Contributing

Contributions are welcome, including well-argued objections to a design decision. Read
[CONTRIBUTING.md](CONTRIBUTING.md) for the ground rules and the sign-off requirement (DCO, no
CLA), and [docs/development.md](docs/development.md) for building, testing and the checks a
pull request must pass.

## Security

Do not report vulnerabilities in public issues. [SECURITY.md](SECURITY.md) describes the
private reporting channel and what is in scope.

## License

Apache License 2.0 ([LICENSE](LICENSE)). The Linux eBPF probes in
`crates/sensors/linux/ebpf/` are dual-licensed GPL-2.0-only OR MIT, because the kernel
verifier requires a GPL-compatible license for the helpers they use. See [NOTICE](NOTICE).
