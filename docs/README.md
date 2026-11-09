# Technical documentation

How the agent works, with links into the code that implements each mechanism. Code
comments state only the why or the invariant and link the matching section here, so
when the code and a page disagree, fix the page in the same pull request.

Status at a glance: [capabilities.md](capabilities.md) (what is built, partial or planned,
with evidence) and [roadmap.md](roadmap.md) (generated from it and the tracking issues).
ATT&CK techniques with named detection content: [attack-coverage.md](attack-coverage.md).

Links and anchors in these pages are checked in CI by `tools/check-docs.py`.

## Contributors

Start with the architecture, then the page for the area you are changing.

- [architecture.md](architecture.md): binaries, crate map, dependency direction, where platform code lives.
- [lifecycle.md](lifecycle.md): one event from sensor to upload, threads, queues, startup and shutdown per OS.
- [schema.md](schema.md): the event model, the sensor contract, schema versioning and golden fixtures.
- [state-and-storage.md](state-and-storage.md): `BoundedMap` and the durable upload spool.
- [configuration.md](configuration.md): `agent.toml` discovery and validation, the signed policy document, policy helpers.
- [redaction.md](redaction.md): raw for detection, redacted for output; the redaction functions and their limits.
- [development.md](development.md): toolchains, building, testing, sibling checkouts, CI gates.
- [local-interfaces.md](local-interfaces.md): the local IPC channel, `cli`, the JSONL outputs.

### Sensors

- [sensors/linux/README.md](sensors/linux/README.md): map of the Linux sources and how the agent composes them.
  - [ebpf-probes.md](sensors/linux/ebpf-probes.md): raw tracepoint router, BTF-patched offsets, maps, in-kernel filters, verifier rules.
  - [wire-format.md](sensors/linux/wire-format.md): the ring-buffer ABI and the variable-length exec record.
  - [userspace-loader.md](sensors/linux/userspace-loader.md): build, load and attach, the drain loop, normalization, loss.
  - [process-context.md](sensors/linux/process-context.md): lineage, process generations, argv, parent image, containers.
  - [signals.md](sensors/linux/signals.md): signals to the agent and to security tools, the pinned `SIGKILL` slot.
  - [lsm.md](sensors/linux/lsm.md): BPF-LSM `file_open` and `inode_setattr`.
  - [uprobes.md](sensors/linux/uprobes.md): TLS, readline, `getaddrinfo` and UDP/53 capture.
  - [audit-fallback.md](sensors/linux/audit-fallback.md): the `NETLINK_AUDIT` fallback and the SELinux AVC reader.
  - [netlink.md](sensors/linux/netlink.md): `sock_diag`, conntrack, proc connector.
  - [journal.md](sensors/linux/journal.md): sshd, PAM, sudo/su and systemd unit events from journald.
  - [service-logs.md](sensors/linux/service-logs.md): web access logs and the MySQL error log.
  - [procmem.md](sensors/linux/procmem.md): process memory reads for YARA memory scanning.
  - [testing.md](sensors/linux/testing.md): unit, robustness, fuzz and live lab tests.
- [sensors/windows/README.md](sensors/windows/README.md): the four Windows sources and their silence heartbeats.
  - [etw.md](sensors/windows/etw.md): the ETW session, providers, threading, back-pressure, liveness.
  - [etw-enrichment.md](sensors/windows/etw-enrichment.md): identity, paths, containers, mark-of-the-web, BITS, remote threads, LSASS.
  - [eventlog.md](sensors/windows/eventlog.md): Event Log poll targets, transports, audit policy.
  - [sockets.md](sensors/windows/sockets.md): socket-table snapshots for LISTENER-DRIFT.
  - [minifilter.md](sensors/windows/minifilter.md): the file-system minifilter and its event channel.
- [sensors/macos/README.md](sensors/macos/README.md): the four macOS sources and why they use C shims.
  - [endpoint-security.md](sensors/macos/endpoint-security.md): the EndpointSecurity client.
  - [unified-log.md](sensors/macos/unified-log.md): sudo, TCC and Gatekeeper from `log stream`.
  - [sockets.md](sensors/macos/sockets.md): libproc socket snapshots.
  - [network-extension.md](sensors/macos/network-extension.md): flows and DNS from the Network Extension.

## Detection engineers

- [detection/README.md](detection/README.md): the engines, how the sink connects them, shared conventions.
- [detection/rules.md](detection/rules.md): stateless and stateful rules, `RuleState`, signature-gated findings.
- [detection/sigma.md](detection/sigma.md): the supported Sigma subset and its load-time validation.
- [detection/yara.md](detection/yara.md): file and process-memory scanning.
- [detection/ioc.md](detection/ioc.md): IOC feeds, matching and the own-traffic skip.
- [detection/enrichment.md](detection/enrichment.md): hashes, signatures and PE version strings.
- [detection/ml.md](detection/ml.md): on-device ML tiers, feature parity, scoring and attribution.
- [detection/deception.md](detection/deception.md): canary files and decoy credentials.
- [correlation.md](correlation.md): co-occurrence rules, the Bayesian belief, kill shields, verdict fusion.
- [attack-coverage.md](attack-coverage.md): ATT&CK techniques with named detection content (generated).

## Operators

- [security-model.md](security-model.md): trust boundaries, privileges per OS, signing keys, attack surface, what is not defended.
- [self-protection.md](self-protection.md): watchdog, hang and silence detection, integrity checks, release probation.
- [response.md](response.md): kill, quarantine, escalation and isolation, and how to undo them.
- [transport.md](transport.md): the control-plane channel, spooling, retries and degraded behavior.
- [updates-and-releases.md](updates-and-releases.md): signed releases, content rings, key rotation, rollback, `release-tool`.
- [packaging.md](packaging.md): packages per OS, the bootstrap layout, the release workflow.
- [release.md](release.md): cutting a release, the release PR, signing, the unsigned-alpha rule, every release secret.
- [configuration.md](configuration.md): every `agent.toml` key and environment override.
- [local-interfaces.md](local-interfaces.md): `cli` commands and the local output files.
- [capabilities.md](capabilities.md) and [roadmap.md](roadmap.md): what works today and what comes next.
