# Fuzzing

Coverage-guided (libFuzzer) fuzzing for the byte parsers — the deeper sibling
of the deterministic robustness suites in each crate's `tests/`. The contract
under test is the same everywhere: any input may fail to parse, none may panic,
because a panic on the drain path kills the sensor.

## Targets

| Target | Exercises |
| --- | --- |
| `audit_parse` | `sensor_linux_audit::parse_audit_message` (audit netlink wire) |
| `netlink_parse` | `DiagMsg` / `ProcEvent` / `ConntrackFlow` decoders (sock_diag, proc connector, conntrack attribute walks) |

## Running

Needs nightly and `cargo-fuzz` (`cargo install cargo-fuzz`). From the repo root:

```bash
cargo +nightly fuzz run audit_parse -- -max_total_time=300
cargo +nightly fuzz run netlink_parse -- -max_total_time=300
```

A crash drops a reproducer under `fuzz/artifacts/<target>/`; minimize with
`cargo +nightly fuzz tmin <target> <artifact>`, then pin the minimized input as
a regression test in the owning crate's robustness suite (named after the
behavior, per code-style.md) — the fuzz corpus itself stays untracked.

Baseline at introduction (2026-09-22, 90s each): `audit_parse` 43M execs,
`netlink_parse` 18M execs, zero crashes.
