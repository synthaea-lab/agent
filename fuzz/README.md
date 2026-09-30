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

## Cadence

`.github/workflows/fuzz.yml` runs every target for 10 minutes on Monday and
Thursday (and on demand: Actions > Fuzz > Run workflow, with a `seconds`
input). Each run restores the previous run's corpus from the Actions cache and
saves the grown one, so coverage accumulates; the twice-weekly rhythm keeps the
cache under GitHub's 7-day eviction. The corpus stays untracked.

A crash fails the job for that target (the other still runs) and uploads the
reproducer as the `fuzz-crash-<target>` artifact. Then follow the steps above:
minimize, pin as a regression test, fix. GitHub disables scheduled workflows
after 60 days without repository activity; re-enable it from the Actions tab if
that ever happens.

Baseline at introduction (2026-09-22, 90s each): `audit_parse` 43M execs,
`netlink_parse` 18M execs, zero crashes.
