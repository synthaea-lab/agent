# Fuzzing

Coverage-guided fuzzing (libFuzzer, through `cargo-fuzz`) for the parsers that read kernel
and attacker-influenced bytes. The contract is the same for every target: any input may fail
to parse, none may panic, because a panic on a drain path stops the sensor. The deterministic
robustness suites in each crate's `tests/` pin the same contract on every `cargo test`.

| Target | Exercises |
| --- | --- |
| `audit_parse` | the audit netlink message parser (`sensor-linux-audit`) |
| `netlink_parse` | the `sock_diag`, proc connector and conntrack decoders (`sensor-linux-netlink`) |
| `exec_record_parse` | the variable-length exec record and its argv windows (`sensor-linux-wire`) |
| `logs_parse` | the web access log and MySQL error log parsers (`sensor-linux-logs`) |

This crate is excluded from the workspace: it needs a nightly toolchain and libFuzzer
instrumentation, and runs on Linux or macOS.

## Running

Install `cargo-fuzz` once, then run a target from the repository root:

```sh
cargo install cargo-fuzz
cargo +nightly fuzz run --fuzz-dir tests/fuzz audit_parse -- -max_total_time=300
```

A crash writes a reproducer under `tests/fuzz/artifacts/<target>/`. Minimize it:

```sh
cargo +nightly fuzz tmin --fuzz-dir tests/fuzz <target> <artifact>
```

then add the minimized input as a regression test to the owning crate's robustness suite,
named after the behavior, and fix the parser. The corpus and artifacts are not committed.
