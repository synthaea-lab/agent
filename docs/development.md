# Development

How to build and test the agent workspace, how tests that depend on the other public repositories
work, and what CI enforces on every pull request. Contribution rules (DCO sign-off, what is not
accepted, security reports) are in [`CONTRIBUTING.md`](../CONTRIBUTING.md).

## Toolchain

| Pin | File | Used for |
| --- | --- | --- |
| Rust 1.99.1 with `rustfmt`, `clippy` | [`rust-toolchain.toml`](../rust-toolchain.toml) | everything; rustup picks it up in the repository |
| a dated nightly | [`ebpf-toolchain.txt`](../ebpf-toolchain.txt) | compiling the Linux eBPF probes (with `rust-src`) |
| nightly `rustfmt` | none | [`rustfmt.toml`](../rustfmt.toml) uses unstable options that stable `rustfmt` silently ignores |

Bump a toolchain in its own commit: a bump hidden in a feature change makes breakage hard to bisect.
Build-machine provisioning scripts are described in [Packaging](packaging.md#toolchain-scripts).

## Building

```sh
cargo build                     # default members: agent, watchdog, cli, crates
cargo build -p agent --release
```

- `crates/sensors/linux/ebpf` (package `sensor-linux-ebpf`) is a workspace member but not a default member: it targets
  `bpfel-unknown-none` and is built by `sensor-linux`'s build script when the eBPF toolchain and
  `bpf-linker` are present. Without them the probes are skipped and the Linux sensor builds without
  them. CI and local commands pass `--workspace --exclude sensor-linux-ebpf`.
- `fuzz/` is excluded from the workspace; it needs nightly and libFuzzer
  (see [`fuzz/README.md`](../fuzz/README.md)).
- `agent`'s default features are `dynamic-onnx` (download a prebuilt ONNX Runtime) and `test-key`
  (the public updater test keys, plus the `--allow-test-key` flags). Packaged builds disable both
  defaults; see [Packaging](packaging.md#test-key-exclusion). The prebuilt runtime needs a recent
  libstdc++, so the default build does not link on Debian 12 or Ubuntu 22.04
  ([#53](https://github.com/synthaea-lab/agent/issues/53)).

## Testing

```sh
cargo test --workspace --exclude sensor-linux-ebpf
cargo test -p updater --no-default-features   # the packaged trust set (keys unprovisioned)
tools/gauntlet.sh                             # everything CI runs, on one machine
tools/gauntlet.sh --fast                      # skip the cross-target and docs passes
git config core.hooksPath tools/hooks         # opt-in: run the gauntlet on pre-push
```

[`gauntlet.sh`](../tools/gauntlet.sh) mirrors the CI jobs and adds a cross-target clippy sweep,
because host-only clippy never sees `cfg`-gated code for the other OSes.

### Sibling repositories

Some tests check a contract whose other half lives in another public repository: the server's
routes and golden fixtures, the ML pipeline's fixtures, the shipped detection content. The repos are
checked out side by side:

```text
<SYNTHAEA_ROOT>/
  agent/      this repository
  server/     synthaea-lab/server
  ml/         synthaea-lab/ml
  rules/      synthaea-lab/rules
  scenarios/  synthaea-lab/scenarios
```

Tests reach a sibling only through the dev-only [`siblings`](../crates/siblings/src/lib.rs) crate:
`siblings::require!(repo, rel)` returns a file's text and `siblings::require_path!(repo, rel)` a
path. When the sibling is absent they print one `skipped: needs sibling repo ...` line and return
from the test, so the agent builds and tests alone. Never use a relative path or `include_str!` into
a sibling.

| Variable | Effect |
| --- | --- |
| `SYNTHAEA_ROOT` | Directory holding the siblings (default: this repository's parent). |
| `SYNTHAEA_REQUIRE_SIBLINGS=1` | A missing sibling panics instead of skipping. CI's `test` and `content` jobs set it, so a contract test cannot pass by not running. |

Siblings track their `main` branch in CI, so a change on either side of a contract that the other
side cannot read fails the next run here.

### Privileged tests

The IPC end-to-end test ([`crates/ipc/tests/e2e.rs`](../crates/ipc/tests/e2e.rs)) needs root on Unix
or an elevated process on Windows to pass peer authentication, and otherwise skips itself. Because
`cargo test` hides a skip message on success, CI builds the test binary as the runner user, runs only
that binary under `sudo`, and sets `SYNTHAEA_REQUIRE_PRIVILEGED_TESTS=1`, which turns a skip into a
failure.

### PKCS#11 signing test

`release-tool`'s token test ([`pkcs11_softhsm.rs`](../release-tool/tests/pkcs11_softhsm.rs)) needs a
SoftHSM module and skips without one. Run it with [`tools/test-pkcs11.sh`](../tools/test-pkcs11.sh),
which finds the module (or uses `RELEASE_TOOL_SOFTHSM_MODULE`), creates a throwaway token directory,
and makes a skip fatal.

## CI gates

[`ci.yml`](../.github/workflows/ci.yml) runs on every push to `main` and every pull request. All jobs
use a read-only token and pinned action SHAs.

| Job | Checks |
| --- | --- |
| `lint` (ubuntu) | nightly `rustfmt --check`; dependency direction ([`check-deps.py`](../tools/check-deps.py)); PowerShell scripts ASCII-only; shell scripts with a shebang are executable in git; [`check-no-test-key.sh`](../tools/check-no-test-key.sh); `cargo test -p updater --no-default-features`; unit tests of the PE/Mach-O import checkers; `cargo doc` with `-D warnings`. |
| `deny` | `cargo-deny check` with [`deny.toml`](../deny.toml): licenses, RUSTSEC advisories, and stale advisory ignores as errors. |
| `test` (ubuntu, windows, macos) | Siblings checked out, `SYNTHAEA_REQUIRE_SIBLINGS=1`; `cargo clippy --workspace --all-targets -D warnings`; `cargo test --workspace`; on Linux the SoftHSM test; the privileged/elevated IPC e2e. |
| `content` | The `rules` sibling through the real engines (sigma, yara, IOC content suites) and `attack-coverage.py --check`, which fails when [`docs/attack-coverage.md`](attack-coverage.md) is stale. |
| `linux-ebpf` | The pinned nightly and a SHA-256-pinned `bpf-linker`; clippy with the probes embedded; fails if either probe object was not embedded. No tests (loading probes needs a privileged kernel). Its cache is never shared with `test`, where a restored build output would skip the probes. |

Other workflows:

| Workflow | When | Checks |
| --- | --- | --- |
| [`dco.yml`](../.github/workflows/dco.yml) | pull requests | every non-merge, non-bot commit has `Signed-off-by` with the author's email. |
| [`fuzz.yml`](../.github/workflows/fuzz.yml) | twice a week; 30 s smoke when the fuzz setup changes | coverage-guided fuzzing resuming from a cached corpus; not a merge gate. |
| [`linux-deb-portability.yml`](../.github/workflows/linux-deb-portability.yml), [`linux-apk-portability.yml`](../.github/workflows/linux-apk-portability.yml) | changes to the agent, Linux sensor, updater, packaging or toolchain | build, install and start the static packages. |
| [`windows-static-agent.yml`](../.github/workflows/windows-static-agent.yml), [`macos-static-agent.yml`](../.github/workflows/macos-static-agent.yml) | `main`, and changes to `ml`, the ONNX Runtime scripts, the lockfile or toolchain | static ONNX Runtime link and import checks. |
| [`release.yml`](../.github/workflows/release.yml) | `v*` tags | see [Packaging](packaging.md#release-workflow). |

### Workspace rules CI enforces

- **Dependency direction** ([`check-deps.py`](../tools/check-deps.py)): `schema` depends on no
  workspace crate; `policy` only on `schema`; sensor crates only on `schema`; detection crates never
  on a sensor; leaf crates (`transport`, `ipc`, `sinks`, `updater`, `config`, `store`, `response`,
  `conformance`) only on the base tier; only the binaries compose everything. A new crate must be
  added to the script's rules in the same change. This is why fetch-and-apply logic lives in the
  `agent` binary and not in `updater` or `transport`.
- **Platform code**: `cfg(target_os)` and platform-only dependencies are allowed only in
  `crates/sensors/*`, `crates/updater` (the Linux layout) and the quarantine permission helpers;
  platform dependencies must be target-gated. The three-OS `test` job is what enforces it.
- **Lints**: the workspace lint table plus clippy `-D warnings`; every `unsafe` block needs a
  `// SAFETY:` comment; every `pub` item is documented, with `# Errors` / `# Panics` sections.
