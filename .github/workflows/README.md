# CI Workflows

| Workflow | Runs | Contents |
| --- | --- | --- |
| `ci.yml` | every push/PR | rustfmt, dependency-direction check, cargo-deny (licenses + RUSTSEC), clippy `-D warnings` + tests on ubuntu/windows/macos with the `server`/`ml`/`rules` siblings checked out beside this repo (`SYNTHAEA_REQUIRE_SIBLINGS=1`: a contract test that cannot find its sibling fails), and a `content` job running the sigma/yara/intel content suites against the `rules` sibling |
| `windows-static-agent.yml` | main, and changes to `crates/ml`, the onnxruntime build/link scripts, the lockfile or toolchain | onnxruntime built from source (cached by build-script hash), agent linked statically with `--no-default-features`, `check-pe-imports.py` fails on `onnxruntime.dll`/`directml.dll`/`d3d12.dll`, `agent.exe --help` (#746) |
| `macos-static-agent.yml` | main, and changes to `crates/ml`, the onnxruntime build/link scripts, `check-macho-imports.py`, the lockfile or toolchain | validated on `macos-15` (#338): onnxruntime built from source on an Apple Silicon runner (cached by build-script hash; Intel only on `workflow_dispatch`), `cargo test -p ml --no-default-features`, agent linked statically, `check-macho-imports.py` (beside `otool -L`) fails on any library that is not an OS one or that names onnxruntime, `agent --help` |
