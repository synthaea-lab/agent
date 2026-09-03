# CI Workflows

| Workflow | Runs | Contents |
| --- | --- | --- |
| `ci.yml` | every push/PR | rustfmt, dependency-direction check, cargo-deny (licenses + RUSTSEC), clippy `-D warnings` + tests on ubuntu/windows/macos |
| `ml.yml` | changes under `ml/` | ruff + pytest on the Python pipeline (ONNX parity check once migrated) |
| `content.yml` | changes under `rules/` | detection-content validation (YAML today; sigma-cli and yara-x compile checks once content lands) |
