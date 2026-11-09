# tools

Developer and release tooling. The Python scripts use the standard library only and run
the same on Linux, macOS and Windows; the shell scripts need a POSIX shell.

| Tool | Purpose |
| --- | --- |
| [`gauntlet.sh`](gauntlet.sh) | Runs every check a pull request must pass, on one machine. `--fast` skips the cross-target and documentation passes. |
| [`hooks/pre-push`](hooks/pre-push) | Optional pre-push hook that runs the gauntlet: `git config core.hooksPath tools/hooks`. |
| [`check-deps.py`](check-deps.py) | Enforces the dependency direction between workspace crates. |
| [`check-docs.py`](check-docs.py) | Checks links and anchors in `README.md` and `docs/`. |
| [`attack-coverage.py`](attack-coverage.py) | Generates `docs/attack-coverage.md` from this repository and a `rules` checkout; `--check` fails when it is stale. |
| [`gen-roadmap.py`](gen-roadmap.py) | Generates `docs/roadmap.md` from `docs/capabilities.md` and the tracking issues (needs `gh`). |
| [`check-exec-bits.py`](check-exec-bits.py), [`check-ps1-ascii.py`](check-ps1-ascii.py) | Keep shell scripts executable in git and PowerShell scripts ASCII-only. |
| [`check-pe-imports.py`](check-pe-imports.py), [`check-macho-imports.py`](check-macho-imports.py) | Fail when a Windows or macOS agent binary loads ONNX Runtime or another non-system library. Tests in [`tests/`](tests). |
| [`check-ebpf-symbols.py`](check-ebpf-symbols.py) | Fails when the built eBPF object's program or map names differ from [`crates/sensors/linux/ebpf/symbols.txt`](../crates/sensors/linux/ebpf/symbols.txt), the names the loader looks up. `--sizes` prints per-program instruction counts to compare before and after a change. Tests in [`tests/`](tests). |
| [`check-no-test-key.sh`](check-no-test-key.sh), [`assert-no-test-key.sh`](assert-no-test-key.sh) | Prove that packaged builds do not carry the public test signing keys. |
| [`test-pkcs11.sh`](test-pkcs11.sh) | Runs `release-tool`'s hardware-token test against SoftHSM. |
| [`release/`](release) | `release-tool`, the offline tool that builds and signs release, content and key-rotation manifests. |

How these fit into the development workflow is described in
[docs/development.md](../docs/development.md).
