# packaging

Everything that turns build output into an installable agent running as a service.
[docs/packaging.md](../docs/packaging.md) explains the design in full: what each package
installs, how it cooperates with the self-updater, and the build constraints (static ONNX
Runtime, embedded eBPF probes, no public test key).

| Folder | Artifacts | Service integration |
| --- | --- | --- |
| [`linux/`](linux/README.md) | static musl `.deb` and `.apk`; `.rpm` | systemd unit, sysusers and tmpfiles; OpenRC on Alpine |
| [`windows/`](windows/README.md) | MSI (WiX v3) | Windows service registered by the watchdog |
| [`macos/`](macos/README.md) | app bundle and `.pkg` (design only) | launchd daemon and a network system extension |
| [`toolchain/`](toolchain) | build-machine provisioning, static ONNX Runtime build | none |

Rules every package follows:

- The package installs the bootstrap binaries and the layout the updater manages, so
  self-update never fights the package manager: the package owns the bootstrap, the updater
  owns the payload.
- Uninstall is clean and complete.
- Packaged builds are built without default features, so they never carry the public test
  signing keys.

## Release workflow

Pushing a tag `vX.Y.Z[-suffix]`, or running
[`release.yml`](../.github/workflows/release.yml) by hand for an existing tag, builds every
artifact and publishes a GitHub release.
A tag with a `-` suffix (`-beta.1`, `-rc.1`) is published as a pre-release. The workflow never
creates a tag.

| Platform | Published file | Notes |
| --- | --- | --- |
| Debian and Ubuntu, x86_64 | `synthaea-agent_<version>-1_amd64.deb` | static musl, installed and started in CI first |
| Alpine, x86_64 | `synthaea-agent-<version>-r0.apk` | signed only by a throwaway `abuild` key: `apk add --allow-untrusted` |
| Windows, x86_64 | `synthaea-agent-<tag>-windows-x86_64.exe` | the agent executable alone, no MSI yet |
| macOS, arm64 | `synthaea-agent-<tag>-macos-arm64.tar.gz` | the agent executable alone, no `.pkg` yet, not notarized |
| all | `SHA256SUMS`, plus `SHA256SUMS.asc` and `synthaea-release-key.asc` when signed | covers every file above |

Package file names carry the version from `apps/agent/Cargo.toml` and `APKBUILD`, not the
tag. No artifact is code-signed yet; `SHA256SUMS` carries a detached GPG signature when the
release is signed. The jobs, the test-key scan and the signing model are described in
[docs/packaging.md](../docs/packaging.md#release-workflow).
