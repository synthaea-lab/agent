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

A release is cut by merging the release PR that release-please keeps open on `main`; the tag
it creates runs [`release.yml`](../.github/workflows/release.yml), which builds every artifact
below, signs each platform whose secrets are configured, and publishes a GitHub release.
Without signing secrets the release is published as an unsigned alpha pre-release, which is
only allowed for 0.0.x versions. The flow, every secret and how to cut a release are in
[docs/release.md](../docs/release.md).

| Platform | Published file | Notes |
| --- | --- | --- |
| Debian and Ubuntu, x86_64 | `synthaea-agent_<version>-1_amd64.deb` | static musl, installed and started in CI first |
| Alpine, x86_64 | `synthaea-agent-<version>-r0.apk` | signed only by a throwaway `abuild` key: `apk add --allow-untrusted` |
| Windows, x86_64 | `synthaea-agent-<version>-windows-x86_64.exe` | the agent executable alone, no MSI yet; Authenticode-signed when configured |
| macOS, arm64 | `synthaea-agent-<version>-macos-arm64.tar.gz` | the agent executable alone, no `.pkg` yet; Developer ID signed and notarized when configured |
| all | `synthaea-{agent,watchdog,cli}-<version>.cdx.json` | CycloneDX SBOM per binary |
| all | `SHA256SUMS`, plus `SHA256SUMS.asc` and `synthaea-release-key.asc` when signed | covers every file above |

The version comes from `[workspace.package]` in `Cargo.toml`; the release PR updates it with
`APKBUILD`, the rpm spec and `Product.wxs`. Every file has a build provenance attestation. The
jobs and the test-key scan are described in
[docs/packaging.md](../docs/packaging.md#release-workflow).
