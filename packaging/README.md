# packaging — Installers and Service Integration

Everything that turns build output into an installable, running agent per platform.
Subfolders are created when work on a platform starts.

| Platform | Artifacts | Service integration |
| --- | --- | --- |
| `windows/` | MSI (fleet deploy via GPO/Intune), signed binaries (signing not yet done) | SCM service (watchdog self-registers `SynthaEDR` via `install`/`uninstall`, invoked as MSI custom actions — see `windows/README.md`) |
| `macos/` | notarized .pkg, app bundle for the UI | launchd daemons, system-extension approval flow (ES + network entitlements) |
| `linux/` | .deb and .rpm, static musl build option | systemd units (agent + watchdog), sysusers/tmpfiles |

`windows/` (#37) is the first subfolder with real content: `Product.wxs` (WiX v3),
`build.ps1`, and its own `README.md` with install/build/test steps. Build-tested
end to end (install, uninstall, clean removal) on a real Windows 11 machine — see
that README's "Status" note for details. The "ETW manifest registration" this
table used to list for Windows has been dropped: `sensor-windows-etw` only
*consumes* existing OS/ETW providers, it doesn't publish its own manifest-based
provider, so there is nothing to register for that sensor. If a future sensor
does need to register its own ETW manifest, that belongs back in this table then.

Shared rules:
- Installers install the `updater`-managed layout from day one, so self-update never
  fights the package manager (packages own the bootstrap, `updater` owns the payload).
- Uninstall must be clean and complete — an EDR that leaves residue destroys trust.
- Signing/notarization pipelines are part of packaging, not an afterthought; unsigned
  dev builds are clearly marked and refuse to enroll against production servers.

The lab's `provisioning/agent-install` scripts consume these artifacts, so packaging
becomes real at the walking-skeleton milestone (first end-to-end scenario run).

## Release workflow (`.github/workflows/release.yml`)

Pushing a tag `vX.Y.Z[-suffix]` (or running the workflow by hand with an existing tag) builds
every artifact with the same jobs that guard packaging on `main` — they are `workflow_call`-able
and upload what they built only when the release calls them — then publishes a GitHub release.
A tag with a `-` suffix (`-beta.1`, `-rc.1`) is published as a **pre-release**. The workflow
never creates a tag itself.

| Platform | Built by | Published file | Notes |
| --- | --- | --- | --- |
| Debian/Ubuntu x86_64 | `linux-deb-portability.yml` | `synthaea-agent_<cargo version>-1_amd64.deb` | static musl; installed and started in CI first |
| Alpine x86_64 | `linux-apk-portability.yml` | `synthaea-agent-<pkgver>-r0.apk` | signed only by a throwaway `abuild` key: `apk add --allow-untrusted` |
| Windows x86_64 | `windows-static-agent.yml` | `synthaea-agent-<tag>-windows-x86_64.exe` | the agent executable alone, **no MSI** (`build.ps1` needs WiX and a watchdog build; no CI job runs it yet) |
| macOS arm64 | `macos-static-agent.yml` | `synthaea-agent-<tag>-macos-arm64.tar.gz` | the agent executable alone, **no .pkg**, not notarized |
| — | `release.yml` | `SHA256SUMS` (+ `SHA256SUMS.asc`, `synthaea-release-key.asc` when signed) | covers every file above |

Not produced yet: the `.rpm` (`linux/build-rpm.sh` has no CI job), the MSI and the macOS `.pkg`.
Package file names carry the version from `apps/agent/Cargo.toml` / `APKBUILD`, not the tag; the
workflow warns when the two differ.

**Test key (ADR-0027).** The release job runs `tools/check-no-test-key.sh` on the tagged tree
and, after collecting the artifacts, `tools/assert-no-test-key.sh` on every binary it is about
to publish (extracted from the `.deb`, the `.apk` and the macOS tarball, plus the `.exe`). Either
failing stops the release.

**Signing.** No updater release or content manifest is signed by this workflow: ADR-0027 keeps
those keys on hardware tokens, offline, and `release-tool sign` runs on the release manager's
machine. No artifact is code-signed either (Authenticode, Apple Developer ID and a package
repository key are all still to procure). The one signature CI can make is a detached GPG
signature over `SHA256SUMS`, from these **optional** secrets of the `release` environment
(Settings > Environments > `release`, created on the first run; add required reviewers there to
put a second person in front of every publish):

| Secret | Content |
| --- | --- |
| `RELEASE_GPG_PRIVATE_KEY` | ASCII-armored private key (a signing subkey) used for `SHA256SUMS.asc` |
| `RELEASE_GPG_PASSPHRASE` | its passphrase (empty if the key has none) |

Without `RELEASE_GPG_PRIVATE_KEY` the release is still published, with a warning in the run and
an **"UNSIGNED BUILD"** banner at the top of its notes. Code signing (`signtool` in `build.ps1`,
`codesign`/`notarytool` for macOS, a GPG key for apt/apk repositories) will add its own secrets
here when it lands.
