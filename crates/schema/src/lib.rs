//! # schema
//!
//! The platform boundary of the agent: the normalized event model shared by every
//! sensor, the rule engine, the correlator, and the ML feature extractors, plus the
//! [`sensor`] contract every platform sensor implements.
//!
//! ## Semi-frozen API
//!
//! Every crate in the workspace depends on this one. Changes to public types ripple
//! everywhere and need explicit justification in review — prefer additive changes
//! (new fields with serde defaults, new [`Event`] variants) over reshaping what exists.
//!
//! **Every serialization-visible change bumps [`SCHEMA_VERSION`]** and adds a full
//! `tests/fixtures/v<N>/` snapshot (existing fixture files are never edited) — no
//! exception for additive changes, even though they don't break a Rust reader on
//! this crate's current types. This resolves issue #114 (closed): a change is
//! "visible" in three ways, and all three bump the version the same way —
//!
//! 1. **New optional field** on an existing type (e.g. [`EventMeta::container`],
//!    #169, v9 → v10) — non-breaking for a Rust reader (`#[serde(default)]`), but
//!    a non-Rust consumer (the server, a SIEM export) that snapshots the field set
//!    it deserializes still sees a change.
//! 2. **New [`Event`] variant** (e.g. `Event::Auth`, #94, v12 → v13) — non-breaking
//!    for a Rust reader too ([`Event`] is `#[non_exhaustive]`, forcing a wildcard
//!    match arm), but it changes the closed set of `"type"` tag values a consumer
//!    keying on that tag can see, the same concern as case 1.
//! 3. **Removal, rename, or type change** — breaking outright, bumps for the
//!    obvious reason.
//!
//! Bumping on 1 and 2 costs nothing (the version is metadata, not a compatibility
//! gate — old fixtures keep deserializing under new types, see
//! `tests/v1_compat.rs`) and buys every consumer an honest signal of "this shape
//! didn't exist before v*N*", which not bumping would silently hide. See
//! `docs/architecture/event-schema.md` for the full contract and worked examples.
//!
//! Not every change to this crate is a schema change: reusing bits within an
//! *existing* field (e.g. [`FLAG_PERSISTENCE_ARTIFACT`]) adds no new shape, so it
//! does not bump [`SCHEMA_VERSION`] — see that constant's doc comment. Nor is this
//! the same contract as a sensor's own wire ABI (e.g. `sensor-linux-wire`'s
//! `WIRE_VERSION`, bumped independently for #204): that governs the eBPF-to-
//! userspace struct layout on one platform, never this crate's public JSON model.
//!
//! ## Layout
//!
//! The event types live in one private module per domain (`process`, `file`, `network`,
//! `auth`, …) and are all re-exported here, so every type is `schema::Name` whatever file
//! holds it. [`Event`], the enum that carries them, is in `event`; the fields every event
//! shares are in `meta`.
//!
//! ## What this crate is not
//!
//! Not the wire format. Sensors normalize their platform's native representation into
//! these types; fixed-size `repr(C)` structs for the eBPF ring buffer live with the
//! Linux sensor pair (`sensors/linux`), ETW layouts with `sensors/windows/etw`. The
//! old iteration let the eBPF wire format (fixed 256-byte buffers, `TASK_COMM_LEN`)
//! define the shared model; that is deliberately undone here — command lines and paths
//! are unbounded owned strings (Windows encoded-PowerShell command lines run to
//! kilobytes), and user identity is per-platform instead of a bare Unix uid.

use serde::{Deserialize, Serialize};

pub mod detection;
#[cfg(feature = "test-fixtures")]
pub mod fixtures;
pub mod sensor;
pub mod time;

/// Version of the serialized event model. Bumped on any serialization-visible change,
/// together with a new golden-fixture directory (see crate docs).
///
/// Bumped 12 → 13 for [`Event::Auth`] (#94): a new enum variant is a new possible
/// `"type"` tag value, which counts as serialization-visible per the rule above —
/// even though it breaks nothing for readers of *old* data (see `tests/v1_compat.rs`,
/// which pins that `tests/fixtures/v1/*.json`, frozen and never edited, still
/// deserialize under the current `Event` type). `tests/fixtures/v13/` is a full
/// snapshot (every golden fixture, not only the new `Auth` ones), matching the
/// precedent already established by versions 2 through 12. Originally claimed as
/// 10 → 11 while this branch was open; rebased to 13 once #189 (`NetworkFlow`,
/// 11 → 12) merged into `main` first — same coordination note as the shared auth-event design.
///
/// Bumped 13 → 14 for [`Event::TlsCapture`] and [`Event::ReadlineInput`] (#90):
/// two new enum variants for uprobes-based TLS plaintext capture and shell readline
/// input capture. Same serialization-visible reasoning as v13 above.
///
/// Bumped 14 → 15 for [`Event::FileWrite`], [`Event::FileDelete`], and
/// [`Event::FileRename`] (#262): three new enum variants for Linux
/// write/delete/rename telemetry. Same serialization-visible reasoning as v13/v14.
///
/// Bumped 15 → 16 for [`Event::SocketBind`] (#263): one new enum variant for
/// discrete, real-time `bind(2)` telemetry on Linux. Same reasoning as v13-v15.
///
/// Bumped 16 → 17 for [`Event::FileChmod`] and [`Event::FileChown`] (#262 Phase 2):
/// two new enum variants for Linux permission/ownership-change telemetry. Same
/// reasoning as v13-v16.
///
/// Bumped 17 → 18 for [`Event::SocketListen`] (#263 Phase 2): one new enum variant
/// for discrete, real-time `listen(2)` telemetry on Linux. Same reasoning as
/// v13-v17.
///
/// Bumped 18 → 19 for [`Event::SocketAccept`] (#263 Phase 2): one new enum variant
/// for `accept(2)`/`accept4(2)` telemetry (the peer address of a newly accepted
/// connection) on Linux. Same reasoning as v13-v18.
///
/// Bumped 19 → 20 for [`Event::TccDecision`] and [`Event::GatekeeperVerdict`]
/// (#95): two new enum variants for macOS unified-log telemetry (TCC
/// privacy-permission decisions, Gatekeeper scan verdicts). macOS-only families,
/// same precedent as the Windows-only `RegistrySet`/`WmiActivity`/`ScriptBlock`
/// variants; same serialization-visible reasoning as v13-v19. Originally
/// claimed as 18 → 19 while #95's branch was open; renumbered once #263's
/// `SocketAccept` (18 → 19) merged into `main` first — the same coordination
/// note as v13 and the shared auth-event design.
///
/// Bumped 20 → 21 for [`Event::FileQuarantine`], [`Event::Mount`],
/// [`Event::Signal`], and [`Event::XpcConnect`] (#96, the macOS
/// `EndpointSecurity` catalog widening): download provenance, mount/unmount,
/// tamper-relevant signals, and XPC connections. `Mount` and `Signal` are
/// platform-neutral shapes (Linux mount/kill telemetry can reuse them);
/// `FileQuarantine`/`XpcConnect` are macOS-only families per the v20
/// precedent. Same serialization-visible reasoning as v13-v20. Originally
/// claimed as 19 → 20 while #96's branch was open; renumbered with the rest
/// of the macOS stack when `SocketAccept` took v19 on `main` first.
///
/// Bumped 21 → 22 for [`Event::FileSetxattr`] and [`Event::FileRemovexattr`]
/// (#262 Phase 3): two new enum variants for Linux extended-attribute
/// telemetry (`setxattr(2)`/`removexattr(2)`). Same reasoning as v13-v21.
/// Originally claimed as 19 → 20 while this branch was open; renumbered once
/// the macOS stack (#95/#96) took v19-v21 on `main` first — same coordination
/// note as v13 and the shared auth-event design.
///
/// Bumped 22 → 23 for [`Event::PolicyDenial`] (#297): one new enum variant
/// for OS-security-mechanism denials, first emitted by `sensor-linux-audit`
/// from `SELinux` AVC records. Deliberately generic (`mechanism: String`,
/// not a Linux-only shape) so Windows AppLocker/WDAC (#328) and macOS
/// TCC/Gatekeeper — which already have their own dedicated `Event` variants,
/// [`TccDecisionEvent`]/[`GatekeeperVerdictEvent`] from v20 — can reuse it
/// instead of growing a fourth parallel "denial" family later. Schema-only:
/// no detection rule ships with this bump, see the issue for why. Same
/// serialization-visible reasoning as v13-v22. Originally claimed as 21 → 22
/// while this branch was open; renumbered once #262 Phase 3's xattr telemetry
/// took v22 on `main` first — same coordination note as v13 and the shared auth-event design.
///
/// Bumped 23 → 24 for [`Event::KernelModule`] and [`Event::BpfOperation`]
/// (#264: kernel module load/unload and eBPF program/map lifecycle
/// telemetry — `init_module(2)`/`finit_module(2)`/`delete_module(2)` and a
/// filtered `bpf(2)`). Linux-only, no cross-platform reuse (same posture as
/// #265's `Ptrace`/`ProcessVmRead`/`ProcessVmWrite`/`MemfdCreate` — these
/// syscalls have no Windows/macOS analogue this shape fits). Same
/// serialization-visible reasoning as v13-v23. Originally claimed as 21 → 22
/// while this branch was open; renumbered to 22 → 23 once `#262` Phase 3's
/// xattr telemetry took v22 on `main` first, then to 23 → 24 once `#297`'s
/// `PolicyDenial` took v23 on `main` in turn — same coordination note as above.
///
/// Bumped 24 → 25 for [`Event::Ptrace`], [`Event::ProcessVmRead`],
/// [`Event::ProcessVmWrite`], and [`Event::MemfdCreate`] (#265: process
/// injection/debugging telemetry — `ptrace(2)`, `process_vm_readv(2)`/
/// `process_vm_writev(2)`, `memfd_create(2)`). Linux-only, no cross-platform
/// reuse (unlike `AuthEvent`'s logon/session precedent) — these syscalls have no
/// Windows/macOS analogue this shape fits. Same serialization-visible reasoning
/// as v13-v24. Originally claimed as 21 → 22 while this branch was open, then
/// renumbered each time another PR took the number first: 22 → 23 (#262 Phase 3
/// xattr), 23 → 24 (#297 `PolicyDenial`), 24 → 25 (#264 kernel module / eBPF).
///
/// Bumped 25 → 26 for [`Event::IdentityChange`], [`Event::CapSet`], and
/// [`Event::Namespace`] (#266: privilege escalation, capability abuse, and
/// container-escape telemetry via `setuid`-family syscalls, `capset(2)`, and
/// `setns(2)`/`unshare(2)`). Linux-only, no cross-platform reuse, same
/// posture as #264/#265's Linux-only additions. Same serialization-visible
/// reasoning as v13-v25.
///
/// Bumped 26 → 27 for [`ExecEvent::env_security`] (#363): a present-only
/// allowlist capture of the loader-hijack environment family (`LD_PRELOAD`,
/// `LD_LIBRARY_PATH`, `LD_AUDIT`, `LD_DEBUG_OUTPUT`, `GLIBC_TUNABLES`) —
/// additive optional field, no new `Event` variant, same serialization-visible
/// reasoning as every field addition since v13. Originally claimed as 21 → 22
/// while this branch was open, then renumbered each time another PR took the
/// number first: 22 → 23 (#262 Phase 3 xattr), 23 → 24 (#297 `PolicyDenial`),
/// 24 → 25 (#264), 25 → 26 → 27 (#265, #266).
///
/// Bumped 27 → 29 for [`CapSetEvent`]'s capability sets widening from `u32`
/// to `u64` and the new optional [`KernelModuleEvent::path`] (#457). A v27
/// reader rejects a capability mask above `u32::MAX` (`CAP_BPF` is bit 39),
/// so the widening is serialization-visible even though every value below
/// 2^32 still serializes identically. 28 was claimed by #469 (ATT&CK technique
/// ids) while both branches were open; #457 merged first, so #469 renumbers
/// below — same coordination note as v13 and the shared auth-event design.
///
/// Bumped 29 → 30 for [`PolicyDenialEvent::object_path`] (#427, Linux half:
/// filled from the AVC record's `path=`/`name=`; the Windows `AppLocker` half —
/// switching the 8004 emitter off `FileOpenEvent` and adding the 8003 audit-
/// mode target — is a separate follow-up, #428 was step 1 only).
///
/// Bumped 30 → 31 for [`detection::Detection::techniques`] (#74): structured
/// ATT&CK technique identifiers on a detection, additive `Vec<String>`
/// alongside `attributions`, no new variant. 30 was claimed by #469 while
/// both branches were open; #427/#490 merged first, so #469 renumbers here —
/// same coordination note as v13, v28→29, and the shared auth-event design. Same
/// serialization-visible reasoning as every field addition since v13.
///
/// Bumped 31 → 32 for [`FileRenameEvent::executable_path`] (#459 part 1): the
/// renaming process's own executable path, so an evidence-gated exclusion
/// (comm + trusted path, `policy::name_exclusion_applies`) can discriminate
/// `sed -i.bak`/`perl -i.orig` from a real mass-rename encryptor instead of
/// trusting `comm` alone. `None` when the sensor couldn't resolve it (macOS
/// ES always provides it for free; Linux reads `/proc/<pid>/exe` at rename
/// time and the pid can have already exited by then — see
/// `sensor-linux/normalize.rs`'s doc for that race). 31 was claimed by #74
/// while both branches were open; #74 merged first, so this one renumbers —
/// same coordination note as v13, v28→29, and v30→31 above.
///
/// Bumped 32 → 33 for [`MemfdCreateEvent::fd`] (#510): the descriptor
/// `memfd_create(2)` returned, so `check_memfd_exec` can compare it to the
/// `<n>` of an exec via `/proc/self/fd/<n>` instead of correlating on pid and
/// time alone. 32 was claimed by #513 (`FileRenameEvent::executable_path`) while
/// both branches were open; #513 merged first, so this one renumbers — same
/// coordination note as v13, v28→29 and v30→31 above.
///
/// Bumped 33 → 34 for [`Event::Prctl`] (#457): the two `prctl(2)` options that
/// reshape a process tree's privilege ceiling, `PR_SET_SECUREBITS` and
/// `PR_CAPBSET_DROP`, filtered at the source. Linux-only, no cross-platform
/// reuse (same posture as `Ptrace`/`Namespace`). Same serialization-visible
/// reasoning as v13-v33.
///
/// Bumped 34 → 35 for [`EventMeta::process_generation`] and
/// [`EventMeta::parent_process_generation`] (#519): an opaque stamp
/// that tells two incarnations of one pid apart, so a pid-keyed cache (`rules`'
/// `pid_comm`, `pid_image_path`) can tell a recycled pid from the process it
/// remembers. Additive and optional (`None` on Windows and macOS, and on Linux
/// events the sensor could not stamp), the same serialization-visible reasoning
/// as v13-v34.
///
/// Bumped 35 → 36 for [`Event::HttpRequest`] and [`Event::HttpSummary`] (#478):
/// what the agent derives from a web server's access log — one event for a request
/// that matches a detection signature, one summary per source per window. Neither
/// reuses an existing variant; both carry a `meta` with `pid`/`ppid` 0,
/// since a log line names no process. Same serialization-visible reasoning as v13-v35.
///
/// Bumped 36 → 37 for [`Event::AmsiContent`] (#282): the post-decoding buffer
/// a runtime hands to AMSI before running it (EID 1101 of
/// Microsoft-Antimalware-Scan-Interface). Windows-only, same posture as
/// `ScriptBlock`. 36 was claimed by #478 (`HttpRequest`/`HttpSummary`) while
/// both branches were open; #478 merged first, so this one renumbers — same
/// coordination note as v13, v28→29, v30→31 and v32→33 above.
///
/// Bumped 37 → 38 for [`Event::Defender`] (#283): Microsoft Defender
/// Antivirus verdicts and tamper traces (EIDs 1116/1117/5001/5007/5010/5012
/// of its Operational channel). Windows-only. #632 (`LdapSearch`) also
/// targets v38 while both branches are open: whichever merges second
/// renumbers, same coordination note as v13, v28→29, v30→31 and v32→33.
///
/// Bumped 38 → 39 for [`Event::UdpRecv`] (#263): one new enum variant for inbound
/// UDP datagrams (`recvfrom(2)`) on Linux, the counterpart of [`Event::UdpSend`].
/// #654 also targets v39 while both branches are open: whichever merges second
/// renumbers, as above.
///
/// Bumped 39 → 40 for [`Event::Session`] (#285): session lifecycle from the
/// Windows Terminal Services channels (connect, logon, disconnect, reconnect,
/// logoff). It claimed 39 alongside #650 (`UdpRecv`), which merged first, so
/// this one renumbers. #577 (`BitsJob`) also targets v40 while both branches
/// are open: whichever merges second renumbers, as above.
///
/// Bumped 40 → 41 for [`Event::LdapSearch`] (#364): the LDAP searches a
/// process sends (EID 30 of Microsoft-Windows-LDAP-Client), the endpoint's
/// view of directory reconnaissance. Windows-only, same posture as
/// `WmiActivity`. 38 was claimed by #283 (`Defender`), 39 by #263 (`UdpRecv`) and 40 by
/// #285 (`Session`) while this branch was open; all merged first, so this
/// one renumbers, same coordination note as above.
///
/// Bumped 41 → 42 for [`Event::SocketCreate`] (#263): `socket(2)`, context
/// rather than an address — the domain/type/protocol the caller asked for.
/// Closes the last gap in #263's telemetry proposal besides the netlink
/// socket-table baseline (a separate, periodic-snapshot source, not a
/// discrete syscall trace like the rest of this file).
///
/// Bumped 42 → 43 for [`Event::PackageChange`] (#87): a package was added,
/// removed, or changed version since the agent's last diffed inventory
/// snapshot — the walking-skeleton slice of the asset inventory, packages
/// only, Linux only.
/// Bumped 43 → 44 for [`Event::NtlmAuth`] (#364): NTLM authentications from
/// the Microsoft-Windows-NTLM provider (direction, account, target, remote
/// address, NTLM version). Windows-only. It claimed 41 while #632 (`LdapSearch`)
/// was open, then 43 after #263 (`SocketCreate`, 42) merged, then 44 after #772
/// (`PackageChange`) took 43; same coordination note as above.
///
/// Bumped 44 → 45 for [`Event::LogCleared`] (#799): a Windows event log
/// cleared, from the record the Event Log service writes into the fresh log
/// (Security 1102, System 104), whatever did the clearing. Windows-only.
/// #577 (`BitsJob`) was open at the same time; whichever merges second
/// renumbers, same coordination note as above.
///
/// Bumped 45 → 47 for [`Event::DnsQuery`] (#458): Linux glibc `getaddrinfo`
/// telemetry now includes an ordered address set and an explicit truncation flag.
/// 46 was claimed by #577 (`BitsJob`, open at the time); it landed second and
/// renumbers below, same coordination note as above.
///
/// Bumped 47 → 48 for [`Event::BitsJob`] (#284): BITS jobs from
/// `Microsoft-Windows-Bits-Client`, the only record that ties a BITS download
/// (whose network I/O the service does itself) back to the process that asked
/// for it. Windows-only. It claimed 35, then 40, then 42, then 43, then 44,
/// then 45, then 46, while #519, #654, #632, #263, #87, #364, #799 and #458
/// merged first with 35, 40, 41, 42, 43, 44, 45 and 47; same coordination
/// note as above.
///
/// Bumped 48 → 52 for [`detection::DetectionSource::Ioc`] (#60): an on-device
/// indicator match (hash, IP or domain) carrying the indicator, its
/// [`detection::IocKind`] and the feed provenance. #993, #994 and #995 were open
/// at the time and each claim 49; 50 and 51 are left for the two that renumber.
/// Whichever of these merges later renumbers, same coordination note as above.
///
/// Bumped 52 → 53 for [`ExecEvent::original_file_name`], [`ExecEvent::company_name`],
/// [`ExecEvent::file_description`] and [`ExecEvent::product_name`] (#983): PE
/// version-resource metadata for the executed image, read by enrichment. Windows
/// only (`None` elsewhere). Originally claimed 49, renumbered on merge: #60 landed
/// first and took 52, leaving 50/51 reserved for #994/#995 (also renumbering from
/// their own 49 claims) — this PR took the next free number above all three
/// instead of guessing which of 50/51 would still be open by the time it merged.
///
/// Bumped 53 → 55 for [`Event::KerberosDelegationFailure`] (#364): the Kerberos
/// client's own unconstrained-delegation and TGT-session-key-export denials,
/// from the (off by default) `Microsoft-Windows-Kerberos/Operational` channel.
/// Windows-only. Originally claimed 49; renumbered past #60's 52 and #983's 53.
/// #994 merged first, ahead of the 54 it had reserved for #995, so main went
/// straight from 53 to 55 and left 54 unused.
///
/// Bumped 55 → 56 for Windows minifilter explicit timestamp requests (#136). #995
/// (`ListenPortEvent::protocol`) had planned to renumber past the skipped 54 to 57.
///
/// Bumped 56 → 57 for mounted raw-volume open telemetry (#136 slice 4), stacked on
/// the timestomp slice above — it merged first and took the 57 #995 was planning
/// on, without #995 having pushed its own renumbering commit yet.
///
/// Bumped 57 → 58 for [`ListenPortEvent::protocol`] (<https://github.com/synthaea-lab/agent/issues/40> part 1): #136 slice 4
/// merged first and took 57, which this had also claimed; 58 is the next free
/// number above it.
///
/// Not bumped for the Windows UDP collector (<https://github.com/synthaea-lab/agent/issues/40> part 2, stacked on #995): no
/// wire change — #995 already defined `ListenPortEvent::protocol`; this PR only
/// fills it with the real value (6 or 17) instead of #995's TCP-only `6` (review
/// of #1008).
///
/// Bumped 58 → 59 for [`ExecEvent::image_file_id`] (#688): the identity of the
/// image file at exec time, so the T1204.002 signature gate can distinguish the
/// image that ran from whatever the path contains when it is later verified.
///
/// Bumped 59 → 62 for [`Event::UnitStop`] (#1085): the stop of a security-tool systemd unit as an
/// event of its own, replacing a `FileOpenEvent` carrying `FLAG_UNIT_STOPPED`. A raw `openat`
/// flag can carry any bit, so an unprivileged open could set that one.
///
/// Bumped 62 → 65 for [`ExecEvent::cmdline_truncated`] (#1112): a sensor now
/// bounds argv at capture and flags the cut. First claimed 61 while #1114 held 60;
/// #1085 landed first with 62, #1114 renumbered to 63 and <https://github.com/synthaea-lab/agent/issues/41> (#1150) claims 64,
/// so this takes 65. Whichever of those merges later renumbers, same coordination
/// note as above.
///
/// Bumped 65 → 66 for [`SignalEvent::target_unit`] (#1103): the systemd unit of the signalled
/// process, so an alert on a signal to a security tool names the tool and not only an image path;
/// and for [`SignalEvent::signals_lost`], the report of signals the sensor had no room for.
/// First claimed 60, then 63; #1116 took 65, so this takes 66.
///
/// Bumped 66 → 67 for [`Event::RemoteThread`] and [`Event::ProcessAccess`] (<https://github.com/synthaea-lab/agent/issues/41>): a thread
/// created in another process and a memory-reading open of LSASS, from the driver-free ETW
/// providers the Sysmon decision's lab capture (#715) confirmed, as the native equivalents of Sysmon 8
/// and 10. Windows only. [`ProcessAccessEvent::caller_image_path`] carries the caller's
/// full image, for the LSASS rule's expected readers (<https://github.com/synthaea-lab/agent/issues/45>). First claimed 63, then 64; #1112 and #1103 merged first and took 65
/// and 66, so this takes 67.
///
/// Bumped 67 → 68 for [`ExecEvent::argv_omitted_bytes`] (<https://github.com/synthaea-lab/agent/issues/48>): the
/// Linux exec probe reads a head and a tail window of the argument block and says
/// how much of it lies between them. First claimed 67;
/// <https://github.com/synthaea-lab/agent/issues/41> merged first and took it, so this takes 68.
///
/// Bumped 68 → 69 for [`SignalEvent::sender_is_watchdog`]
/// (<https://github.com/synthaea-lab/agent/issues/322>), so a signal from the agent's own watchdog
/// is told from an intruder's.
///
/// Bumped 69 → 70 for [`RegistrySetEvent::key`] becoming a [`RegistryKey`]
/// (<https://github.com/synthaea-lab/agent/issues/91>): a write through a key the Windows
/// sensor cannot name in full (opened relative to a root handle that predates its session,
/// about 80% of a live host's writes) is emitted with the part of the name it knows instead
/// of being dropped. First claimed 69; agent#323 merged first and took it, so this takes 70.
pub const SCHEMA_VERSION: u32 = 70;

mod auth;
mod event;
mod file;
mod flags;
mod health;
mod host;
mod http;
mod injection;
mod kernel;
mod meta;
mod network;
mod privilege;
mod process;
mod security_controls;
mod self_protection;

pub use auth::*;
pub use event::*;
pub use file::*;
pub use flags::*;
pub use health::*;
pub use host::*;
pub use http::*;
pub use injection::*;
pub use kernel::*;
pub use meta::*;
pub use network::*;
pub use privilege::*;
pub use process::*;
pub use security_controls::*;
pub use self_protection::*;
