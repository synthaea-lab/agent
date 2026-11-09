//! The download-to-execution rules of [`crate::RuleState`]: a file a known downloader wrote
//! (T1105), a file carrying a download-provenance mark (T1204.002, T1566.001), a file a BITS job
//! fetched (T1197), and a file whose mark-of-the-web was removed (T1553.005), each executed
//! within its window.

use schema::{
    BitsJobEvent, BitsJobState, ExecEvent, FileDeleteEvent, FileOpenEvent, FileQuarantineEvent,
    FileRenameEvent, FileSetxattrEvent, User, detection::Severity,
};
use store::BoundedMap;

use crate::{
    Alert,
    exclusions::{
        BITS_EXEC_WINDOW_NS, DOWNLOAD_EXEC_WINDOW_NS, DOWNLOADER_COMMS,
        MAIL_CLIENT_QUARANTINE_AGENTS, QUARANTINE_EXEC_WINDOW_NS,
    },
    has_write_intent,
    signature_gate::SignatureGatedAlert,
    state::written_file_is,
};

/// Bound of each path table below.
const RECENT_WRITES_CAP: usize = 4_096;

struct RecentWrite {
    pid: u32,
    comm: String,
    timestamp_ns: u64,
}

/// `check_quarantined_exec`'s tags: the plain join, and the one a mail client's
/// mark gets (<https://github.com/synthaea-lab/agent/issues/17>).
const USER_EXECUTION_TECHNIQUE: &str = "T1204.002";
const MAIL_ATTACHMENT_TECHNIQUE: &str = "T1566.001/T1204.002";

/// The freedesktop.org "Common extended attributes" xattr holding a downloaded file's URL.
/// `wget` and `curl --xattr` set it; which browsers do is not verified (no Linux capture).
/// The Linux download-provenance mark (<https://github.com/synthaea-lab/agent/issues/17>).
pub(crate) const XDG_ORIGIN_URL_XATTR: &str = "user.xdg.origin.url";

/// A download-provenance mark, as [`crate::RuleState::on_file_quarantine`] saw it.
struct RecentQuarantine {
    timestamp_ns: u64,
    agent: Option<String>,
    origin_url: Option<String>,
    /// Set by the first exec that alerted: one alert per mark, not per run.
    alerted: bool,
}

/// The [`FileQuarantineEvent`] a `setxattr` of [`XDG_ORIGIN_URL_XATTR`] stands for,
/// `None` for any other xattr. The sensor reports the attribute's name, not its value
/// (see [`FileSetxattrEvent`]): `origin_url` and `referrer_url` stay `None` ("unrecorded"
/// in the finding) and `agent` is the writing process's `comm`, the browser.
pub(crate) fn quarantine_from_setxattr(event: &FileSetxattrEvent) -> Option<FileQuarantineEvent> {
    (event.name == XDG_ORIGIN_URL_XATTR).then(|| FileQuarantineEvent {
        meta: event.meta.clone(),
        path: event.path.clone(),
        agent: Some(event.meta.comm.clone()),
        origin_url: None,
        referrer_url: None,
    })
}

/// A file a BITS job downloads, as [`crate::RuleState::on_bits_job`] saw it.
struct RecentBitsDownload {
    /// The job's latest file-added or completion time: the exec window runs
    /// from when the file is actually there.
    timestamp_ns: u64,
    /// The job that armed this path.
    job_id: String,
    /// That job completed: the file is on disk, and no cancellation of
    /// another job (or a late one of this job) removes it.
    on_disk: bool,
    client_pid: u32,
    client_comm: String,
    job_title: String,
    url: String,
    /// Set by the first exec that alerted: one alert per download, not per run.
    alerted: bool,
}

/// A mark-of-the-web removal (`FileDelete` of a `:Zone.Identifier` stream), as
/// [`crate::RuleState::on_file_delete`] saw it.
struct MotwRemoval {
    timestamp_ns: u64,
    pid: u32,
    comm: String,
    /// Set by the first exec that alerted: one alert per removal, not per run.
    alerted: bool,
}

/// The path tables of the download-to-execution joins. Each is LRU-bounded and keyed on the
/// path an exec will report.
pub(crate) struct DownloadState {
    /// path → info about the last write by a known downloader (T1105). LRU-bounded:
    /// downloader writes are rare, but a hostile loop must not grow agent memory.
    recent_writes: BoundedMap<String, RecentWrite>,
    /// case-folded path → its latest download-provenance mark (T1204.002,
    /// #365). LRU-bounded like `recent_writes`: a burst of downloads, or a
    /// hostile loop writing marks, must not grow agent memory.
    recent_quarantines: BoundedMap<String, RecentQuarantine>,
    /// case-folded local path → the BITS job downloading it (T1197, #284).
    /// LRU-bounded like `recent_quarantines`.
    recent_bits_downloads: BoundedMap<String, RecentBitsDownload>,
    /// case-folded host path → its latest mark-of-the-web removal (T1553.005,
    /// #442). LRU-bounded: `Unblock-File` over a whole module tree removes
    /// hundreds of marks at once.
    recent_motw_removals: BoundedMap<String, MotwRemoval>,
}

impl DownloadState {
    pub(crate) fn new() -> Self {
        Self {
            recent_writes: BoundedMap::new(RECENT_WRITES_CAP),
            recent_quarantines: BoundedMap::new(RECENT_WRITES_CAP),
            recent_bits_downloads: BoundedMap::new(RECENT_WRITES_CAP),
            recent_motw_removals: BoundedMap::new(RECENT_WRITES_CAP),
        }
    }

    /// The exec joins that alert at once: T1105, T1197 and T1553.005, in that order.
    /// T1204.002 waits for the signature, see [`Self::check_quarantined_exec`].
    pub(crate) fn on_exec(&mut self, event: &ExecEvent) -> Vec<Alert> {
        let mut alerts = Vec::new();
        alerts.extend(self.check_download_then_exec(event));
        alerts.extend(self.check_bits_download_exec(event));
        alerts.extend(self.check_exec_after_motw_removal(event));
        alerts
    }

    /// T1105 — execution of a path recently written by `curl`/`wget`, within the
    /// correlation window. Compares `comm` (the process name, as derived by the kernel)
    /// to the basename of the downloaded path — not `argv[0]` nor a substring of the
    /// command line.
    ///
    /// Two bugs found in real conditions on 2026-08-13 while looking for the right
    /// criterion:
    /// - a naive `cmdline.contains(path)` also matched `chmod +x /tmp/payload` or
    ///   `rm /tmp/payload` (the path appears as an argument, without `chmod`/`rm` being
    ///   the executed payload) — three alerts for a single scenario.
    /// - comparing `argv[0]` to the full path missed the (yet most likely) case of a
    ///   payload with a shebang (`#!/bin/sh`): the kernel then executes the
    ///   interpreter, with `argv = ["/bin/sh", "/tmp/edr-payload"]` — `argv[0]` is
    ///   `/bin/sh`, not the downloaded path, hence a false negative on the actual
    ///   execution.
    ///
    /// `comm`, on the other hand, is reliable in both cases: the kernel derives it from
    /// the name of the executed file (`edr-payload`), even when the actual interpreter
    /// differs — confirmed in real conditions (`comm: "edr-payload"` while `cmdline`
    /// starts with `/bin/sh`). Known limitation: the Linux kernel truncates `comm` to
    /// 15 bytes, so a file name longer than that will not match exactly (a sensor
    /// property, reported by conformance).
    fn check_download_then_exec(&self, event: &ExecEvent) -> Option<Alert> {
        let comm = event.meta.comm.as_str();
        let (path, write) =
            self.recent_writes
                .iter()
                .find(|(path, write): &(&String, &RecentWrite)| {
                    written_file_is(path, comm)
                        && event.meta.timestamp_ns.saturating_sub(write.timestamp_ns)
                            <= DOWNLOAD_EXEC_WINDOW_NS
                })?;
        Some(Alert {
            technique: "T1105",
            severity: Severity::High,
            message: format!(
                "pid={} comm={} executes {path}, written {} earlier by pid={} comm={}",
                event.meta.pid,
                comm,
                format_delta(event.meta.timestamp_ns.saturating_sub(write.timestamp_ns)),
                write.pid,
                write.comm,
            ),
        })
    }

    /// T1204.002 — User Execution: Malicious File. A file carrying a
    /// download-provenance mark (`FileQuarantine`: macOS quarantine xattr,
    /// Windows `Zone.Identifier`) is executed within
    /// [`QUARANTINE_EXEC_WINDOW_NS`] of being marked. Platform-neutral: the
    /// join is on the executed image path, which both ES and ETW report as the
    /// full path the mark was written for.
    ///
    /// One alert per mark (`alerted`): re-running the same download is not a
    /// new finding, a re-download writes a fresh mark and is. Paths are
    /// case-folded — NTFS and default APFS are both case-insensitive.
    ///
    /// Known gap: a downloaded *script* run through an interpreter
    /// (`powershell -File x.ps1`, `sh x.sh`) has the interpreter as its image
    /// path and does not join; T1105's comm-based match has the same shape of
    /// limit on Linux.
    ///
    /// Gated on the image's signature (#441): every installer a user downloads
    /// and runs matches the join, and almost all of them are signed. The
    /// signature is only known after enrichment, off the capture thread, so this
    /// returns a [`SignatureGatedAlert`] (see [`crate::RuleState::on_exec_signature_gated`]).
    pub(crate) fn check_quarantined_exec(
        &mut self,
        event: &ExecEvent,
    ) -> Option<SignatureGatedAlert> {
        let now = event.meta.timestamp_ns;
        let mark = self
            .recent_quarantines
            .get_mut(&event.image_path.to_lowercase())?;
        let age = now.saturating_sub(mark.timestamp_ns);
        if mark.alerted || age > QUARANTINE_EXEC_WINDOW_NS {
            return None;
        }
        mark.alerted = true;
        // A mail client's mark is the one thing that says how the file arrived:
        // the finding names the attachment vector as well, and still only says
        // "marked by", since a person who saved an attachment on purpose and
        // ran it looks the same.
        let by_mail_client = mark.agent.as_deref().is_some_and(|agent| {
            MAIL_CLIENT_QUARANTINE_AGENTS
                .iter()
                .any(|client| agent.eq_ignore_ascii_case(client))
        });
        Some(SignatureGatedAlert::new(Alert {
            technique: if by_mail_client {
                MAIL_ATTACHMENT_TECHNIQUE
            } else {
                USER_EXECUTION_TECHNIQUE
            },
            severity: Severity::High,
            message: format!(
                "pid={} comm={} executes {}, downloaded {} earlier (origin: {}, marked by {})",
                event.meta.pid,
                event.meta.comm,
                event.image_path,
                format_delta(age),
                mark.origin_url.as_deref().unwrap_or("unrecorded"),
                mark.agent.as_deref().unwrap_or("unknown"),
            ),
        }))
    }

    /// T1197 — BITS Jobs. A file a BITS job downloaded is executed within
    /// [`BITS_EXEC_WINDOW_NS`] of the job adding it or completing (#284). BITS
    /// does the download from its own service, so neither the T1105 joins
    /// (keyed on the downloading comm) nor the correlator's connect+write
    /// rule (keyed on one pid) can see it; the job record is what names the
    /// client.
    ///
    /// One alert per download (`alerted`), case-folded paths. Files fetched
    /// from Microsoft update hosts are filtered at the sensor and never reach
    /// this table; the job's owner is not a filter.
    ///
    /// Not covered: notify-command persistence (`bitsadmin /SetNotifyCmdLine`)
    /// is no job state the provider reports, so its set-up shows only as the
    /// `bitsadmin` command line. The file it runs, when BITS downloaded it,
    /// still joins here.
    fn check_bits_download_exec(&mut self, event: &ExecEvent) -> Option<Alert> {
        let now = event.meta.timestamp_ns;
        let download = self
            .recent_bits_downloads
            .get_mut(&event.image_path.to_lowercase())?;
        let age = now.saturating_sub(download.timestamp_ns);
        if download.alerted || age > BITS_EXEC_WINDOW_NS {
            return None;
        }
        download.alerted = true;
        Some(Alert {
            technique: "T1197",
            // Below T1105/T1204.002: non-Microsoft updaters (Google Omaha,
            // OneDrive) download through BITS and run what they fetched.
            severity: Severity::Medium,
            message: format!(
                "pid={} comm={} executes {}, downloaded {} earlier by BITS job \"{}\" of pid={} comm={} (url: {})",
                event.meta.pid,
                event.meta.comm,
                event.image_path,
                format_delta(age),
                download.job_title,
                download.client_pid,
                download.client_comm,
                download.url,
            ),
        })
    }

    /// Records the mark [`Self::check_quarantined_exec`] joins on: the path's latest, so a
    /// re-download re-arms it.
    pub(crate) fn on_file_quarantine(&mut self, event: &FileQuarantineEvent) {
        self.recent_quarantines.insert(
            event.path.to_lowercase(),
            RecentQuarantine {
                timestamp_ns: event.meta.timestamp_ns,
                agent: event.agent.clone(),
                origin_url: event.origin_url.clone(),
                alerted: false,
            },
        );
    }

    /// Linux producer of the same mark: a `setxattr` of [`XDG_ORIGIN_URL_XATTR`] is
    /// mapped to a [`FileQuarantineEvent`] and recorded like any other, so
    /// [`Self::check_quarantined_exec`] joins it unchanged. Any other xattr name is
    /// ignored. See [`quarantine_from_setxattr`] for what the mark carries.
    pub(crate) fn on_file_setxattr(&mut self, event: &FileSetxattrEvent) {
        if let Some(mark) = quarantine_from_setxattr(event) {
            self.on_file_quarantine(&mark);
        }
    }

    /// Arms, re-arms or drops the path of a BITS job's file for
    /// [`Self::check_bits_download_exec`], by the job's state.
    pub(crate) fn on_bits_job(&mut self, event: &BitsJobEvent) {
        let key = event.local_path.to_lowercase();
        let previous = self.recent_bits_downloads.peek(&key);
        let same_job = previous.is_some_and(|d| d.job_id == event.job_id);
        match event.state {
            BitsJobState::FileAdded => {
                // Another job's completed download is what sits at the path:
                // its window and attribution stand until a completion
                // replaces the file (#577 review).
                if previous.is_some_and(|d| d.on_disk && !same_job) {
                    return;
                }
                self.arm_bits_download(key, event, false, false);
            }
            BitsJobState::Completed => {
                // A late completion of the download that already alerted is not
                // a new download; another job's completion is.
                let alerted = same_job && previous.is_some_and(|d| d.alerted);
                self.arm_bits_download(key, event, true, alerted);
            }
            // A cancelled job deletes its own partial file: nothing of it left
            // to run. Only its own, and only a partial one: cancelling job B,
            // which targeted the path job A already downloaded, leaves A's
            // payload in place (#577 review).
            BitsJobState::Cancelled => {
                if same_job && previous.is_some_and(|d| !d.on_disk) {
                    self.recent_bits_downloads.remove(&key);
                }
            }
            // BITS retries a failed transfer on its own; keep the entry.
            BitsJobState::TransferError => {}
        }
    }

    fn arm_bits_download(
        &mut self,
        key: String,
        event: &BitsJobEvent,
        on_disk: bool,
        alerted: bool,
    ) {
        self.recent_bits_downloads.insert(
            key,
            RecentBitsDownload {
                timestamp_ns: event.meta.timestamp_ns,
                job_id: event.job_id.clone(),
                on_disk,
                client_pid: event.meta.pid,
                client_comm: event.meta.comm.clone(),
                job_title: event.job_title.clone(),
                url: event.url.clone(),
                alerted,
            },
        );
    }

    pub(crate) fn record_downloader_write(&mut self, event: &FileOpenEvent) {
        let comm = event.meta.comm.as_str();
        if !DOWNLOADER_COMMS.contains(&comm) || !has_write_intent(event.flags) {
            return;
        }
        self.recent_writes.insert(
            event.path.clone(),
            RecentWrite {
                pid: event.meta.pid,
                comm: comm.to_string(),
                timestamp_ns: event.meta.timestamp_ns,
            },
        );
    }

    /// Remembers a Windows `FileDelete` of a `:Zone.Identifier` stream: the
    /// mark-of-the-web removed from its host file (#442). No alert on its own —
    /// `Unblock-File` over a downloaded module tree removes hundreds of marks
    /// legitimately, and the event itself stays in the telemetry for hunting.
    ///
    /// A `User::Unknown` remover counts: the Windows sensor reports it when the
    /// process exited or is protected before its token was read, which is the
    /// shape of a one-shot `cmd /c "powershell Unblock-File x.exe & x.exe"`.
    /// What rules out a Unix file merely named `x:Zone.Identifier` is a Unix
    /// user or a POSIX path, the evidence that it is not a Windows stream.
    pub(crate) fn record_motw_removal(&mut self, event: &FileDeleteEvent) {
        self.record_motw_gone(&event.path, &event.meta);
    }

    /// The same fact from a `FileRename` of the stream: `Rename-Item -Stream` or a
    /// `SetInformation` rename on the stream handle takes the mark off its host
    /// without deleting anything. Only the minifilter reports it (#136, #853: the
    /// Kernel-File rename, event 27, is not consumed). A rename that leaves the
    /// stream on the same host (a case change) removed nothing; one that moves the
    /// mark to another file still strips it from this one.
    pub(crate) fn record_motw_stream_rename(&mut self, event: &FileRenameEvent) {
        let still_marked = motw_stream_host(&event.new_path)
            .zip(motw_stream_host(&event.old_path))
            .is_some_and(|(new_host, old_host)| new_host.eq_ignore_ascii_case(old_host));
        if !still_marked {
            self.record_motw_gone(&event.old_path, &event.meta);
        }
    }

    /// `stream_path` is a `:Zone.Identifier` stream that no longer carries its mark,
    /// by `meta`'s process.
    fn record_motw_gone(&mut self, stream_path: &str, meta: &schema::EventMeta) {
        if matches!(meta.user, User::Unix { .. }) {
            return;
        }
        let Some(host) = motw_stream_host(stream_path).filter(|host| !host.starts_with('/')) else {
            return;
        };
        self.recent_motw_removals.insert(
            host.to_lowercase(),
            MotwRemoval {
                timestamp_ns: meta.timestamp_ns,
                pid: meta.pid,
                comm: meta.comm.clone(),
                alerted: false,
            },
        );
    }

    /// T1553.005 — Subvert Trust Controls: Mark-of-the-Web Bypass. A file whose
    /// mark-of-the-web was removed is executed within
    /// [`QUARANTINE_EXEC_WINDOW_NS`] of the removal: the SmartScreen/Office
    /// protected-view prompt that mark would have raised was taken out of the
    /// way first (#442). The removal alone doesn't alert, see
    /// [`Self::record_motw_removal`].
    ///
    /// Independent of T1204.002 ([`Self::check_quarantined_exec`]): a file both
    /// marked and unmarked inside the window raises both, since they are two
    /// techniques; the origin URL, when the mark was seen, is quoted here too.
    ///
    /// Not covered: a download that never got a mark (curl, certutil, most
    /// droppers, see `DOWNLOADER_COMMS`) and an archive extractor that drops it
    /// — there is no removal to see; a mark rewritten in place to `ZoneId=0`,
    /// or its stream renamed through the Kernel-File path (event 27; the
    /// minifilter's rename is consumed, [`Self::record_motw_stream_rename`]). The full
    /// list is in `docs/detection/download-provenance.md`.
    fn check_exec_after_motw_removal(&mut self, event: &ExecEvent) -> Option<Alert> {
        let key = event.image_path.to_lowercase();
        let now = event.meta.timestamp_ns;
        let removal = self.recent_motw_removals.get_mut(&key)?;
        let age = now.saturating_sub(removal.timestamp_ns);
        if removal.alerted || age > QUARANTINE_EXEC_WINDOW_NS {
            return None;
        }
        removal.alerted = true;
        let (remover_pid, remover_comm) = (removal.pid, removal.comm.clone());
        let origin = self
            .recent_quarantines
            .get_mut(&key)
            .and_then(|mark| mark.origin_url.clone());
        Some(Alert {
            technique: "T1553.005",
            // At least T1204.002's: the same execution, plus a deliberate step
            // to take the warning out of the way first.
            severity: Severity::High,
            message: format!(
                "pid={} comm={} executes {}, {} after its mark-of-the-web was removed by pid={} comm={} (origin: {})",
                event.meta.pid,
                event.meta.comm,
                event.image_path,
                format_delta(age),
                remover_pid,
                remover_comm,
                origin.as_deref().unwrap_or("unrecorded"),
            ),
        })
    }
}

/// The host file of a `:Zone.Identifier` stream path, `$DATA` type suffix or
/// not (`C:\d\a.exe:Zone.Identifier:$DATA` → `C:\d\a.exe`). Same rule as
/// the Windows sensor's `stream_host_path`, which this crate can't depend on.
fn motw_stream_host(path: &str) -> Option<&str> {
    let path = strip_suffix_ignore_ascii_case(path, ":$DATA").unwrap_or(path);
    let host = strip_suffix_ignore_ascii_case(path, ":Zone.Identifier")?;
    (!host.is_empty() && !host.ends_with(['\\', '/', ':'])).then_some(host)
}

fn strip_suffix_ignore_ascii_case<'a>(s: &'a str, suffix: &str) -> Option<&'a str> {
    let split = s.len().checked_sub(suffix.len())?;
    let tail = s.get(split..)?;
    tail.eq_ignore_ascii_case(suffix).then(|| &s[..split])
}

fn format_delta(delta_ns: u64) -> String {
    format!("{:.1}s", delta_ns as f64 / 1_000_000_000.0)
}
