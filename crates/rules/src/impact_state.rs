//! The file-impact rules of [`crate::RuleState`]: the T1486 shapes (mass rename with an
//! appended suffix, per pid and per shell loop, write-new-then-unlink, write volume alongside a
//! rename burst), the Linux timestomp dedup (T1070.006), and the damage manifest of renames and
//! deletions a ransomware detection carries.

use std::collections::VecDeque;

use schema::{
    Event, FileDeleteEvent, FileOpenEvent, FileRenameEvent, FileWriteEvent, O_CREAT, User,
    detection::Severity,
};
use store::BoundedMap;

use crate::{
    Alert,
    exclusions::{
        APK_STAGING_FILE_PREFIX, BURST_WRITE_BYTES_THRESHOLD, COMPRESSION_DRIVER_COMMS,
        COMPRESSION_SUFFIXES, COMPRESSOR_COMMS, CREATE_UNLINK_HISTORY_PER_PID,
        CREATE_UNLINK_PAIR_WINDOW_NS, CREATE_UNLINK_PID_CAP, IN_PLACE_EDIT_COMMS,
        MAILDIR_FLAG_LETTERS, PACKAGE_MANAGER_COMMS, PACKAGE_MANAGER_TEMP_RENAME_SUFFIXES,
        RANSOMWARE_EXCLUDED_PATH_PREFIXES, RANSOMWARE_LOOP_CHILD_MAX, RANSOMWARE_RENAME_THRESHOLD,
        RANSOMWARE_RENAME_WINDOW_NS, SELINUX_POLICY_TOOL_COMMS, TOUCHED_FILES_PER_PID,
        TOUCHED_FILES_PID_CAP,
    },
    has_write_intent,
    sliding::{SlidingCounter, SlidingSum},
    state::{COUNTER_CAP, PidFact, written_file_is},
};

/// One process incarnation's timestomp alert state (#1036): when it last alerted and how many
/// requests the window has swallowed since, so the next alert can say how many there were.
#[derive(Default)]
struct SetTimeWindow {
    last_alert_ns: Option<u64>,
    folded: u32,
}

impl SetTimeWindow {
    /// `Some(requests folded since the last alert)` when this request alerts, `None` when it is
    /// folded into the alert of the window it falls in.
    fn admit(&mut self, ts: u64, window_ns: u64) -> Option<u32> {
        if self
            .last_alert_ns
            .is_some_and(|t| ts.saturating_sub(t) <= window_ns)
        {
            self.folded = self.folded.saturating_add(1);
            return None;
        }
        self.last_alert_ns = Some(ts);
        Some(std::mem::take(&mut self.folded))
    }
}

/// One Linux timestomp alert per process incarnation per this window (#1036).
pub(crate) const SET_TIME_ALERT_WINDOW_NS: u64 = 60_000_000_000;

/// The sliding history of the file-impact rules. The rules that trust a process by its binary
/// read the exec-time image table `RuleState` keeps, passed in as `images`.
pub(crate) struct ImpactState {
    /// Linux timestomp alerts already raised, per process incarnation `(pid, generation)`
    /// (#1036): one alert per window per process, see [`Self::dedup_file_set_time`].
    set_time_alerted: BoundedMap<(u32, u64), SetTimeWindow>,
    /// pid → sliding counter for RANSOMWARE-RENAME (T1486, issue #262): renames by
    /// this pid where `new_path` is `old_path` plus an appended suffix. LRU-bounded:
    /// a hostile process renaming under many different pids (unusual, but not
    /// impossible) must not grow this without limit either.
    ransomware_rename: BoundedMap<u32, SlidingCounter>,
    /// ppid → the same counter, for the shell-loop shape (`for f in *; do mv "$f"
    /// "$f.locked"; done`, `find … -exec mv {} {}.x \;`): each rename runs in its own
    /// short-lived `mv` pid, so the per-pid counter never climbs, but every child
    /// shares the loop's shell as `ppid`. Real Linux ransomware ships this way, so the
    /// per-pid counter alone would miss it (issue #262 review, old-dov). LRU-bounded.
    /// `ppid <= 1` (unknown/init) is never keyed here — see `check_mass_rename_pattern`.
    ransomware_rename_by_ppid: BoundedMap<u32, SlidingCounter>,
    /// pid → (timestamp, path) of the recent write-intent creations (`O_CREAT`) seen
    /// for it, newest last: the "new file" half of the write-new-then-unlink T1486
    /// shape (#512 part B). `FileWriteEvent` carries only an fd, so the correlation is
    /// between this creation and a later `FileDeleteEvent`, both of which carry paths.
    /// Bounded by [`CREATE_UNLINK_PID_CAP`] pids x [`CREATE_UNLINK_HISTORY_PER_PID`].
    recent_creates: BoundedMap<u32, VecDeque<(u64, String)>>,
    /// pid → (timestamp, path) of unlinks that found no creation to pair with yet.
    /// The kernel always creates `X.suffix` before unlinking `X`, but userspace drains
    /// the open and delete ring buffers independently, so the delete can be processed
    /// first (the same ordering hazard as `RuleState`'s `pending_proc_fd_exec`, #503); the
    /// creation then pairs with it on arrival. Same bounds as `recent_creates`.
    pending_unlinks: BoundedMap<u32, VecDeque<(u64, String)>>,
    /// pid → the newest renames and deletions seen for it (oldest first): the damage
    /// manifest of a ransomware detection (issue #82), read through [`Self::touched_files`].
    /// Bounded by [`TOUCHED_FILES_PID_CAP`] pids x [`TOUCHED_FILES_PER_PID`] events.
    touched_files: BoundedMap<u32, VecDeque<Event>>,
    /// pid → sliding counter of write-new-then-unlink pairs (T1486, #512 part B).
    ransomware_unlink: BoundedMap<u32, SlidingCounter>,
    /// pid → sliding sum of `FileWriteEvent::bytes_requested` (issue #82): the
    /// write-volume half of a second, independent T1486 corroboration signal —
    /// heavy write volume alongside a rename burst, regardless of whether the
    /// rename shape itself matched `check_mass_rename_pattern`'s prefix-preserving
    /// pattern. LRU-bounded.
    write_volume: BoundedMap<u32, SlidingSum>,
    /// pid → sliding counter of renames, any shape — the rename half of the
    /// write-volume corroboration signal above. Deliberately separate from
    /// `ransomware_rename`: that counter only records prefix-preserving renames
    /// (`check_mass_rename_pattern`'s shape), this one counts every rename, so a
    /// pid that renames heavily without preserving the original name still
    /// contributes here.
    rename_count: BoundedMap<u32, SlidingCounter>,
}

impl ImpactState {
    pub(crate) fn new() -> Self {
        Self {
            set_time_alerted: BoundedMap::new(COUNTER_CAP),
            ransomware_rename: BoundedMap::new(COUNTER_CAP),
            ransomware_rename_by_ppid: BoundedMap::new(COUNTER_CAP),
            recent_creates: BoundedMap::new(CREATE_UNLINK_PID_CAP),
            pending_unlinks: BoundedMap::new(CREATE_UNLINK_PID_CAP),
            touched_files: BoundedMap::new(TOUCHED_FILES_PID_CAP),
            ransomware_unlink: BoundedMap::new(COUNTER_CAP),
            write_volume: BoundedMap::new(COUNTER_CAP),
            rename_count: BoundedMap::new(COUNTER_CAP),
        }
    }

    /// The rename half of [`crate::RuleState::on_file_rename`]: the damage manifest, then the
    /// mass-rename and write-volume T1486 checks, in that order.
    pub(crate) fn on_file_rename(
        &mut self,
        event: &FileRenameEvent,
        images: &BoundedMap<u32, PidFact>,
    ) -> Vec<Alert> {
        self.record_touched(event.meta.pid, Event::FileRename(event.clone()));
        let mut alerts: Vec<Alert> = self
            .check_mass_rename_pattern(event, images)
            .into_iter()
            .collect();
        alerts.extend(self.check_burst_write_volume(event));
        alerts
    }

    /// The unlink half of [`crate::RuleState::on_file_delete`]: the damage manifest, then
    /// [`Self::check_write_new_then_unlink`].
    pub(crate) fn on_file_delete(
        &mut self,
        event: &FileDeleteEvent,
        images: &BoundedMap<u32, PidFact>,
    ) -> Option<Alert> {
        self.record_touched(event.meta.pid, Event::FileDelete(event.clone()));
        self.check_write_new_then_unlink(event, images)
    }

    /// Tracks write volume per pid (issue #82), consumed by `check_burst_write_volume` on the
    /// next `FileRenameEvent`.
    pub(crate) fn record_write(&mut self, event: &FileWriteEvent) {
        self.write_volume
            .get_or_insert_with(event.meta.pid, SlidingSum::default)
            .add(
                event.meta.timestamp_ns,
                event.bytes_requested,
                RANSOMWARE_RENAME_WINDOW_NS,
            );
    }

    /// T1486 — Data Encrypted for Impact. Ransomware's near-universal tell: a burst
    /// of renames, each keeping the original filename intact and appending a new
    /// suffix (`invoice.pdf` → `invoice.pdf.locked`), from the same pid, in a tight
    /// window. Extension-agnostic by design — matching on "`old_path` is a strict
    /// prefix of `new_path`" catches every real family's naming scheme (`.locked`,
    /// `.encrypted`, `.WNCRY`, a random hex suffix, ...) without a list to keep
    /// current against new strains, and without false-positiving on renames that
    /// *don't* preserve the original name (a normal `mv a b` has no such relation).
    ///
    /// Deliberately keyed on rename shape alone, not `FileWriteEvent` volume: many
    /// legitimate bulk operations (package installs, `tar` extraction, a compiler's
    /// intermediate files) write many files quickly, but essentially none rename
    /// hundreds of pre-existing files to append a shared new suffix in seconds —
    /// see `RANSOMWARE_RENAME_THRESHOLD`'s doc for the calibration reasoning.
    ///
    /// Counted twice, so both real shapes reach the threshold (issue #262 review):
    /// per-pid for a single encryptor binary, and per-ppid for the shell-loop shape
    /// (`for f in *; do mv "$f" "$f.locked"; done`) where each rename is a separate
    /// short-lived `mv` pid but every one shares the loop's shell as `ppid`. The
    /// per-pid branch wins when it fires, so a single process yields one alert, not
    /// two (its renames also land in the per-ppid counter, but that branch is only
    /// consulted when the per-pid one did not fire this event).
    ///
    /// Known benign producers of this exact shape (#459 part 1 closes the first
    /// two; the third stays open, see below):
    /// - Log rotation (`app.log` → `app.log.1`): handled by [`is_rotation_suffix`]
    ///   (a suffix with no letter never counts) — the one case a shape signal settles.
    /// - In-place edit with a backup: `sed -i.bak` `rename(2)`s the
    ///   original to `f.bak`/`f.orig` from one pid; 20+ files in one command
    ///   (`sed -i.bak … *.conf`) used to trip this rule. [`Self::is_in_place_edit_backup`]
    ///   now excludes it, gated on `comm` + the pid's exec-time `image_path`
    ///   (CLAUDE.md — name-keyed exclusions must be gated on evidence, cf.
    ///   [`policy::name_exclusion_applies`]; excluding on `comm` alone would be
    ///   spoofable, an encryptor can set `comm=sed` for free). Fails closed when
    ///   no path is known, see `Self::is_in_place_edit_backup`.
    /// - Maildir flag changes (`…:2,S` → `…:2,ST`): one IMAP pid, prefix-preserving,
    ///   lettered suffix; "mark all read" on a large folder can exceed the
    ///   threshold. [`is_maildir_flag_change`] now excludes it — structurally
    ///   (the flag-letter alphabet), deliberately *not* also comm-gated; see
    ///   that function's doc for why.
    ///
    /// Cross-directory moves (`~/docs/a.docx` → `~/.stash/a.docx.locked`, #512):
    /// when the directories differ the full-path prefix test can never hold, so the
    /// same appended-suffix relation is read off the file *names* instead
    /// ([`appended_suffix`]). Same counters, same exclusions; the one new benign
    /// producer that shape brings in is the Maildir delivery move
    /// (`new/msg` → `cur/msg:2,S`), excluded by [`is_maildir_delivery`].
    ///
    /// Shapes this rule still cannot see at all (write-new-then-unlink) need a
    /// separate open/delete correlation — still a follow-up, tracked in #512.
    fn check_mass_rename_pattern(
        &mut self,
        event: &FileRenameEvent,
        images: &BoundedMap<u32, PidFact>,
    ) -> Option<Alert> {
        let suffix = appended_suffix(&event.old_path, &event.new_path)?;
        if suffix.is_empty()
            || is_rotation_suffix(suffix)
            || Self::is_in_place_edit_backup(event, images)
            || is_maildir_flag_change(&event.old_path, suffix)
            || is_maildir_delivery(&event.old_path, &event.new_path, suffix)
        {
            return None;
        }
        let ts = event.meta.timestamp_ns;

        // Per-pid: a single encryptor process renaming its way through a tree.
        let pid_entry = self
            .ransomware_rename
            .get_or_insert_with(event.meta.pid, SlidingCounter::default);
        let pid_count = pid_entry.record(ts, RANSOMWARE_RENAME_WINDOW_NS);
        if pid_count >= RANSOMWARE_RENAME_THRESHOLD
            && pid_entry.try_alert(ts, RANSOMWARE_RENAME_WINDOW_NS)
        {
            return Some(Alert {
                technique: "T1486",
                severity: Severity::Critical,
                message: format!(
                    "pid={} comm={}: {pid_count} files renamed with an appended suffix in {}s \
                     (e.g. {} → {}) — suspected ransomware encryption pass",
                    event.meta.pid,
                    event.meta.comm,
                    RANSOMWARE_RENAME_WINDOW_NS / 1_000_000_000,
                    event.old_path,
                    event.new_path,
                ),
            });
        }

        // Per-ppid: a shell loop spawning one short-lived `mv` per file — the per-pid
        // counter above never climbs, but the parent shell ties the burst together.
        // Only pids that are themselves light renamers feed this counter, so a single
        // busy process (already handled above) does not also drive the shared per-ppid
        // counter to a second alert — see `RANSOMWARE_LOOP_CHILD_MAX`.
        //
        // ppid 0 ("unknown" — a `PROC_LINEAGE` miss on the sensor, never real pid 0)
        // and ppid 1 (init — orphans and daemons reparent there) are shared buckets
        // that would lump unrelated processes into a false "shell-loop" alert; a real
        // loop's children have the loop's shell as parent, so skip both (#455 review).
        if pid_count > RANSOMWARE_LOOP_CHILD_MAX || event.meta.ppid <= 1 {
            return None;
        }
        let ppid_entry = self
            .ransomware_rename_by_ppid
            .get_or_insert_with(event.meta.ppid, SlidingCounter::default);
        let ppid_count = ppid_entry.record(ts, RANSOMWARE_RENAME_WINDOW_NS);
        if ppid_count >= RANSOMWARE_RENAME_THRESHOLD
            && ppid_entry.try_alert(ts, RANSOMWARE_RENAME_WINDOW_NS)
        {
            return Some(Alert {
                technique: "T1486",
                severity: Severity::Critical,
                message: format!(
                    "ppid={}: {ppid_count} files renamed with an appended suffix by short-lived \
                     children in {}s (e.g. {} → {}, comm={}) — suspected ransomware encryption \
                     pass (shell-loop pattern)",
                    event.meta.ppid,
                    RANSOMWARE_RENAME_WINDOW_NS / 1_000_000_000,
                    event.old_path,
                    event.new_path,
                    event.meta.comm,
                ),
            });
        }
        None
    }

    /// T1486, the shape `check_mass_rename_pattern` cannot see because none of it is a
    /// rename (#512 part B): the encryptor writes `file.docx.locked` as a **new** file and
    /// only then unlinks `file.docx` (safer than an in-place rewrite: the original
    /// survives until the copy is complete). Same appended-suffix relation
    /// ([`appended_suffix`], so a cross-directory pair counts too), same lettered,
    /// non-rotation, non-Maildir suffix filter, same threshold and window.
    ///
    /// The correlation is a write-intent `O_CREAT` open (`record_create`) and an unlink
    /// of the file whose name the new one extends, by one pid within
    /// [`CREATE_UNLINK_PAIR_WINDOW_NS`], in either arrival order (`pending_unlinks`).
    /// It cannot use `FileWriteEvent`: that event carries an fd and no path.
    ///
    /// The benign producer measured live (Debian 13) is compression: `gzip`, `xz`,
    /// `bzip2` and `zstd` each did 30 of these in 5 s over a `*.log` glob. They are
    /// excluded by [`COMPRESSOR_COMMS`] gated on the pid running the trusted binary of
    /// that name, failing closed ([`Self::runs_trusted_binary_named`]); a suffix
    /// allowlist (`.gz`) alone would be free for an encryptor to copy. `logrotate` with
    /// `compress` opens the `.gz` and unlinks the input itself (gzip only writes to an
    /// inherited fd), so it is excluded as a compression *driver*
    /// ([`Self::is_compression_driver`]): trusted binary named `logrotate` **and** a
    /// compression extension, both required (found live by Jihair on Alpine, #527). A third
    /// benign producer, `semodule -B`/`-DB` rebuilding the `SELinux` policy store, is excluded
    /// the same way as the compressors ([`Self::is_selinux_policy_tool`]): no suffix
    /// convention to also require (found live on Fedora, #1013). Nothing else measured
    /// (`zip -m`, `rsync --remove-source-files`, `git gc`, atomic writers, `apt`)
    /// exceeded 2. Restricted to Unix events: the Windows and macOS producers of this
    /// shape (Explorer, `ditto`, installers) were not measured.
    ///
    /// **Not covered**: a shell loop with one process per step (`openssl enc -out $f.enc`
    /// creates, a separate `rm $f` unlinks). Creation and unlink then belong to different
    /// pids, so no pair forms (confirmed live on Debian 13); tying them through the
    /// parent would also fold in ordinary `cp x x.bak; rm x` scripts, which was not
    /// measured. The rename shape of that loop is covered by `check_mass_rename_pattern`.
    ///
    /// Like every pid-keyed table here it inherits #519: a recycled pid keeps a stale
    /// history until it ages out of the window.
    fn check_write_new_then_unlink(
        &mut self,
        event: &FileDeleteEvent,
        images: &BoundedMap<u32, PidFact>,
    ) -> Option<Alert> {
        if !matches!(event.meta.user, User::Unix { .. }) {
            return None;
        }
        let pid = event.meta.pid;
        let ts = event.meta.timestamp_ns;
        let created = self.recent_creates.get_mut(&pid).and_then(|creates| {
            let idx = creates.iter().rposition(|(created_ts, path)| {
                pairs_create_and_unlink(*created_ts, path, ts, &event.path)
            })?;
            creates.remove(idx).map(|(_, path)| path)
        });
        let Some(created) = created else {
            // No creation seen yet: it may still arrive after this unlink.
            let pending = self.pending_unlinks.get_or_insert_with(pid, VecDeque::new);
            if pending.len() >= CREATE_UNLINK_HISTORY_PER_PID {
                pending.pop_front();
            }
            pending.push_back((ts, event.path.clone()));
            return None;
        };
        self.count_create_unlink_pair(&event.meta, ts, &event.path, &created, images)
    }

    /// The creation half: remembers a write-intent `O_CREAT` open, or pairs it with an
    /// unlink that arrived first. Unix events only, see
    /// [`Self::check_write_new_then_unlink`].
    pub(crate) fn record_create(
        &mut self,
        event: &FileOpenEvent,
        images: &BoundedMap<u32, PidFact>,
    ) -> Option<Alert> {
        if event.flags & O_CREAT == 0
            || !has_write_intent(event.flags)
            || !matches!(event.meta.user, User::Unix { .. })
        {
            return None;
        }
        let pid = event.meta.pid;
        let created_ts = event.meta.timestamp_ns;
        let unlinked = self.pending_unlinks.get_mut(&pid).and_then(|pending| {
            let idx = pending.iter().position(|(unlink_ts, path)| {
                pairs_create_and_unlink(created_ts, &event.path, *unlink_ts, path)
            })?;
            pending.remove(idx)
        });
        if let Some((unlink_ts, deleted)) = unlinked {
            return self.count_create_unlink_pair(
                &event.meta,
                unlink_ts,
                &deleted,
                &event.path,
                images,
            );
        }
        let creates = self.recent_creates.get_or_insert_with(pid, VecDeque::new);
        if creates.len() >= CREATE_UNLINK_HISTORY_PER_PID {
            creates.pop_front();
        }
        creates.push_back((created_ts, event.path.clone()));
        None
    }

    /// Counts one matched write-new-then-unlink pair per pid, alerting at the
    /// mass-rename threshold. `ts` is the later (unlink) time.
    fn count_create_unlink_pair(
        &mut self,
        meta: &schema::EventMeta,
        ts: u64,
        deleted: &str,
        created: &str,
        images: &BoundedMap<u32, PidFact>,
    ) -> Option<Alert> {
        if Self::is_compressor(meta, images)
            || Self::is_compression_driver(meta, deleted, created, images)
            || Self::is_selinux_policy_tool(meta, images)
        {
            return None;
        }
        let pid_entry = self
            .ransomware_unlink
            .get_or_insert_with(meta.pid, SlidingCounter::default);
        let pid_count = pid_entry.record(ts, RANSOMWARE_RENAME_WINDOW_NS);
        if pid_count >= RANSOMWARE_RENAME_THRESHOLD
            && pid_entry.try_alert(ts, RANSOMWARE_RENAME_WINDOW_NS)
        {
            return Some(Alert {
                technique: "T1486",
                severity: Severity::Critical,
                message: format!(
                    "pid={} comm={}: {pid_count} files replaced by a new file with an appended \
                     suffix and then unlinked in {}s (e.g. {deleted} → {created}) — suspected \
                     ransomware encryption pass (write-new-then-unlink)",
                    meta.pid,
                    meta.comm,
                    RANSOMWARE_RENAME_WINDOW_NS / 1_000_000_000,
                ),
            });
        }
        None
    }

    /// True when `comm` is a compression driver ([`COMPRESSION_DRIVER_COMMS`], i.e.
    /// `logrotate`) that really runs the trusted binary of that name and the new file
    /// only appends a compression extension to the old name.
    fn is_compression_driver(
        meta: &schema::EventMeta,
        deleted: &str,
        created: &str,
        images: &BoundedMap<u32, PidFact>,
    ) -> bool {
        COMPRESSION_DRIVER_COMMS.contains(&meta.comm.as_str())
            && appended_suffix(deleted, created)
                .is_some_and(|suffix| COMPRESSION_SUFFIXES.contains(&suffix))
            && Self::runs_trusted_binary_named(meta, images)
    }

    /// True when `comm` is a compression tool ([`COMPRESSOR_COMMS`]) and the pid really
    /// runs the trusted binary of that name: see [`Self::runs_trusted_binary_named`].
    fn is_compressor(meta: &schema::EventMeta, images: &BoundedMap<u32, PidFact>) -> bool {
        COMPRESSOR_COMMS.contains(&meta.comm.as_str())
            && Self::runs_trusted_binary_named(meta, images)
    }

    /// True when `comm` is a `SELinux` policy-store tool ([`SELINUX_POLICY_TOOL_COMMS`]) and
    /// the pid really runs the trusted binary of that name (#1013): `semodule -B`'s
    /// create-then-replace of every module in the targeted policy base set matches this
    /// shape with no `comm`-independent suffix convention to additionally require, unlike
    /// [`Self::is_compression_driver`].
    fn is_selinux_policy_tool(meta: &schema::EventMeta, images: &BoundedMap<u32, PidFact>) -> bool {
        SELINUX_POLICY_TOOL_COMMS.contains(&meta.comm.as_str())
            && Self::runs_trusted_binary_named(meta, images)
    }

    /// True when this pid's exec-time `image_path` is known, sits at a trusted system
    /// path **and is a binary named `comm`**. Both halves matter: a trusted path alone
    /// is not enough, because a process running the system `python3` can rename its own
    /// `comm` to `gzip` with `prctl(PR_SET_NAME)` and would otherwise inherit the
    /// exclusion; what an encryptor cannot fake is that the trusted binary it runs is
    /// *called* `gzip`. Unknown is **not** trusted (fails closed): delete events carry no
    /// rename-time `executable_path` to fall back on, and "no exec seen" (a forked child
    /// that only set `comm`) is not evidence of `/usr/bin/gzip`.
    fn runs_trusted_binary_named(
        meta: &schema::EventMeta,
        images: &BoundedMap<u32, PidFact>,
    ) -> bool {
        PidFact::current(images, meta.pid, meta.process_generation).is_some_and(|p| {
            !p.is_empty()
                && policy::name_exclusion_applies(Some(p))
                && written_file_is(p, &meta.comm)
        })
    }

    /// The Linux per-process dedup of [`crate::RuleState::on_file_set_time`] over the `alerts`
    /// a Unix event raised: one alert per process incarnation per
    /// [`SET_TIME_ALERT_WINDOW_NS`], package managers skipped.
    pub(crate) fn dedup_file_set_time(
        &mut self,
        event: &schema::FileSetTimeEvent,
        mut alerts: Vec<Alert>,
        images: &BoundedMap<u32, PidFact>,
    ) -> Vec<Alert> {
        // A package manager unpacking an archive stamps every file with its stored mtime. The
        // skip is keyed on the exec-time image, not on `comm` alone: `comm` is the basename of
        // whatever was exec'd and any process can rewrite it (`prctl(PR_SET_NAME)`), so a copy of
        // `touch` named `/tmp/rpm`, or `python3` renamed to `rpm`, would otherwise stomp silently
        // (#1045 review). Fails closed: a package manager whose exec the sensor missed (started
        // before the agent) alerts at Low until it exits.
        if crate::stateless::is_package_manager_comm(&event.meta.comm)
            && Self::runs_trusted_binary_named(&event.meta, images)
        {
            return Vec::new();
        }
        let key = (event.meta.pid, event.meta.process_generation.unwrap_or(0));
        let window = self
            .set_time_alerted
            .get_or_insert_with(key, SetTimeWindow::default);
        match window.admit(event.meta.timestamp_ns, SET_TIME_ALERT_WINDOW_NS) {
            None => alerts.clear(),
            Some(folded) if folded > 0 => {
                // The one alert per window hides how many requests there were: say so.
                for alert in &mut alerts {
                    alert.message.push_str(&format!(
                        " ({folded} more request(s) from this process since its last alert were not reported)"
                    ));
                }
            }
            Some(_) => {}
        }
        alerts
    }

    /// Remembers a rename or deletion for `pid`, dropping the oldest past the per-pid bound.
    fn record_touched(&mut self, pid: u32, event: Event) {
        let history = self.touched_files.get_or_insert_with(pid, VecDeque::new);
        if history.len() == TOUCHED_FILES_PER_PID {
            history.pop_front();
        }
        history.push_back(event);
    }

    /// The renames and deletions of the process incarnation `(pid, generation)` still
    /// remembered, oldest first: the damage manifest a ransomware detection carries
    /// (issue #82). Two known, different generations never mix (a recycled pid's earlier
    /// life is not this process's damage); a missing stamp keeps the pid-only behavior.
    #[must_use]
    pub(crate) fn touched_files(&self, pid: u32, generation: Option<u64>) -> Vec<Event> {
        self.touched_files
            .peek(&pid)
            .map(|history| {
                history
                    .iter()
                    .filter(|e| match (e.meta().process_generation, generation) {
                        (Some(a), Some(b)) => a == b,
                        _ => true,
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Second, independent T1486 signal (issue #82): heavy write volume alongside
    /// a rename burst, regardless of whether the rename shape matched
    /// `check_mass_rename_pattern`'s prefix-preserving pattern — catches a
    /// renamed-over-the-original-name encryptor shape that check's
    /// suffix-appending model doesn't.
    ///
    /// Only ever runs on `FileRenameEvent` (dispatched from `on_file_rename`,
    /// never on an unlink) — despite an earlier version of this doc's claim to
    /// catch a "writes-new-then-unlinks" shape, no unlink telemetry feeds this
    /// at all (review finding, #496). `bytes_written` comes from
    /// `FileWriteEvent::bytes_requested`, which `sensor-linux-ebpf`'s
    /// `sys_enter_write` hook records for every `write(2)` regardless of what
    /// the fd refers to — a regular file, a socket, a pipe — so a chatty
    /// network/IPC-heavy process's write volume counts the same as real disk
    /// writes toward this total. Both caveats are honest gaps, not yet closed.
    ///
    /// Deliberately no name-keyed exclusion here: `FileRenameEvent`/`FileWriteEvent`
    /// carry no executable path (same gap `check_mass_rename_pattern`'s doc
    /// describes, tracked in #459), so a `comm`-only exclusion would be spoofable.
    /// `RANSOMWARE_EXCLUDED_PATH_PREFIXES` is path-based, not name-based, and stays.
    /// [`is_package_manager_temp_rename`] requires both the filename shape and
    /// `comm` to match a known package manager (#496, hardened per #500
    /// review): the shape alone — staging heavy writes under `foo.dpkg-new`
    /// then renaming it onto `foo` — previously cleared both gates below and
    /// false-positived T1486, but the shape by itself is just a naming
    /// convention the renaming process controls; requiring `comm` too raises
    /// the bar to also impersonating the specific package manager it belongs
    /// to, not just picking a suffix.
    fn check_burst_write_volume(&mut self, event: &FileRenameEvent) -> Option<Alert> {
        if RANSOMWARE_EXCLUDED_PATH_PREFIXES
            .iter()
            .any(|prefix| event.new_path.starts_with(prefix))
            || is_package_manager_temp_rename(&event.old_path, &event.new_path, &event.meta.comm)
        {
            return None;
        }
        let ts = event.meta.timestamp_ns;
        // Independent field from `rename_count` below — read first so the
        // `SlidingCounter` borrow can stay held through the `try_alert` call.
        let bytes_written = self
            .write_volume
            .get_or_insert_with(event.meta.pid, SlidingSum::default)
            .total(ts, RANSOMWARE_RENAME_WINDOW_NS);
        let entry = self
            .rename_count
            .get_or_insert_with(event.meta.pid, SlidingCounter::default);
        let rename_count = entry.record(ts, RANSOMWARE_RENAME_WINDOW_NS);
        if rename_count >= RANSOMWARE_RENAME_THRESHOLD
            && bytes_written >= BURST_WRITE_BYTES_THRESHOLD
            && entry.try_alert(ts, RANSOMWARE_RENAME_WINDOW_NS)
        {
            return Some(Alert {
                technique: "T1486",
                severity: Severity::Critical,
                message: format!(
                    "pid={} comm={} wrote {}MB and renamed {rename_count}x in {}s — \
                     suspected ransomware kill chain",
                    event.meta.pid,
                    event.meta.comm,
                    bytes_written / (1024 * 1024),
                    RANSOMWARE_RENAME_WINDOW_NS / 1_000_000_000,
                ),
            });
        }
        None
    }

    /// True for `check_mass_rename_pattern`'s in-place-edit-with-backup false
    /// positive (#459 part 1): `comm` is a known in-place-edit tool
    /// ([`IN_PLACE_EDIT_COMMS`]) and the binary behind the pid is at a trusted
    /// path ([`policy::name_exclusion_applies`]).
    ///
    /// The path is the exec-time `image_path` from `RuleState::pid_image_path`, not
    /// `FileRenameEvent::executable_path`: the latter is a rename-time `/proc` read
    /// that a short-lived process loses (#513 review), and "unknown" there is
    /// something the process controls by exiting. Unlike the other name-keyed
    /// exclusions (whose image paths the kernel hands us at exec time), an
    /// unresolvable path here **fails closed**: a pid with no exec seen (it never
    /// exec'd since the agent started — e.g. a forked child that only set `comm`)
    /// is not evidence of `/usr/bin/sed`. `executable_path` is only a fallback for
    /// that gap, never a way to override a known exec-time path.
    fn is_in_place_edit_backup(event: &FileRenameEvent, images: &BoundedMap<u32, PidFact>) -> bool {
        if !IN_PLACE_EDIT_COMMS.contains(&event.meta.comm.as_str()) {
            return false;
        }
        let path = PidFact::current(images, event.meta.pid, event.meta.process_generation)
            .or(event.executable_path.as_deref());
        // A trusted path is not enough on its own: the system `python3` can set its own
        // `comm` to `sed` (`prctl(PR_SET_NAME)`) and would inherit the exclusion. What
        // an encryptor cannot fake is that the trusted binary it runs is *called* `comm`.
        matches!(
            path,
            Some(p) if !p.is_empty()
                && policy::name_exclusion_applies(Some(p))
                && written_file_is(p, &event.meta.comm)
        )
    }
}

/// Suffixes logrotate and similar rotators append (`.1`, `-20260924`, `.1.2`, `~`
/// backups): no ASCII letter at all. Ransomware markers carry letters (`.locked`,
/// `.WNCRY`, `.id-<hex>.[mail]`); an all-digit random suffix is the one blind spot,
/// accepted over alerting on every rotation run.
fn is_rotation_suffix(suffix: &str) -> bool {
    !suffix.bytes().any(|b| b.is_ascii_alphabetic())
}

/// True when `old_path` is `new_path` with one of
/// [`PACKAGE_MANAGER_TEMP_RENAME_SUFFIXES`] appended *and* `comm` is one of
/// [`PACKAGE_MANAGER_COMMS`] — the package-manager "stage under a temp name,
/// then rename over the real one" shape `check_burst_write_volume` excludes
/// (#496), corroborated by which process is doing it (#500 review) so the
/// filename convention alone isn't a free pass. The path relationship is the
/// reverse of [`is_rotation_suffix`]'s callers (`new_path` = `old_path` +
/// suffix): here the suffix is on the *old* name.
fn is_package_manager_temp_rename(old_path: &str, new_path: &str, comm: &str) -> bool {
    PACKAGE_MANAGER_COMMS.contains(&comm)
        && (old_path
            .strip_prefix(new_path)
            .is_some_and(|suffix| PACKAGE_MANAGER_TEMP_RENAME_SUFFIXES.contains(&suffix))
            || is_apk_staging_rename(old_path, new_path))
}

/// True for apk-tools' real staging shape (#500 review, Jihair): `old_path`
/// sits in the same directory as `new_path` (not derived from it by suffix —
/// see [`APK_STAGING_FILE_PREFIX`]'s doc) and its basename is that prefix
/// followed by a hex digest, e.g. `usr/bin/.apk.e9a41015…` ->
/// `usr/bin/c89`. Splits on the last `/` rather than comparing absolute
/// prefixes because apk's renames are relative to a directory fd
/// (`renameat`), so there's no leading `/` to anchor on — `usr/bin/foo` and
/// `bin/foo` must both work, and no separator at all means "current
/// directory" for both sides equally.
fn is_apk_staging_rename(old_path: &str, new_path: &str) -> bool {
    let (old_dir, old_base) = old_path.rsplit_once('/').unwrap_or(("", old_path));
    let (new_dir, _) = new_path.rsplit_once('/').unwrap_or(("", new_path));
    old_dir == new_dir
        && old_base
            .strip_prefix(APK_STAGING_FILE_PREFIX)
            .is_some_and(|hex| !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// The suffix a rename appends to a file's name, when that is what it does: the tail
/// of `new_path` after `old_path` (same directory, `a.docx` → `a.docx.locked`), or,
/// when the directories differ, the tail of `new_path`'s *file name* after
/// `old_path`'s (`~/docs/a.docx` → `~/.stash/a.docx.locked`, #512). `None` when
/// neither relation holds. Splits on `/` and `\\` alike: Windows sensors feed this
/// rule too. Works on the raw path strings, so a relative pair (both relative to
/// the same unresolved dirfd or cwd) compares consistently without resolving it.
fn appended_suffix<'a>(old_path: &str, new_path: &'a str) -> Option<&'a str> {
    if let Some(suffix) = new_path.strip_prefix(old_path) {
        return Some(suffix);
    }
    let old_base = split_dir_base(old_path).1;
    let new_base = split_dir_base(new_path).1;
    // No `old_dir == new_dir` shortcut: with equal directories the literal prefix test
    // above only fails when the separators differ (`dir/a` vs `dir\a.locked`), and the
    // base-name comparison below is exactly what must still run then.
    if old_base.is_empty() {
        return None;
    }
    new_base.strip_prefix(old_base)
}

/// Whether creating `created` (at `created_ts`) and unlinking `deleted` (at `deleted_ts`)
/// is one write-new-then-unlink: the new file's name extends the deleted one's by a
/// lettered, non-rotation, non-Maildir suffix ([`appended_suffix`]), the kernel-time
/// order is create-then-unlink, and they are within [`CREATE_UNLINK_PAIR_WINDOW_NS`].
fn pairs_create_and_unlink(created_ts: u64, created: &str, deleted_ts: u64, deleted: &str) -> bool {
    created_ts <= deleted_ts
        && deleted_ts - created_ts <= CREATE_UNLINK_PAIR_WINDOW_NS
        && appended_suffix(deleted, created).is_some_and(|suffix| {
            !suffix.is_empty()
                && !is_rotation_suffix(suffix)
                && !is_maildir_delivery(deleted, created, suffix)
        })
}

/// `path` split at its last separator into `(directory, file name)`; no separator
/// means an empty directory part.
fn split_dir_base(path: &str) -> (&str, &str) {
    match path.rfind(['/', '\\']) {
        Some(i) => (&path[..i], &path[i + 1..]),
        None => ("", path),
    }
}

/// True for a suffix that is exactly a Maildir info marker: `:2,` followed by
/// zero or more flag letters. Delivering a message out of `new/` into `cur/` is a
/// cross-directory rename that appends precisely this (`msg` → `msg:2,S`), and an
/// IMAP server or `mbsync` does it for every message a client opens: 20+ in a
/// few seconds on "mark all read" (#512). Structural like
/// [`is_maildir_flag_change`], for the same reason: the alphabet is a tight shape
/// and there is no small fixed set of `comm` values to gate on.
fn is_maildir_info_suffix(suffix: &str) -> bool {
    suffix.strip_prefix(":2,").is_some_and(is_maildir_flags)
}

/// True for a real Maildir delivery: a move from a `new` directory into the `cur`
/// directory next to it, whose new name only appends a Maildir info suffix
/// ([`is_maildir_info_suffix`]). The directory shape is part of the test, not just the
/// suffix: `:2,` followed by lowercase keyword letters is a free, readable extension for
/// an encryptor (`f.docx` → `f.docx:2,locked`), so the suffix alone must never exclude
/// a rename (#526 review, found live on Alpine).
fn is_maildir_delivery(old_path: &str, new_path: &str, suffix: &str) -> bool {
    if !is_maildir_info_suffix(suffix) {
        return false;
    }
    let (old_dir, _) = split_dir_base(old_path);
    let (new_dir, _) = split_dir_base(new_path);
    let (old_parent, old_leaf) = split_dir_base(old_dir);
    let (new_parent, new_leaf) = split_dir_base(new_dir);
    old_leaf == "new" && new_leaf == "cur" && old_parent == new_parent
}

/// True for what follows `:2,` in a Maildir info suffix: the standard flag letters
/// ([`MAILDIR_FLAG_LETTERS`]) and then, optionally, Dovecot's IMAP keywords, which it
/// stores as lowercase `a`-`z` after them (`:2,Sa`, `:2,RSab`; Thunderbird tags,
/// `$Label1`, Junk/NonJunk). Delivering or tagging 20+ messages raised T1486 on the
/// standard alphabet alone (#526 review, live on Alpine). The order keeps the shape
/// tight: keywords never precede a standard flag.
fn is_maildir_flags(flags: &str) -> bool {
    let keywords = flags.trim_start_matches(|c: char| {
        u8::try_from(c).is_ok_and(|b| MAILDIR_FLAG_LETTERS.contains(&b))
    });
    keywords.bytes().all(|b| b.is_ascii_lowercase())
}

/// True for `check_mass_rename_pattern`'s Maildir-flag-change false positive
/// (#459 part 1): `old_path` already ends in the Maildir info/flags marker
/// (`:2,` optionally followed by flag letters) and `suffix` — the tail
/// `new_path` appends — is composed entirely of valid Maildir flag letters
/// ([`MAILDIR_FLAG_LETTERS`]).
///
/// Deliberately **not** also gated on `comm`, unlike [`ImpactState::is_in_place_edit_backup`]
/// and unlike issue #459's own suggestion: `sed` is one fixed,
/// well-known binary, but "a mail server touching Maildir" has no small
/// fixed `comm` set to enumerate without guessing (dovecot, courier,
/// procmail, maildrop, notmuch, mbsync, offlineimap, mutt, ...) — inventing
/// one would be exactly the uncalibrated-exclusion-list problem this crate's
/// own module doc warns against. The flag-letter alphabet constraint is
/// already a tight structural signal on its own, the same class of reasoning
/// [`is_rotation_suffix`]'s all-digit check relies on.
fn is_maildir_flag_change(old_path: &str, suffix: &str) -> bool {
    if suffix.is_empty() || !is_maildir_flags(suffix) {
        return false;
    }
    let Some(marker) = old_path.rfind(":2,") else {
        return false;
    };
    is_maildir_flags(&old_path[marker + 3..])
}
