//! The Kernel-Process records the sensor handles, and the decisions about them that do not
//! need an ETW record: which ids are read, which image paths count, and how a process start
//! becomes an [`ExecEvent`].

use schema::{EventMeta, ExecEvent};

use crate::{normalize::basename, shed::CmdlineShedding};

/// What a Kernel-Process record names when its image field is missing.
pub(crate) const UNKNOWN_IMAGE: &str = "<unknown>";

/// The Kernel-Process event ids `process_provider` handles. Processes already running come
/// from the pid-store seed, not from a rundown (EID 15). Thread stops (EID 4), which the
/// THREAD keyword brings along, are dropped on their id before any parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KernelProcessEvent {
    /// EID 1: a new process, forwarded as an [`ExecEvent`].
    ProcessStart,
    /// EID 2: prunes the pid store (PID recycling).
    ProcessEnd,
    /// EID 3: a thread start, forwarded when it is started from another process
    /// (<https://github.com/synthaea-lab/agent/issues/41>).
    ThreadStart,
    /// EID 5: a DLL or EXE mapped into a process.
    ImageLoad,
    /// EIDs 23-26: a server silo is created or torn down
    /// (<https://github.com/synthaea-lab/agent/issues/39>).
    SiloChange,
}

impl KernelProcessEvent {
    /// Every id [`Self::from_id`] reads: the provider's event-id filter.
    pub(crate) const EVENT_IDS: [u16; 8] = [1, 2, 3, 5, 23, 24, 25, 26];

    pub(crate) fn from_id(event_id: u16) -> Option<Self> {
        match event_id {
            1 => Some(Self::ProcessStart),
            2 => Some(Self::ProcessEnd),
            3 => Some(Self::ThreadStart),
            5 => Some(Self::ImageLoad),
            23..=26 => Some(Self::SiloChange),
            _ => None,
        }
    }
}

/// A Kernel-Process sequence number field, `None` when the event version has none or it
/// is 0 (no stamp).
pub(crate) fn sequence_number(field: Option<u64>) -> Option<u64> {
    field.filter(|&n| n != 0)
}

/// The image an `ImageLoad` names, `None` when the record names none.
pub(crate) fn loaded_image(field: Option<String>) -> Option<String> {
    field.filter(|image| !image.is_empty() && image != UNKNOWN_IMAGE)
}

/// A `ProcessStart` record, its image path already normalized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessStart {
    pub(crate) pid: u32,
    pub(crate) ppid: u32,
    pub(crate) image_path: String,
    pub(crate) timestamp_ns: u64,
    /// #725: `ProcessStart` v4+ carries both incarnation stamps; an older version leaves
    /// them unset rather than guessed.
    pub(crate) generation: Option<u64>,
    pub(crate) parent_generation: Option<u64>,
}

/// What the sensor learns about a started process outside its record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExecContext {
    pub(crate) meta: EventMeta,
    pub(crate) parent_image_path: Option<String>,
    /// F-1: the real command line ([`CommandLine::into_text`]); `None` when no source had it.
    pub(crate) cmdline: Option<String>,
    pub(crate) image_file_id: Option<String>,
}

/// Where the command line of a started process came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CommandLine {
    /// Read from the process's PEB: the primary source.
    FromProcess(String),
    /// The process could not be read (already exited, protected); the kernel recorded this
    /// with its creation.
    FromCreation(String),
    /// Neither source had it.
    Unavailable,
}

impl CommandLine {
    /// The process's own answer when it gave one. The creation record is only asked for
    /// otherwise: asking may wait, and takes the record out of its store.
    pub(crate) fn choose(
        from_process: Option<String>,
        from_creation: impl FnOnce() -> Option<String>,
    ) -> Self {
        match from_process {
            Some(cmdline) => Self::FromProcess(cmdline),
            None => from_creation().map_or(Self::Unavailable, Self::FromCreation),
        }
    }

    /// Counts a start the process did not answer for: rescued by its creation record, or lost.
    pub(crate) fn count_into(&self, shedding: &CmdlineShedding) {
        match self {
            Self::FromProcess(_) => {}
            Self::FromCreation(_) => {
                shedding.from_creation.add();
            }
            Self::Unavailable => {
                shedding.lost.add();
            }
        }
    }

    pub(crate) fn into_text(self) -> Option<String> {
        match self {
            Self::FromProcess(cmdline) | Self::FromCreation(cmdline) => Some(cmdline),
            Self::Unavailable => None,
        }
    }
}

impl ProcessStart {
    /// The image to remember for the pid. Never `"<unknown>"`: a hit on it would suppress
    /// live lookups.
    pub(crate) fn cacheable_image(&self) -> Option<&str> {
        (self.image_path != UNKNOWN_IMAGE).then_some(self.image_path.as_str())
    }

    pub(crate) fn exec_event(self, context: ExecContext) -> ExecEvent {
        let ExecContext {
            mut meta,
            parent_image_path,
            cmdline,
            image_file_id,
        } = context;
        // The stamps as the kernel recorded them at this creation, not whatever holds the
        // pids in the store by now.
        meta.process_generation = self.generation.or(meta.process_generation);
        meta.parent_process_generation = self.parent_generation.or(meta.parent_process_generation);
        // Fall back to the image path only when no source had the command line, never to a
        // placeholder pretending to be arguments.
        let cmdline = cmdline.unwrap_or_else(|| self.image_path.clone());
        ExecEvent {
            meta,
            image_path: self.image_path,
            cmdline,
            argv: vec![], // Windows has a flat command line; consumers fall back
            cmdline_truncated: false, // CreateProcess caps it at 32,766 UTF-16 units (#1112)
            argv_omitted_bytes: None, // read from the PEB after the fact: a lost read is not measured
            env_security: Vec::new(), // no exec-environment capture on Windows yet (#363 is Linux-only)
            parent_comm: parent_image_path.as_deref().map(basename),
            parent_image_path,
            sha256: None, // filled by the agent's enrichment stage
            signature: None,
            original_file_name: None, // filled by the agent's enrichment stage (#983)
            company_name: None,
            file_description: None,
            product_name: None,
            image_file_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_event_id_filter_is_exactly_the_ids_read() {
        for event_id in 0..=u16::MAX {
            assert_eq!(
                KernelProcessEvent::EVENT_IDS.contains(&event_id),
                KernelProcessEvent::from_id(event_id).is_some(),
                "EID {event_id}"
            );
        }
    }

    #[test]
    fn handled_ids_map_to_their_event() {
        assert_eq!(
            KernelProcessEvent::from_id(1),
            Some(KernelProcessEvent::ProcessStart)
        );
        assert_eq!(
            KernelProcessEvent::from_id(2),
            Some(KernelProcessEvent::ProcessEnd)
        );
        assert_eq!(
            KernelProcessEvent::from_id(3),
            Some(KernelProcessEvent::ThreadStart)
        );
        assert_eq!(
            KernelProcessEvent::from_id(5),
            Some(KernelProcessEvent::ImageLoad)
        );
        for silo_id in 23..=26 {
            assert_eq!(
                KernelProcessEvent::from_id(silo_id),
                Some(KernelProcessEvent::SiloChange)
            );
        }
    }

    #[test]
    fn thread_stops_rundowns_and_other_ids_are_dropped() {
        for id in [0, 4, 6, 15, 22, 27, u16::MAX] {
            assert_eq!(KernelProcessEvent::from_id(id), None, "EID {id}");
        }
    }

    #[test]
    fn a_zero_or_missing_sequence_number_is_no_stamp() {
        assert_eq!(sequence_number(None), None);
        assert_eq!(sequence_number(Some(0)), None);
        assert_eq!(sequence_number(Some(42)), Some(42));
    }

    #[test]
    fn an_image_load_without_an_image_is_not_forwarded() {
        assert_eq!(loaded_image(None), None);
        assert_eq!(loaded_image(Some(String::new())), None);
        assert_eq!(loaded_image(Some(UNKNOWN_IMAGE.to_owned())), None);
        assert_eq!(
            loaded_image(Some(r"C:\Windows\System32\ntdll.dll".to_owned())),
            Some(r"C:\Windows\System32\ntdll.dll".to_owned())
        );
    }

    fn start(image_path: &str) -> ProcessStart {
        ProcessStart {
            pid: 4242,
            ppid: 100,
            image_path: image_path.to_owned(),
            timestamp_ns: 7,
            generation: None,
            parent_generation: None,
        }
    }

    fn meta(process_generation: Option<u64>, parent_process_generation: Option<u64>) -> EventMeta {
        EventMeta {
            process_generation,
            parent_process_generation,
            ..schema::fixtures::meta()
        }
    }

    fn context(meta: EventMeta) -> ExecContext {
        ExecContext {
            meta,
            parent_image_path: None,
            cmdline: None,
            image_file_id: None,
        }
    }

    #[test]
    fn an_unknown_image_is_not_cached() {
        assert_eq!(start(UNKNOWN_IMAGE).cacheable_image(), None);
        assert_eq!(start(r"C:\a.exe").cacheable_image(), Some(r"C:\a.exe"));
    }

    #[test]
    fn the_record_stamps_win_over_the_store() {
        let mut process = start(r"C:\a.exe");
        process.generation = Some(11);
        process.parent_generation = Some(12);
        let event = process.exec_event(context(meta(Some(1), Some(2))));
        assert_eq!(event.meta.process_generation, Some(11));
        assert_eq!(event.meta.parent_process_generation, Some(12));
    }

    #[test]
    fn a_record_without_stamps_keeps_the_store_generations() {
        let event = start(r"C:\a.exe").exec_event(context(meta(Some(1), Some(2))));
        assert_eq!(event.meta.process_generation, Some(1));
        assert_eq!(event.meta.parent_process_generation, Some(2));
    }

    #[test]
    fn a_failed_command_line_read_falls_back_to_the_image_path() {
        let event = start(r"C:\a.exe").exec_event(context(meta(None, None)));
        assert_eq!(event.cmdline, r"C:\a.exe");

        let mut read = context(meta(None, None));
        read.cmdline = Some(r#""C:\a.exe" --flag"#.to_owned());
        let event = start(r"C:\a.exe").exec_event(read);
        assert_eq!(event.cmdline, r#""C:\a.exe" --flag"#);
    }

    fn never_asked() -> Option<String> {
        panic!("the creation record is asked for although the process answered")
    }

    /// The exec event and the counters of a start whose two sources answered as given.
    fn started_with(
        from_process: Option<&str>,
        from_creation: Option<&str>,
    ) -> (ExecEvent, CmdlineShedding) {
        let shedding = CmdlineShedding::default();
        let cmdline = CommandLine::choose(from_process.map(str::to_owned), || {
            from_creation.map(str::to_owned)
        });
        cmdline.count_into(&shedding);
        let mut context = context(meta(None, None));
        context.cmdline = cmdline.into_text();
        (start(r"C:\a.exe").exec_event(context), shedding)
    }

    #[test]
    fn the_command_line_read_from_the_process_wins_and_the_creation_record_is_left_alone() {
        let cmdline = CommandLine::choose(Some("a.exe --from-peb".to_owned()), never_asked);
        assert_eq!(
            cmdline,
            CommandLine::FromProcess("a.exe --from-peb".to_owned())
        );

        let (event, shedding) = started_with(Some("a.exe --from-peb"), Some("a.exe --other"));
        assert_eq!(event.cmdline, "a.exe --from-peb");
        assert_eq!(shedding.from_creation.get(), 0);
        assert_eq!(shedding.lost.get(), 0);
    }

    #[test]
    fn a_process_that_could_not_be_read_gets_the_command_line_of_its_creation_record() {
        let (event, shedding) = started_with(None, Some("reg.exe save HKLM\\SYSTEM s"));

        assert_eq!(event.cmdline, "reg.exe save HKLM\\SYSTEM s");
        assert_eq!(shedding.from_creation.get(), 1);
        assert_eq!(shedding.lost.get(), 0);
    }

    #[test]
    fn a_start_no_source_answers_for_reports_its_image_path_and_is_counted_lost() {
        let (event, shedding) = started_with(None, None);

        assert_eq!(event.cmdline, r"C:\a.exe");
        assert_eq!(shedding.lost.get(), 1);
        assert_eq!(shedding.from_creation.get(), 0);
    }

    #[test]
    fn the_parent_name_comes_from_the_parent_image() {
        let mut with_parent = context(meta(None, None));
        with_parent.parent_image_path = Some(r"C:\Windows\explorer.exe".to_owned());
        with_parent.image_file_id = Some("0:1".to_owned());
        let event = start(r"C:\a.exe").exec_event(with_parent);
        assert_eq!(event.parent_comm.as_deref(), Some("explorer.exe"));
        assert_eq!(
            event.parent_image_path.as_deref(),
            Some(r"C:\Windows\explorer.exe")
        );
        assert_eq!(event.image_file_id.as_deref(), Some("0:1"));
        assert_eq!(event.image_path, r"C:\a.exe");
        assert!(event.argv.is_empty());

        let orphan = start(r"C:\a.exe").exec_event(context(meta(None, None)));
        assert_eq!(orphan.parent_comm, None);
    }
}
