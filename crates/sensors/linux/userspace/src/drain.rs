//! One drain of one ring buffer into an `EventSink`: the per-wakeup cap, the agent's own-pid
//! exclusion and the read of a fixed-size wire record. Kept apart from the rings themselves so
//! it runs over any byte source, a fake one in the tests.

use core::ops::Deref;

use schema::{Event, sensor::EventSink};

/// Items one drain takes before returning to `select!`: a ring read never yields, so an
/// uncapped one starves every other ring (issue #326,
/// `docs/sensors/linux/userspace-loader.md#the-drain-loop`).
pub(crate) const MAX_ITEMS_PER_DRAIN: usize = 256;

/// A source of raw ring-buffer records.
pub(crate) trait RecordSource {
    type Record<'a>: Deref<Target = [u8]>
    where
        Self: 'a;

    fn next_record(&mut self) -> Option<Self::Record<'_>>;
}

impl RecordSource for aya::maps::RingBuf<aya::maps::MapData> {
    type Record<'a> = aya::maps::ring_buf::RingBufItem<'a>;

    fn next_record(&mut self) -> Option<Self::Record<'_>> {
        self.next()
    }
}

/// Why a drain stopped.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Drained {
    /// The source ran out: its readiness may be cleared.
    Dry,
    /// [`MAX_ITEMS_PER_DRAIN`] was reached with records possibly still waiting. Readiness
    /// must stay set, so the next `select!` round drains it again instead of waiting for the
    /// next epoll edge.
    Capped,
}

/// Takes up to [`MAX_ITEMS_PER_DRAIN`] records from `source` and sends each event `to_event`
/// makes of one to `sink`. `to_event` returns an `Event`, or `None` for a record that is not
/// one (a refused record, a payload that is not a DNS query), which is skipped.
///
/// Events of `own_pid` are dropped (issue #340): the agent's own writes would otherwise be
/// observed and written again without bound.
pub(crate) fn drain_records<S, E>(
    source: &mut S,
    sink: &dyn EventSink,
    own_pid: u32,
    mut to_event: impl FnMut(&[u8]) -> E,
) -> Drained
where
    S: RecordSource + ?Sized,
    E: Into<Option<Event>>,
{
    for _ in 0..MAX_ITEMS_PER_DRAIN {
        let Some(record) = source.next_record() else {
            return Drained::Dry;
        };
        let Some(event) = to_event(&record).into() else {
            continue;
        };
        if event.meta().pid != own_pid {
            sink.on_event(event);
        }
    }
    Drained::Capped
}

/// A fixed-size `repr(C)` record the eBPF probes write into a ring buffer.
///
/// # Safety
///
/// The type must be the very `repr(C)` layout the probe writes into its ring (shared through
/// `sensor_linux_wire`), so that the first `size_of::<Self>()` bytes of a record from that ring
/// are a valid value of it.
pub(crate) unsafe trait WireRecord: Copy {}

macro_rules! wire_records {
    ($($ty:ident),* $(,)?) => {
        $(
            // SAFETY: a `sensor_linux_wire` type, the layout the probe writes into its ring.
            unsafe impl WireRecord for sensor_linux_wire::$ty {}
        )*
    };
}

wire_records!(
    FileOpenEvent,
    ConnectEvent,
    FileWriteEvent,
    FileDeleteEvent,
    FileRenameEvent,
    SocketBindEvent,
    FileChmodEvent,
    FileSetTimeEvent,
    FileChownEvent,
    UdpSendEvent,
    UdpRecvEvent,
    DnsUdpQueryEvent,
    SocketListenEvent,
    SocketAcceptEvent,
    SocketCreateEvent,
    FileSetxattrEvent,
    FileRemovexattrEvent,
    MountEvent,
    SignalEvent,
    KernelModuleEvent,
    BpfEvent,
    PrctlEvent,
    PtraceEvent,
    ProcessVmReadEvent,
    ProcessVmWriteEvent,
    MemfdCreateEvent,
    IdentityChangeEvent,
    CapSetEvent,
    NamespaceEvent,
);

/// The `T` at the start of `record`, or `None` when the record is shorter than `T`.
pub(crate) fn read_wire<T: WireRecord>(record: &[u8]) -> Option<T> {
    if record.len() < core::mem::size_of::<T>() {
        return None;
    }
    // SAFETY: the length was checked above, `T: WireRecord` makes those bytes a valid `T`, and
    // `read_unaligned` handles the ring buffer's arbitrary alignment.
    Some(unsafe { core::ptr::read_unaligned(record.as_ptr().cast::<T>()) })
}

/// Exec records refused (ADR-0045): lengths that are not a shape the probe writes, or a record
/// shorter than they announce. Counted, the first one and every thousandth logged; the record
/// is dropped, never read past its end.
static EXEC_RECORDS_REFUSED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The exec event and its argv windows (ADR-0045: the record's size is not fixed), or `None`,
/// counted in [`EXEC_RECORDS_REFUSED`], for a record that does not parse.
pub(crate) fn exec_record(
    record: &[u8],
) -> Option<(
    sensor_linux_wire::ExecEvent,
    sensor_linux_wire::ExecArgv<'_>,
)> {
    match sensor_linux_wire::parse_exec_record(record) {
        Ok(parsed) => Some(parsed),
        Err(error) => {
            note_refused_exec_record(error, record.len());
            None
        }
    }
}

fn note_refused_exec_record(error: sensor_linux_wire::ExecRecordError, len: usize) {
    let n = EXEC_RECORDS_REFUSED.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    if n == 1 || n.is_multiple_of(1000) {
        tracing::warn!(
            ?error,
            len,
            refused = n,
            "sensor-linux: exec record refused"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, sync::Mutex};

    use schema::fixtures;

    use super::*;

    struct FakeRing(VecDeque<Vec<u8>>);

    impl RecordSource for FakeRing {
        type Record<'a> = Vec<u8>;

        fn next_record(&mut self) -> Option<Vec<u8>> {
            self.0.pop_front()
        }
    }

    #[derive(Default)]
    struct Collect(Mutex<Vec<Event>>);

    impl EventSink for Collect {
        fn on_event(&self, event: Event) {
            self.0.lock().unwrap().push(event);
        }
    }

    impl Collect {
        fn pids(&self) -> Vec<u32> {
            self.0
                .lock()
                .unwrap()
                .iter()
                .map(|e| e.meta().pid)
                .collect()
        }
    }

    /// A record whose first four bytes are the pid of the event it stands for.
    fn record(pid: u32) -> Vec<u8> {
        pid.to_le_bytes().to_vec()
    }

    fn event_of(record: &[u8]) -> Event {
        let pid = u32::from_le_bytes(record[..4].try_into().unwrap());
        Event::FileOpen(schema::FileOpenEvent {
            meta: schema::EventMeta {
                pid,
                ..fixtures::meta()
            },
            ..fixtures::file_open()
        })
    }

    #[test]
    fn a_drain_stops_at_the_cap_and_leaves_the_rest_for_the_next_round() {
        let total = MAX_ITEMS_PER_DRAIN + 10;
        let mut ring = FakeRing((1..=total as u32).map(record).collect());
        let sink = Collect::default();

        assert_eq!(
            drain_records(&mut ring, &sink, 0, event_of),
            Drained::Capped
        );
        assert_eq!(sink.pids().len(), MAX_ITEMS_PER_DRAIN);
        assert_eq!(ring.0.len(), 10);

        assert_eq!(drain_records(&mut ring, &sink, 0, event_of), Drained::Dry);
        assert_eq!(sink.pids().len(), total);
    }

    #[test]
    fn a_ring_that_runs_out_exactly_at_the_cap_counts_as_capped() {
        let mut ring = FakeRing((1..=MAX_ITEMS_PER_DRAIN as u32).map(record).collect());
        let sink = Collect::default();

        assert_eq!(
            drain_records(&mut ring, &sink, 0, event_of),
            Drained::Capped
        );
        assert_eq!(drain_records(&mut ring, &sink, 0, event_of), Drained::Dry);
    }

    #[test]
    fn the_agents_own_events_are_never_sent_to_the_sink() {
        let mut ring = FakeRing([7, 42, 8, 42].into_iter().map(record).collect());
        let sink = Collect::default();

        assert_eq!(drain_records(&mut ring, &sink, 42, event_of), Drained::Dry);
        assert_eq!(sink.pids(), [7, 8]);
    }

    #[test]
    fn records_that_are_not_events_are_skipped_but_count_toward_the_cap() {
        let mut ring = FakeRing((0..=MAX_ITEMS_PER_DRAIN as u32).map(record).collect());
        let sink = Collect::default();
        let odd_only = |r: &[u8]| (r[0] % 2 == 1).then(|| event_of(r));

        assert_eq!(
            drain_records(&mut ring, &sink, 0, odd_only),
            Drained::Capped
        );
        assert_eq!(sink.pids().len(), MAX_ITEMS_PER_DRAIN / 2);
        assert_eq!(ring.0.len(), 1);
    }

    #[test]
    fn a_record_shorter_than_its_wire_type_is_not_read() {
        let size = core::mem::size_of::<sensor_linux_wire::FileOpenEvent>();
        let mut bytes = vec![0u8; size];
        bytes[..4].copy_from_slice(&99u32.to_ne_bytes());

        let full = read_wire::<sensor_linux_wire::FileOpenEvent>(&bytes).expect("full record");
        assert_eq!(full.meta.pid, 99);
        assert!(read_wire::<sensor_linux_wire::FileOpenEvent>(&bytes[..size - 1]).is_none());
        assert!(read_wire::<sensor_linux_wire::FileOpenEvent>(&[]).is_none());
    }

    #[test]
    fn a_refused_exec_record_is_counted_and_dropped() {
        let before = EXEC_RECORDS_REFUSED.load(std::sync::atomic::Ordering::Relaxed);
        let mut ring = FakeRing([vec![0u8; 3]].into());
        let sink = Collect::default();

        let drained = drain_records(&mut ring, &sink, 0, |r: &[u8]| {
            exec_record(r).map(|_| event_of(r))
        });

        assert_eq!(drained, Drained::Dry);
        assert!(sink.pids().is_empty());
        assert_eq!(
            EXEC_RECORDS_REFUSED.load(std::sync::atomic::Ordering::Relaxed),
            before + 1
        );
    }
}
