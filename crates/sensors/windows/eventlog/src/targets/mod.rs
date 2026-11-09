//! Per-domain normalization: one parsed Event Log record into a `schema::Event`. Pure code, built
//! on every platform so its tests run everywhere; the poll targets that wire each normalizer to a
//! channel stay in the Windows-only `sensor.rs`.

pub(crate) mod kerberos;
pub(crate) mod log_cleared;
pub(crate) mod session;

use schema::Event;

/// What a poll target's `parse_block` yields for one `<Event>` XML block.
#[derive(Debug, PartialEq)]
#[expect(
    clippy::large_enum_variant,
    reason = "a short-lived return value whose event is moved straight into the sink by value"
)]
pub(crate) enum BlockOutcome {
    /// Not even parseable: the record cursor stays where it is.
    Unparseable,
    /// Parsed but unusable (missing required fields, an id the target has no shape for):
    /// advances the cursor without counting, since it is noise the sensor filtered out.
    Filtered { record_id: u64 },
    /// A normalized event: advances the cursor, counted and forwarded.
    Event { record_id: u64, event: Event },
}

impl BlockOutcome {
    /// `Filtered` when `event` is `None`, for normalizers whose mapping is itself optional.
    pub(crate) fn from_optional(record_id: u64, event: Option<Event>) -> Self {
        match event {
            Some(event) => Self::Event { record_id, event },
            None => Self::Filtered { record_id },
        }
    }

    /// The block's `EventRecordID`, unless it was unparseable.
    pub(crate) fn record_id(&self) -> Option<u64> {
        match self {
            Self::Unparseable => None,
            Self::Filtered { record_id } | Self::Event { record_id, .. } => Some(*record_id),
        }
    }
}

#[cfg(test)]
mod tests {
    use schema::{EventMeta, LogClearedEvent, User};

    use super::*;

    fn some_event() -> Event {
        Event::LogCleared(LogClearedEvent {
            meta: EventMeta {
                pid: 1,
                ppid: 0,
                user: User::Unknown,
                timestamp_ns: 0,
                comm: String::new(),
                container: None,
                process_generation: None,
                parent_process_generation: None,
            },
            channel: "Security".into(),
            subject_user: String::new(),
            subject_logon_id: None,
            backup_path: None,
        })
    }

    #[test]
    fn only_an_unparseable_block_has_no_record_id() {
        assert_eq!(BlockOutcome::Unparseable.record_id(), None);
        assert_eq!(BlockOutcome::Filtered { record_id: 5 }.record_id(), Some(5));
        let event = BlockOutcome::Event {
            record_id: 6,
            event: some_event(),
        };
        assert_eq!(event.record_id(), Some(6));
    }

    #[test]
    fn a_missing_mapping_is_filtered_not_unparseable() {
        assert_eq!(
            BlockOutcome::from_optional(5, None),
            BlockOutcome::Filtered { record_id: 5 }
        );
        assert_eq!(
            BlockOutcome::from_optional(6, Some(some_event())),
            BlockOutcome::Event {
                record_id: 6,
                event: some_event(),
            }
        );
    }

    #[test]
    fn a_block_without_a_record_id_is_unparseable() {
        assert_eq!(
            log_cleared::normalize_log_cleared_block("<Event><System></System></Event>"),
            BlockOutcome::Unparseable
        );
        assert_eq!(
            session::normalize_session_lifecycle_block("not xml"),
            BlockOutcome::Unparseable
        );
    }
}
