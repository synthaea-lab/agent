//! `Microsoft-Windows-Kerberos/Operational` delegation failures (#364).

use schema::{
    Event, EventMeta, KerberosDelegationFailureEvent, KerberosDelegationFailureKind, User,
    time::now_ns,
};

use super::BlockOutcome;
use crate::xml;

/// `Microsoft-Windows-Kerberos/Operational` into a [`KerberosDelegationFailureEvent`] (#364):
/// EID 201 (unconstrained delegation denied) or 202 (TGT session-key export denied). Skipped
/// (cursor still advances): a block the `EventRecordID`/`EventID` extraction fails on, or any
/// id the `XPath` filter let through that this function has no state for.
///
/// This channel is off by default on a clean install (checked on this host,
/// `docs/sensors/sources.md`); unlike the `auditpol` subcategories other targets
/// enable, nothing here turns it on — same open question as #786's point 1 for
/// `TaskScheduler/Operational`, not duplicated here. A disabled channel is still reported, not
/// silently idle, by the sensor's start-up check (`warn_about_disabled_channels`).
pub(crate) fn normalize_kerberos_delegation_failure_block(block: &str) -> BlockOutcome {
    let Some(record) = xml::parse_kerberos_delegation_failure_block(block) else {
        return BlockOutcome::Unparseable;
    };
    let record_id = record.record_id;
    let kind = match record.event_id {
        201 => KerberosDelegationFailureKind::UnconstrainedDelegationDenied,
        202 => KerberosDelegationFailureKind::TgtSessionKeyExportDenied,
        _ => return BlockOutcome::Filtered { record_id },
    };
    let comm = record
        .process_name
        .as_deref()
        .and_then(|path| path.rsplit(['/', '\\']).next())
        .unwrap_or_default()
        .to_string();
    let event = Event::KerberosDelegationFailure(KerberosDelegationFailureEvent {
        meta: EventMeta {
            pid: record.caller_pid.unwrap_or(0),
            ppid: 0,
            user: User::Unknown,
            timestamp_ns: record.time_created_ns.unwrap_or_else(now_ns),
            comm,
            container: None, // Windows: no container support
            process_generation: None,
            parent_process_generation: None,
        },
        kind,
        target_server: record.target_server.unwrap_or_default(),
        target_user: record.target_user.unwrap_or_default(),
        target_domain: record.target_domain.unwrap_or_default(),
        caller_user: record.client_user_name.unwrap_or_default(),
        caller_domain: record.client_domain_name.unwrap_or_default(),
    });
    BlockOutcome::Event { record_id, event }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Field names and order from the provider's own manifest
    // (`Microsoft-Windows-Security-Kerberos`, `wevtutil gp ... /ge:true /gm:true`, checked on
    // this host, #364): EID 201 and 202 share one nine-field template.
    const BLOCK_201: &str = "<Event><System><EventID>201</EventID>\
        <TimeCreated SystemTime='2026-10-23T09:15:30.0000000Z'/><EventRecordID>5201</EventRecordID>\
        <Channel>Microsoft-Windows-Kerberos/Operational</Channel></System><EventData>\
        <Data Name='TargetName'>cifs/dc01.lab.internal</Data><Data Name='UserName'>analyst</Data>\
        <Data Name='DomainName'>LAB</Data><Data Name='CallerPID'>4120</Data>\
        <Data Name='ProcessName'>C:\\Windows\\System32\\fileserver.exe</Data>\
        <Data Name='ClientLUID'>0x3e7</Data><Data Name='ClientUserName'>svc_fileserver</Data>\
        <Data Name='ClientDomainName'>LAB</Data><Data Name='MechanismOID'>1.2.840.113554.1.2.2</Data>\
        </EventData></Event>";
    const BLOCK_202: &str = "<Event><System><EventID>202</EventID>\
        <TimeCreated SystemTime='2026-10-23T09:16:00.0000000Z'/><EventRecordID>5202</EventRecordID>\
        <Channel>Microsoft-Windows-Kerberos/Operational</Channel></System><EventData>\
        <Data Name='TargetName'>HTTP/app01.lab.internal</Data><Data Name='UserName'>svc_app</Data>\
        <Data Name='DomainName'>LAB</Data><Data Name='CallerPID'>8800</Data>\
        <Data Name='ProcessName'>C:\\inetpub\\w3wp.exe</Data>\
        <Data Name='ClientLUID'>0x3e4</Data><Data Name='ClientUserName'>w3wp</Data>\
        <Data Name='ClientDomainName'>LAB</Data><Data Name='MechanismOID'>1.2.840.113554.1.2.2</Data>\
        </EventData></Event>";

    fn kerberos_failure(block: &str) -> KerberosDelegationFailureEvent {
        match normalize_kerberos_delegation_failure_block(block) {
            BlockOutcome::Event {
                event: Event::KerberosDelegationFailure(e),
                ..
            } => e,
            other => panic!("expected a KerberosDelegationFailure event, got {other:?}"),
        }
    }

    #[test]
    fn a_201_is_unconstrained_delegation_denied_with_the_caller_process() {
        let event = kerberos_failure(BLOCK_201);
        assert_eq!(
            event.kind,
            KerberosDelegationFailureKind::UnconstrainedDelegationDenied
        );
        assert_eq!(event.target_server, "cifs/dc01.lab.internal");
        assert_eq!(event.target_user, "analyst");
        assert_eq!(event.target_domain, "LAB");
        assert_eq!(event.meta.pid, 4120);
        assert_eq!(event.meta.comm, "fileserver.exe");
        assert_eq!(event.caller_user, "svc_fileserver");
        assert_eq!(event.caller_domain, "LAB");
        assert_eq!(event.meta.user, User::Unknown);
        assert_eq!(
            event.meta.timestamp_ns,
            xml::time_created_ns(BLOCK_201).unwrap(),
            "timestamp should come from TimeCreated, not the time the agent happened to parse it"
        );
    }

    #[test]
    fn a_missing_time_created_falls_back_to_now_rather_than_zero() {
        let block = BLOCK_201.replacen(
            "<TimeCreated SystemTime='2026-10-23T09:15:30.0000000Z'/>",
            "",
            1,
        );
        let before = now_ns();
        let event = kerberos_failure(&block);
        assert!(
            event.meta.timestamp_ns >= before,
            "{}",
            event.meta.timestamp_ns
        );
    }

    #[test]
    fn a_202_is_tgt_session_key_export_denied() {
        let event = kerberos_failure(BLOCK_202);
        assert_eq!(
            event.kind,
            KerberosDelegationFailureKind::TgtSessionKeyExportDenied
        );
        assert_eq!(event.target_server, "HTTP/app01.lab.internal");
        assert_eq!(event.meta.pid, 8800);
        assert_eq!(event.meta.comm, "w3wp.exe");
    }

    #[test]
    fn other_ids_are_skipped_but_advance_the_cursor() {
        let other = BLOCK_201.replace("<EventID>201</EventID>", "<EventID>203</EventID>");
        assert!(matches!(
            normalize_kerberos_delegation_failure_block(&other),
            BlockOutcome::Filtered { record_id: 5201 }
        ));
    }

    #[test]
    fn a_missing_caller_pid_is_zero_not_guessed() {
        let block = BLOCK_201.replace("<Data Name='CallerPID'>4120</Data>", "");
        assert_eq!(kerberos_failure(&block).meta.pid, 0);
    }
}
