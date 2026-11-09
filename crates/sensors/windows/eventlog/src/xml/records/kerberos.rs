//! Kerberos client 201/202: a delegation request was denied.

use crate::xml::{
    scan::{extract_between, opt_data},
    time::time_created_ns,
};

/// One Kerberos client-side delegation-failure record: EID 201 (unconstrained
/// delegation denied) or 202 (TGT session key export denied), same nine-field
/// template (`#364`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KerberosDelegationFailureRecord {
    pub record_id: u64,
    pub event_id: u32,
    pub time_created_ns: Option<u64>,
    /// `TargetName`/`Server` — the server named in the local process's request.
    pub target_server: Option<String>,
    /// `UserName` — credentials explicitly supplied to the call, usually empty.
    pub target_user: Option<String>,
    /// `DomainName` — that supplied account's domain.
    pub target_domain: Option<String>,
    /// `CallerPID` — the client process that made the request.
    pub caller_pid: Option<u32>,
    /// `ProcessName` — that process's image path.
    pub process_name: Option<String>,
    /// `ClientUserName` — that process's own owner account.
    pub client_user_name: Option<String>,
    /// `ClientDomainName` — that account's domain.
    pub client_domain_name: Option<String>,
}

/// Parses one 201/202 `<Event>` block. `None` if the block is missing
/// `EventRecordID` or `EventID` (a genuinely different event matched the
/// `XPath` filter — skip rather than guess, same convention as the other
/// parsers in this module).
#[must_use]
pub fn parse_kerberos_delegation_failure_block(
    block: &str,
) -> Option<KerberosDelegationFailureRecord> {
    let record_id = extract_between(block, "<EventRecordID>", "</EventRecordID>")?
        .parse()
        .ok()?;
    let event_id = extract_between(block, "<EventID>", "</EventID>")?
        .parse()
        .ok()?;
    Some(KerberosDelegationFailureRecord {
        record_id,
        event_id,
        time_created_ns: time_created_ns(block),
        target_server: opt_data(block, "TargetName"),
        target_user: opt_data(block, "UserName"),
        target_domain: opt_data(block, "DomainName"),
        caller_pid: opt_data(block, "CallerPID").and_then(|s| s.parse().ok()),
        process_name: opt_data(block, "ProcessName"),
        client_user_name: opt_data(block, "ClientUserName"),
        client_domain_name: opt_data(block, "ClientDomainName"),
    })
}
