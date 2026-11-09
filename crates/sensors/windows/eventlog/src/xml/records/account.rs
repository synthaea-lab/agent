//! Security 4720: a user account was created.

use crate::xml::scan::{extract_between, opt_data};

/// Fields extracted from a 4720 ("A user account was created") `<Event>` block —
/// Security log, requires the "User Account Management" audit subcategory (usually
/// enabled by default on both Client and Server SKUs, but the sensor enables it
/// itself belt-and-suspenders, like it does for 4698's subcategory).
///
/// Scope of the 4720 signal for a userland EDR on a member/standalone machine:
/// **local SAM only** (T1136.001 — Local Account). Domain account creation writes
/// 4720 on the domain controller, not on the machine where the attacker actually ran
/// `net user /add`, so we never observe it — that is T1136.002 (Domain Account) and
/// out of scope regardless. The sensor does not try to distinguish local vs. domain
/// on the reporting host (both look identical here); the SAM/domain distinction is
/// upstream, in whether Windows wrote the 4720 on THIS machine at all.
///
/// `TargetUserSid`/`TargetUserName` — the newly created account.
/// `SubjectUserSid`/`SubjectUserName` — the caller that created it (usually a local
/// administrator, or SYSTEM for programmatic paths like the Local Users MMC applet).
/// `SamAccountName` exists on this event too but is redundant with `TargetUserName`
/// on local SAM (differs from `TargetUserName` only for downlevel domain accounts,
/// which are out of scope) — kept out of the struct to avoid duplication.
///
/// Reconciled against a real `wevtutil qe Security /f:xml` capture on 2026-09-21
/// (Windows 11 lab VM `Sandbox`);
/// the fixture in this module's tests is faithful to that capture.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AccountCreatedEvent {
    pub record_id: u64,
    /// PID of the reporting process (`<Execution ProcessID='...'>`) — LSASS, same
    /// as [`LogonEvent`](crate::xml::LogonEvent). Not the caller's PID; that is not
    /// carried on this event.
    pub pid: u32,
    /// SID of the newly created account (`S-1-5-21-...`). None if the field was
    /// missing (should not happen on a well-formed 4720).
    pub target_user_sid: Option<String>,
    /// SAM name of the newly created account.
    pub target_user_name: Option<String>,
    /// SID of the caller that created the account.
    pub subject_user_sid: Option<String>,
    /// SAM name of the caller.
    pub subject_user_name: Option<String>,
}

/// Parses one 4720 `<Event>` block. `None` if the block is missing `EventRecordID`
/// (a genuinely different event matched the `XPath` filter — skip rather than
/// guess, same convention as the other parsers in this module).
#[must_use]
pub fn parse_account_created_block(block: &str) -> Option<AccountCreatedEvent> {
    let record_id = extract_between(block, "<EventRecordID>", "</EventRecordID>")?
        .parse()
        .ok()?;
    let pid = extract_between(block, "ProcessID='", "'")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Some(AccountCreatedEvent {
        record_id,
        pid,
        // 4720 uses `TargetSid`, NOT `TargetUserSid` (that spelling is only on
        // 4624/4625/4648 in `LogonEvent`). Documented in the Microsoft
        // Security-auditing schema for 4720; caught while writing this module's
        // 4720 fixture.
        target_user_sid: opt_data(block, "TargetSid"),
        target_user_name: opt_data(block, "TargetUserName"),
        subject_user_sid: opt_data(block, "SubjectUserSid"),
        subject_user_name: opt_data(block, "SubjectUserName"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::scan::split_event_blocks;

    // Fixture reconciled 2026-09-21 against a real
    // `wevtutil qe Security /f:xml` capture on Windows 11 lab VM `Sandbox`.
    // Note that `UserAccountControl` is
    // multi-line (indented `%%2080/%%2082/%%2084`, one per line); the parser
    // ignores this field, so the whitespace shape does not affect correctness
    // but is preserved here to stay faithful to what wevtutil rendered.

    /// A local SAM account creation via `net user testuser224 <pwd> /add`
    /// executed by `solka` (a local administrator). Target is the newly
    /// created `testuser224` account (RID 1002).
    const ACCOUNT_CREATED_XML: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4720</EventID><Version>0</Version><Level>0</Level><Task>13824</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-09-21T13:29:23.0286360Z'/><EventRecordID>76327</EventRecordID><Correlation ActivityID='{9f6e2246-49c9-0001-c923-6e9fc949dd01}'/><Execution ProcessID='836' ThreadID='4836'/><Channel>Security</Channel><Computer>Sandbox</Computer><Security/></System><EventData><Data Name='TargetUserName'>testuser224</Data><Data Name='TargetDomainName'>Sandbox</Data><Data Name='TargetSid'>S-1-5-21-1663667890-2519037288-962558911-1002</Data><Data Name='SubjectUserSid'>S-1-5-21-1663667890-2519037288-962558911-1001</Data><Data Name='SubjectUserName'>solka</Data><Data Name='SubjectDomainName'>SANDBOX</Data><Data Name='SubjectLogonId'>0x12abb7</Data><Data Name='PrivilegeList'>-</Data><Data Name='SamAccountName'>testuser224</Data><Data Name='DisplayName'>%%1793</Data><Data Name='UserPrincipalName'>-</Data><Data Name='HomeDirectory'>%%1793</Data><Data Name='HomePath'>%%1793</Data><Data Name='ScriptPath'>%%1793</Data><Data Name='ProfilePath'>%%1793</Data><Data Name='UserWorkstations'>%%1793</Data><Data Name='PasswordLastSet'>%%1794</Data><Data Name='AccountExpires'>%%1794</Data><Data Name='PrimaryGroupId'>513</Data><Data Name='AllowedToDelegateTo'>-</Data><Data Name='OldUacValue'>0x0</Data><Data Name='NewUacValue'>0x15</Data><Data Name='UserAccountControl'>
		%%2080
		%%2082
		%%2084</Data><Data Name='UserParameters'>%%1793</Data><Data Name='SidHistory'>-</Data><Data Name='LogonHours'>%%1797</Data></EventData></Event>"#;

    #[test]
    fn parses_a_real_shaped_account_created_block() {
        let block = split_event_blocks(ACCOUNT_CREATED_XML)[0];
        let parsed = parse_account_created_block(block).expect("should parse");
        assert_eq!(parsed.record_id, 76327);
        assert_eq!(parsed.pid, 836);
        assert_eq!(parsed.target_user_name.as_deref(), Some("testuser224"));
        // 4720 uses `TargetSid`, not `TargetUserSid` — the parser knows this
        // (see comment on `parse_account_created_block`).
        assert_eq!(
            parsed.target_user_sid.as_deref(),
            Some("S-1-5-21-1663667890-2519037288-962558911-1002")
        );
        assert_eq!(
            parsed.subject_user_sid.as_deref(),
            Some("S-1-5-21-1663667890-2519037288-962558911-1001")
        );
        assert_eq!(parsed.subject_user_name.as_deref(), Some("solka"));
    }

    #[test]
    fn account_created_block_missing_record_id_does_not_parse() {
        let block = "<Event><EventData><Data Name='TargetUserName'>x</Data></EventData></Event>";
        assert!(parse_account_created_block(block).is_none());
    }
}
