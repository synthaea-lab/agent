//! Surfaces a [`schema::PackageChangeEvent`] as a case-attachable record (issue
//! #87). Not a threat rule: there is no ATT&CK technique for "a package changed
//! version", and this one fires unconditionally — the agent only ever emits the
//! event when `inventory::diff_packages` (Linux, dpkg) actually found a
//! difference, so there is nothing here to filter. The point is visibility ("what
//! changed on this host in the incident window"), the same custom-tag family as
//! `RESPONSE-KILL`/`VERDICT-SUPPRESS` for agent-produced records that are not a
//! detected technique.

use schema::{PackageChangeEvent, PackageChangeKind, detection::Severity};

use crate::Alert;

/// Custom tag (not an ATT&CK technique, see the module doc) for every inventory
/// change record this crate produces. Kept singular/specific rather than a
/// generic `INVENTORY-CHANGE` so a future services/autoruns widening of #87 gets
/// its own tag instead of this one silently covering more ground than its name
/// says.
pub const PACKAGE_CHANGE: &str = "INVENTORY-PACKAGE";

/// Always returns exactly one [`Alert`] — see the module doc for why this is
/// unconditional rather than a filter.
#[must_use]
pub fn evaluate_package_change(event: &PackageChangeEvent) -> Vec<Alert> {
    let message = match event.change {
        PackageChangeKind::Added => format!(
            "package `{}` installed (version {})",
            event.package,
            event.version.as_deref().unwrap_or("unknown")
        ),
        PackageChangeKind::Removed => format!(
            "package `{}` removed (was {})",
            event.package,
            event.previous_version.as_deref().unwrap_or("unknown")
        ),
        PackageChangeKind::Upgraded => format!(
            "package `{}` changed version: {} -> {}",
            event.package,
            event.previous_version.as_deref().unwrap_or("unknown"),
            event.version.as_deref().unwrap_or("unknown")
        ),
    };
    vec![Alert {
        technique: PACKAGE_CHANGE,
        severity: Severity::Low,
        message,
    }]
}

#[cfg(test)]
mod tests {
    use schema::fixtures;

    use super::*;

    fn techniques(event: &PackageChangeEvent) -> Vec<&'static str> {
        evaluate_package_change(event)
            .iter()
            .map(|a| a.technique)
            .collect()
    }

    #[test]
    fn every_change_kind_fires_exactly_one_low_severity_alert() {
        for change in [
            PackageChangeKind::Added,
            PackageChangeKind::Removed,
            PackageChangeKind::Upgraded,
        ] {
            let event = PackageChangeEvent {
                change,
                ..fixtures::package_change()
            };
            let alerts = evaluate_package_change(&event);
            assert_eq!(alerts.len(), 1);
            assert_eq!(alerts[0].technique, PACKAGE_CHANGE);
            assert_eq!(alerts[0].severity, Severity::Low);
        }
    }

    #[test]
    fn the_message_names_the_package_and_the_transition() {
        let added = PackageChangeEvent {
            change: PackageChangeKind::Added,
            previous_version: None,
            version: Some("1.7".into()),
            package: "jq".into(),
            ..fixtures::package_change()
        };
        assert!(techniques(&added).contains(&PACKAGE_CHANGE));
        assert!(evaluate_package_change(&added)[0].message.contains("jq"));
        assert!(
            evaluate_package_change(&added)[0]
                .message
                .contains("installed")
        );

        let removed = PackageChangeEvent {
            change: PackageChangeKind::Removed,
            previous_version: Some("1.7".into()),
            version: None,
            package: "jq".into(),
            ..fixtures::package_change()
        };
        assert!(
            evaluate_package_change(&removed)[0]
                .message
                .contains("removed")
        );

        let upgraded = fixtures::package_change();
        let msg = &evaluate_package_change(&upgraded)[0].message;
        assert!(msg.contains("3.0.13-1"), "{msg}");
        assert!(msg.contains("3.0.15-1"), "{msg}");
    }
}
