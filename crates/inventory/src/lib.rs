//! # inventory
//!
//! Periodic, diffed asset inventory per host — the substrate several features
//! quietly assume: installed packages (dpkg/rpm on Linux, MSI/Store on Windows,
//! pkg receipts + apps on macOS), enabled services/daemons, autoruns/persistence
//! points, listening ports, local users/groups.
//!
//! Principles: snapshots are DIFFED on-device and only changes ship (an inventory
//! that re-uploads itself hourly is telemetry spam); every record is timestamped
//! and case-attachable ("what changed on this host in the incident window" is the
//! DFIR question); server side lands in the entity graph and prevalence ("how many
//! hosts run this package/service"), and gives cases vulnerability CONTEXT via
//! version facts — without becoming vulnerability management (a recorded non-goal).
