//! One parser per Event Log record shape; each returns `None` rather than guess when the
//! block lacks its `EventRecordID`.

pub(super) mod account;
pub(super) mod applocker;
pub(super) mod code_integrity;
pub(super) mod defender;
pub(super) mod kerberos;
pub(super) mod log_cleared;
pub(super) mod logon;
pub(super) mod service;
pub(super) mod session;
pub(super) mod task;
pub(super) mod task_definition;
