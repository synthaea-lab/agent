//! Pure credential-redaction helpers shared by the agent and runnable without platform runtimes.
//!
//! Two entry points for a command line, [`redact_command_line`] for one string and
//! [`redact_argv`] for an argument vector, built on one module per kind of secret: `options`
//! (credential flags per tool), `headers`, `url`, `form`, `net` (the Windows `net` command),
//! with `tokens` splitting the line the way its shell would and `secrets` naming the parameters
//! that carry one. `text` redacts free text that may contain a command.

mod argv;
mod cmdline;
pub mod event;
mod form;
mod headers;
mod net;
mod options;
mod secrets;
mod text;
mod tokens;
mod url;

pub use self::{
    argv::redact_argv,
    cmdline::redact_command_line,
    secrets::is_secret_key,
    text::{CommandDialect, redact_command_text},
    url::redact_url_secrets,
};

/// Replacement marker used for every recognized secret value.
pub const REDACTED: &str = "REDACTED";

#[cfg(test)]
mod tests;
