//! Uprobe handlers: userspace attaches them (`sensor-linux-uprobes`) after resolving the
//! library symbols, so these programs only carry the per-call logic.

mod getaddrinfo;
mod readline;
mod tls;
