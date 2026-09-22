//! Integration test: the committed `data/default-agent.toml` template MUST
//! remain a valid `AgentConfig` after every schema change.
//!
//! Per ADR-0013 §Deferred, the template is a hand-written committed file,
//! not generated from Rust literals. A drift between the schema and the
//! template is exactly the kind of silent misconfig source the ADR wants
//! to prevent — CI catches it here.
//!
//! Runs on Linux only: the committed template carries Linux paths and a
//! Unix domain socket. When we later ship a per-OS template (or a
//! `cli config init`-generated one), a windows-cfg variant of this test
//! will follow.

#![cfg(target_os = "linux")]

use std::path::PathBuf;

#[test]
fn committed_template_still_loads() {
    // CARGO_MANIFEST_DIR is the crate directory at build time; the template
    // lives beside `src/` under `data/`.
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("default-agent.toml");
    assert!(
        path.exists(),
        "committed template `{}` is missing",
        path.display()
    );
    let cfg = config::load_from(&path).unwrap_or_else(|e| {
        panic!(
            "committed template `{}` failed to load: {e}\n\
             This is a drift between the schema and the template — update \
             the template to match the schema, not the other way around.",
            path.display()
        )
    });
    assert_eq!(cfg.schema_version, config::SCHEMA_VERSION);
}
