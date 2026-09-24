//! Stages, signs, and promotes a one-file demo release under a given base
//! directory — for manually exercising `agent::integrity`'s live detection path
//! (issue #30/#71) against a real running `agent` process, since ADR-0015's actual
//! download/staging flow ("the agent binary's job") is not built yet. Signs with
//! `updater::key::test_key_pair` — the same test-only key the unit tests use, never
//! a production key — so this only ever produces a manifest the workspace's own
//! `UPDATER_PUBLIC_KEY` accepts.
//!
//! Usage: `cargo run -p updater --example stage_demo_release -- <base_dir>`
//!
//! Linux only, like the rest of `updater::layout` (ADR-0015's Linux-first slice —
//! see that module's doc): the `current` symlink swap this stages is POSIX-shaped,
//! and there is no Windows/macOS layout to demo yet. Compiles to an inert stub
//! elsewhere, same "empty stub outside its platform" posture `updater` itself
//! already has (see CLAUDE.md's platform-code rules) — this file previously had no
//! such gate and failed to compile at all on non-Linux (`layout::Layout` is
//! cfg'd out there, and `std::os::unix::fs::symlink` doesn't exist), breaking any
//! `--all-targets` build on Windows/macOS.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("stage_demo_release: Linux only (ADR-0015's layout is a Linux-first slice)");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
use std::{collections::BTreeMap, env, fs, path::PathBuf};

#[cfg(target_os = "linux")]
use updater::{ReleaseManifest, hash::hash_file, key::test_key_pair, layout::Layout};

#[cfg(target_os = "linux")]
fn main() {
    let base_dir = env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        eprintln!("usage: stage_demo_release <base_dir>");
        std::process::exit(1);
    });

    let layout = Layout::new(&base_dir);
    fs::create_dir_all(layout.bootstrap_dir()).expect("create bootstrap dir");
    fs::create_dir_all(layout.versions_dir()).expect("create versions dir");
    if !layout.current_link().exists() {
        std::os::unix::fs::symlink(layout.bootstrap_dir(), layout.current_link())
            .expect("symlink current -> bootstrap");
    }

    let release_version = layout.current_release_version().map_or(1, |v| v + 1);
    let release_dir = layout.version_dir(release_version);
    fs::create_dir_all(&release_dir).expect("create release dir");
    let protected_file = release_dir.join("agent");
    fs::write(&protected_file, b"the real, unmodified demo agent binary\n")
        .expect("write demo protected file");

    let hash = hash_file(&protected_file).expect("hash demo protected file");
    let mut entries = BTreeMap::new();
    entries.insert(PathBuf::from("agent"), hash);
    let mut manifest = ReleaseManifest::new(release_version, entries);
    manifest.sign(&test_key_pair());
    manifest
        .verify_signature()
        .expect("freshly signed manifest must verify");

    layout
        .verify_staged(&manifest)
        .expect("staged files must verify");
    layout
        .persist_manifest(&manifest)
        .expect("persist manifest");
    layout.promote(release_version).expect("promote release");

    println!(
        "staged and promoted release {release_version} at {}",
        base_dir.display()
    );
    println!("protected file: {}", protected_file.display());
    println!(
        "tamper with it and watch agent::integrity's next check cycle catch it: \
         `echo tampered >> {}`",
        protected_file.display()
    );
}
