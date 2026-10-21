//! # release-tool
//!
//! Offline release tooling for the updater (ADR-0015, ADR-0016): build the manifest
//! of a release directory and sign the manifests the agents verify. Nothing here
//! runs on an endpoint or on the control plane; the server never holds the private
//! key and does not verify signatures, every agent does.
//!
//! ```text
//! release-tool manifest --release-version 3 --dir dist/ --out manifest.json
//! release-tool sign --kind release --key-file release.key manifest.json --out signed.json
//! release-tool roll-forward --from v2.json --release-version 5 --released-at 2026-10-12T09:30:00Z --out v5.json
//! release-tool sign --kind content --key-file release.key v5.json --out v5-signed.json
//! release-tool public-key --key-file release.key
//! ```
//!
//! The key is a file of 64 hex characters (a 32-byte Ed25519 seed). Where the
//! production key lives, who may use it and how it rotates are the open questions
//! of ADR-0015, not decisions this tool makes. `--test-key` signs with the public,
//! checked-in test key for lab and dev releases only.

mod keyfile;
mod manifest_dir;
mod roll_forward;
mod sign;

use std::{io::Write as _, path::PathBuf};

use anyhow::Context as _;
use clap::{Args, Parser, Subcommand};
use ring::signature::Ed25519KeyPair;

#[derive(Parser)]
#[command(
    name = "release-tool",
    about = "Build and sign the manifests the updater verifies"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Hash a directory of release files into an unsigned release manifest.
    Manifest {
        /// The release's `release_version` (strictly greater than the installed one).
        #[arg(long)]
        release_version: u64,
        /// Directory holding the release files (`agent`, `watchdog`, `cli`, ...).
        #[arg(long)]
        dir: PathBuf,
        /// Write here instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Rebuild an earlier content manifest as a newer, unsigned one: the corrective release that
    /// withdraws content from agents that already applied a later release (ADR-0032).
    RollForward {
        /// The earlier content manifest to restore (its signature is dropped).
        #[arg(long)]
        from: PathBuf,
        /// The corrective release's `release_version`: the next number the control plane will assign,
        /// one above the highest release of the ring (rolled-back ones included).
        #[arg(long)]
        release_version: u64,
        /// When it is released, UTC, `YYYY-MM-DDTHH:MM:SSZ`.
        #[arg(long)]
        released_at: String,
        /// The manifest of the release the ring is on now (the one being withdrawn). Optional:
        /// prints what the corrective release removes and which paths need their earlier
        /// bytes put back in the artifact store first.
        #[arg(long)]
        current: Option<PathBuf>,
        /// Write here instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Sign a manifest file.
    Sign {
        /// Which manifest shape the file holds.
        #[arg(long, value_enum)]
        kind: sign::Kind,
        #[command(flatten)]
        key: KeySource,
        /// The manifest to sign.
        manifest: PathBuf,
        /// Write here instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Print the public key (hex) of a signing key: the value to embed in `updater::key`.
    PublicKey {
        #[command(flatten)]
        key: KeySource,
    },
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct KeySource {
    /// File holding the 32-byte Ed25519 seed as 64 hex characters (mode 0600).
    #[arg(long, value_name = "FILE")]
    key_file: Option<PathBuf>,
    /// The public, checked-in test key. Lab and dev releases only: anyone can sign
    /// with it, and a build that embeds it must not be shipped. Exists only in a
    /// `test-key` build (the default).
    #[cfg(feature = "test-key")]
    #[arg(long)]
    test_key: bool,
}

impl KeySource {
    fn load(&self) -> anyhow::Result<Ed25519KeyPair> {
        if let Some(path) = &self.key_file {
            return keyfile::load(path);
        }
        #[cfg(feature = "test-key")]
        {
            eprintln!(
                "warning: signing with the PUBLIC test key; this release is for a lab, not for production"
            );
            Ok(updater::key::test_key_pair())
        }
        #[cfg(not(feature = "test-key"))]
        {
            anyhow::bail!("this build has no test key: pass --key-file")
        }
    }
}

/// What the corrective release does against the release the ring is on, for the operator.
fn report_change(change: &roll_forward::Change, current_version: u64) {
    eprintln!(
        "against release {current_version}: {} unchanged, {} removed from agents, {} brought back",
        change.unchanged,
        change.removed.len(),
        change.brought_back.len()
    );
    for path in &change.removed {
        eprintln!("  removed        {path}");
    }
    for path in &change.brought_back {
        eprintln!(
            "  brought back   {path} (its bytes must be in the artifact store under their hash)"
        );
    }
    if !change.different_bytes.is_empty() {
        eprintln!(
            "{} path(s) hold different bytes in the release being withdrawn — nothing to \
             restore (artifacts are hash-keyed, #804); if publishing below is refused (422, \
             \"not in the store\"), see docs/operations/content.md.",
            change.different_bytes.len()
        );
        for path in &change.different_bytes {
            eprintln!("  different      {path}");
        }
    }
}

fn emit(text: &str, out: Option<&PathBuf>) -> anyhow::Result<()> {
    match out {
        Some(path) => std::fs::write(path, format!("{text}\n"))
            .with_context(|| format!("cannot write {}", path.display())),
        None => {
            writeln!(std::io::stdout(), "{text}")?;
            Ok(())
        }
    }
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Manifest {
            release_version,
            dir,
            out,
        } => {
            let manifest = manifest_dir::build(&dir, release_version)?;
            eprintln!(
                "unsigned release manifest v{release_version}: {} entries",
                manifest.entries.len()
            );
            emit(&serde_json::to_string_pretty(&manifest)?, out.as_ref())
        }
        Command::RollForward {
            from,
            release_version,
            released_at,
            current,
            out,
        } => {
            let text = std::fs::read_to_string(&from)
                .with_context(|| format!("cannot read {}", from.display()))?;
            let manifest = roll_forward::roll_forward(&text, release_version, &released_at)?;
            eprintln!(
                "unsigned corrective content manifest v{release_version} for ring {} ({} entries, \
                 the content of v{}); sign it with `release-tool sign --kind content`",
                manifest.ring,
                manifest.entries.len(),
                serde_json::from_str::<updater::ContentManifest>(&text)
                    .map_or(0, |earlier| earlier.release_version)
            );
            if let Some(current) = current {
                let text = std::fs::read_to_string(&current)
                    .with_context(|| format!("cannot read {}", current.display()))?;
                let now: updater::ContentManifest =
                    serde_json::from_str(&text).context("--current is not a content manifest")?;
                let earlier: updater::ContentManifest = serde_json::from_str(
                    &std::fs::read_to_string(&from)
                        .with_context(|| format!("cannot read {}", from.display()))?,
                )?;
                report_change(&roll_forward::compare(&earlier, &now), now.release_version);
            }
            emit(&serde_json::to_string_pretty(&manifest)?, out.as_ref())
        }
        Command::Sign {
            kind,
            key,
            manifest,
            out,
        } => {
            let key_pair = key.load()?;
            let text = std::fs::read_to_string(&manifest)
                .with_context(|| format!("cannot read {}", manifest.display()))?;
            let signed = sign::sign(kind, &text, &key_pair)?;
            eprintln!("signed {}", signed.summary);
            eprintln!("public key: {}", keyfile::public_key_hex(&key_pair));
            if signed.accepted_by_embedded_key {
                eprintln!("the key embedded in this build of the updater accepts this signature");
            } else {
                eprintln!(
                    "warning: the key embedded in this build of the updater does NOT accept this \
                     signature; agents built with that key will refuse it (embed the public key above first)"
                );
            }
            emit(&signed.json, out.as_ref())
        }
        Command::PublicKey { key } => emit(&keyfile::public_key_hex(&key.load()?), None),
    }
}
