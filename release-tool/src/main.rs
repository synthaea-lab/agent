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
//! release-tool public-key --key-file release.key
//! ```
//!
//! The key is a file of 64 hex characters (a 32-byte Ed25519 seed). Where the
//! production key lives, who may use it and how it rotates are the open questions
//! of ADR-0015, not decisions this tool makes. `--test-key` signs with the public,
//! checked-in test key for lab and dev releases only.

mod keyfile;
mod manifest_dir;
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
