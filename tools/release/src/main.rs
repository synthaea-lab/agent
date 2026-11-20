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
//! A key rotation (ADR-0027) is signed by the offline `recovery` key and by nothing else:
//!
//! ```text
//! release-tool rotation --release-version 9 --reason "scheduled" \
//!     --new-release-key <hex> --retire-release-key <hex> --out rotation.json
//! release-tool sign --kind rotation --pkcs11 ... rotation.json --out rotation-signed.json
//! ```
//!
//! Production keys sign from a PKCS#11 token (ADR-0027 decision 2): the private key never
//! leaves the device and the tool only sends it the bytes to sign.
//!
//! ```text
//! RELEASE_TOOL_PKCS11_PIN=... release-tool sign --kind release \
//!     --pkcs11 /usr/lib64/pkcs11/opensc-pkcs11.so --pkcs11-token release --pkcs11-key release \
//!     manifest.json --out signed.json
//! ```
//!
//! `--key-file` (a file of 64 hex characters, a 32-byte Ed25519 seed) and `--test-key` (the
//! public, checked-in test key) are for lab and dev releases: a key that can be read from a
//! file is not a production key. Who holds the token and who approves a release are decisions
//! of the owner (ADR-0027), not of this tool.

mod keyfile;
mod manifest_dir;
mod pkcs11;
mod roll_forward;
mod rotation;
mod sign;
mod signer;

use std::{
    io::Write as _,
    path::{Path, PathBuf},
};

use anyhow::Context as _;
use clap::{Args, Parser, Subcommand};

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
    /// Build an unsigned key-rotation manifest: a new `release` and/or `content` key and the key
    /// each replaces, to be signed with the `recovery` key (`sign --kind rotation`).
    Rotation(RotationArgs),
    /// Sign a manifest file.
    Sign {
        /// Which manifest shape the file holds.
        #[arg(long, value_enum)]
        kind: sign::Kind,
        #[command(flatten)]
        key: KeySource,
        #[command(flatten)]
        token: Pkcs11Options,
        /// The manifest to sign.
        manifest: PathBuf,
        /// Write here instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Print the public key (hex) of a signing key: the value to commit under `crates/updater/keys/`.
    PublicKey {
        #[command(flatten)]
        key: KeySource,
        #[command(flatten)]
        token: Pkcs11Options,
    },
}

#[derive(Args)]
struct RotationArgs {
    /// Like any release: strictly greater than the highest release or rotation applied.
    #[arg(long)]
    release_version: u64,
    /// The new `release` key, 64 lowercase hex characters.
    #[arg(long, requires = "retire_release_key")]
    new_release_key: Option<String>,
    /// The `release` key the agents trust now and this replaces.
    #[arg(long, requires = "new_release_key")]
    retire_release_key: Option<String>,
    /// The new `content` key, 64 lowercase hex characters.
    #[arg(long, requires = "retire_content_key")]
    new_content_key: Option<String>,
    /// The `content` key the agents trust now and this replaces.
    #[arg(long, requires = "new_content_key")]
    retire_content_key: Option<String>,
    /// Why, for the audit trail (`scheduled`, `suspected exposure of the release key`, ...).
    #[arg(long)]
    reason: String,
    /// How long the rotation stays applicable after it is issued, in days (at most 30).
    #[arg(long, default_value_t = 7)]
    valid_for_days: u64,
    /// Unix seconds when it is issued; now when absent. Fixed for a reproducible manifest.
    #[arg(long)]
    issued_at: Option<u64>,
    /// Write here instead of stdout.
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct KeySource {
    /// File holding the 32-byte Ed25519 seed as 64 hex characters (mode 0600). Lab and dev
    /// releases: a key in a file is not a production key.
    #[arg(long, value_name = "FILE")]
    key_file: Option<PathBuf>,
    /// The PKCS#11 module (shared library) of the token holding the key: the production way
    /// to sign. Needs `--pkcs11-token` and `--pkcs11-key`; the PIN is read from
    /// `RELEASE_TOOL_PKCS11_PIN` or `--pkcs11-pin-file`.
    #[arg(
        long,
        value_name = "MODULE",
        requires = "pkcs11_token",
        requires = "pkcs11_key"
    )]
    pkcs11: Option<PathBuf>,
    /// The public, checked-in test key. Lab and dev releases only: anyone can sign
    /// with it, and a build that embeds it must not be shipped. Exists only in a
    /// `test-key` build (the default).
    #[cfg(feature = "test-key")]
    #[arg(long)]
    test_key: bool,
    /// The public, checked-in test `recovery` key, for `sign --kind rotation` in a lab. Same
    /// warning as `--test-key`.
    #[cfg(feature = "test-key")]
    #[arg(long)]
    test_recovery_key: bool,
}

/// Where the key is on the token, with `--pkcs11`.
#[derive(Args)]
struct Pkcs11Options {
    /// Label of the token (not the slot number, which changes).
    #[arg(long, value_name = "LABEL", requires = "pkcs11")]
    pkcs11_token: Option<String>,
    /// Label shared by the key's private and public objects on the token.
    #[arg(long, value_name = "LABEL", requires = "pkcs11")]
    pkcs11_key: Option<String>,
    /// File holding the token's user PIN (mode 0600), instead of `RELEASE_TOOL_PKCS11_PIN`.
    #[arg(long, value_name = "FILE", requires = "pkcs11")]
    pkcs11_pin_file: Option<PathBuf>,
}

impl KeySource {
    fn load(&self, token: &Pkcs11Options) -> anyhow::Result<Box<dyn signer::Signer>> {
        if let Some(path) = &self.key_file {
            return Ok(Box::new(signer::FileKey::new(keyfile::load(path)?)));
        }
        if let (Some(module), Some(token_label), Some(key)) =
            (&self.pkcs11, &token.pkcs11_token, &token.pkcs11_key)
        {
            let pin = pkcs11::read_pin(token.pkcs11_pin_file.as_deref())?;
            let location = pkcs11::Location {
                module: module.clone(),
                token: token_label.clone(),
                key: key.clone(),
            };
            return Ok(Box::new(pkcs11::Pkcs11Signer::open(&location, &pin)?));
        }
        #[cfg(feature = "test-key")]
        {
            eprintln!(
                "warning: signing with the PUBLIC test key; this release is for a lab, not for production"
            );
            let key_pair = if self.test_recovery_key {
                updater::key::test_recovery_key_pair()
            } else {
                updater::key::test_key_pair()
            };
            Ok(Box::new(signer::FileKey::new(key_pair)))
        }
        #[cfg(not(feature = "test-key"))]
        {
            anyhow::bail!("this build has no test key: pass --pkcs11 or --key-file")
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

fn emit(text: &str, out: Option<&Path>) -> anyhow::Result<()> {
    match out {
        Some(path) => std::fs::write(path, format!("{text}\n"))
            .with_context(|| format!("cannot write {}", path.display())),
        None => {
            writeln!(std::io::stdout(), "{text}")?;
            Ok(())
        }
    }
}

fn cmd_manifest(release_version: u64, dir: &Path, out: Option<&Path>) -> anyhow::Result<()> {
    let manifest = manifest_dir::build(dir, release_version)?;
    eprintln!(
        "unsigned release manifest v{release_version}: {} entries",
        manifest.entries.len()
    );
    emit(&serde_json::to_string_pretty(&manifest)?, out)
}

fn cmd_roll_forward(
    from: &Path,
    release_version: u64,
    released_at: &str,
    current: Option<&Path>,
    out: Option<&Path>,
) -> anyhow::Result<()> {
    let text =
        std::fs::read_to_string(from).with_context(|| format!("cannot read {}", from.display()))?;
    let manifest = roll_forward::roll_forward(&text, release_version, released_at)?;
    eprintln!(
        "unsigned corrective content manifest v{release_version} for ring {} ({} entries, \
         the content of v{}); sign it with `release-tool sign --kind content`",
        manifest.ring,
        manifest.entries.len(),
        serde_json::from_str::<updater::ContentManifest>(&text)
            .map_or(0, |earlier| earlier.release_version)
    );
    if let Some(current) = current {
        let text = std::fs::read_to_string(current)
            .with_context(|| format!("cannot read {}", current.display()))?;
        let now: updater::ContentManifest =
            serde_json::from_str(&text).context("--current is not a content manifest")?;
        let earlier: updater::ContentManifest = serde_json::from_str(
            &std::fs::read_to_string(from)
                .with_context(|| format!("cannot read {}", from.display()))?,
        )?;
        report_change(&roll_forward::compare(&earlier, &now), now.release_version);
    }
    emit(&serde_json::to_string_pretty(&manifest)?, out)
}

fn cmd_rotation(args: RotationArgs) -> anyhow::Result<()> {
    let RotationArgs {
        release_version,
        new_release_key,
        retire_release_key,
        new_content_key,
        retire_content_key,
        reason,
        valid_for_days,
        issued_at,
        out,
    } = args;
    let issued_at = match issued_at {
        Some(at) => at,
        None => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("the clock is before 1970")?
            .as_secs(),
    };
    let manifest = rotation::build(rotation::Request {
        release_version,
        release: new_release_key.zip(retire_release_key),
        content: new_content_key.zip(retire_content_key),
        reason,
        issued_at,
        valid_for_secs: valid_for_days.saturating_mul(24 * 60 * 60),
    })?;
    eprintln!(
        "unsigned key rotation v{release_version}, valid until {}; sign it with the \
         recovery key: `release-tool sign --kind rotation`",
        manifest.expires_at
    );
    for (role, retired, new) in [
        (
            "release",
            &manifest.retired_release_key,
            &manifest.new_release_key,
        ),
        (
            "content",
            &manifest.retired_content_key,
            &manifest.new_content_key,
        ),
    ] {
        if let (Some(retired), Some(new)) = (retired, new) {
            eprintln!("  {role}: {retired} (retired) -> {new} (new)");
        }
    }
    emit(&serde_json::to_string_pretty(&manifest)?, out.as_deref())
}

fn cmd_sign(
    kind: sign::Kind,
    key: &KeySource,
    token: &Pkcs11Options,
    manifest: &Path,
    out: Option<&Path>,
) -> anyhow::Result<()> {
    let signer = key.load(token)?;
    let text = std::fs::read_to_string(manifest)
        .with_context(|| format!("cannot read {}", manifest.display()))?;
    let signed = sign::sign(kind, &text, signer.as_ref())?;
    eprintln!("signed {}", signed.summary);
    eprintln!("public key: {}", signer::public_key_hex(signer.as_ref()));
    if signed.accepted_by_embedded_key {
        eprintln!("the key embedded in this build of the updater accepts this signature");
    } else {
        eprintln!(
            "warning: the key embedded in this build of the updater does NOT accept this \
             signature; agents built with that key will refuse it (embed the public key above first)"
        );
    }
    emit(&signed.json, out)
}

fn cmd_public_key(key: &KeySource, token: &Pkcs11Options) -> anyhow::Result<()> {
    emit(&signer::public_key_hex(key.load(token)?.as_ref()), None)
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Manifest {
            release_version,
            dir,
            out,
        } => cmd_manifest(release_version, &dir, out.as_deref()),
        Command::RollForward {
            from,
            release_version,
            released_at,
            current,
            out,
        } => cmd_roll_forward(
            &from,
            release_version,
            &released_at,
            current.as_deref(),
            out.as_deref(),
        ),
        Command::Rotation(args) => cmd_rotation(args),
        Command::Sign {
            kind,
            key,
            token,
            manifest,
            out,
        } => cmd_sign(kind, &key, &token, &manifest, out.as_deref()),
        Command::PublicKey { key, token } => cmd_public_key(&key, &token),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("release-tool").chain(args.iter().copied()))
    }

    fn rejected(args: &[&str]) -> clap::error::ErrorKind {
        match parse(args) {
            Ok(_) => panic!("{args:?} must not parse"),
            Err(error) => error.kind(),
        }
    }

    #[test]
    fn manifest_takes_a_version_a_directory_and_an_optional_out() {
        let Ok(Cli {
            command:
                Command::Manifest {
                    release_version,
                    dir,
                    out,
                },
        }) = parse(&["manifest", "--release-version", "3", "--dir", "dist"])
        else {
            panic!("manifest did not parse");
        };
        assert_eq!(release_version, 3);
        assert_eq!(dir, PathBuf::from("dist"));
        assert_eq!(out, None);
        assert_eq!(
            rejected(&["manifest", "--dir", "dist"]),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn roll_forward_takes_the_earlier_manifest_and_an_optional_current() {
        let Ok(Cli {
            command:
                Command::RollForward {
                    from,
                    release_version,
                    released_at,
                    current,
                    out,
                },
        }) = parse(&[
            "roll-forward",
            "--from",
            "v2.json",
            "--release-version",
            "5",
            "--released-at",
            "2026-10-12T09:30:00Z",
            "--current",
            "v4.json",
            "--out",
            "v5.json",
        ])
        else {
            panic!("roll-forward did not parse");
        };
        assert_eq!(from, PathBuf::from("v2.json"));
        assert_eq!(release_version, 5);
        assert_eq!(released_at, "2026-10-12T09:30:00Z");
        assert_eq!(current, Some(PathBuf::from("v4.json")));
        assert_eq!(out, Some(PathBuf::from("v5.json")));
        assert_eq!(
            rejected(&[
                "roll-forward",
                "--from",
                "v2.json",
                "--release-version",
                "5"
            ]),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn rotation_defaults_to_seven_days_and_needs_its_keys_in_pairs() {
        let hex = "a".repeat(64);
        let Ok(Cli {
            command:
                Command::Rotation(RotationArgs {
                    valid_for_days,
                    issued_at,
                    new_release_key,
                    retire_release_key,
                    new_content_key,
                    ..
                }),
        }) = parse(&[
            "rotation",
            "--release-version",
            "9",
            "--reason",
            "scheduled",
            "--new-release-key",
            &hex,
            "--retire-release-key",
            &hex,
        ])
        else {
            panic!("rotation did not parse");
        };
        assert_eq!(valid_for_days, 7);
        assert_eq!(issued_at, None);
        assert_eq!(new_release_key.as_deref(), Some(hex.as_str()));
        assert_eq!(retire_release_key.as_deref(), Some(hex.as_str()));
        assert_eq!(new_content_key, None);

        // A new key without the key it replaces (and the reverse) is refused.
        for lone in [
            "--new-release-key",
            "--retire-release-key",
            "--new-content-key",
        ] {
            assert_eq!(
                rejected(&[
                    "rotation",
                    "--release-version",
                    "9",
                    "--reason",
                    "x",
                    lone,
                    &hex
                ]),
                clap::error::ErrorKind::MissingRequiredArgument,
                "{lone}"
            );
        }
        assert_eq!(
            rejected(&["rotation", "--release-version", "9"]),
            clap::error::ErrorKind::MissingRequiredArgument,
            "a reason is required"
        );
    }

    #[test]
    fn sign_needs_a_kind_a_key_source_and_a_manifest() {
        let Ok(Cli {
            command:
                Command::Sign {
                    kind,
                    key,
                    manifest,
                    out,
                    ..
                },
        }) = parse(&[
            "sign",
            "--kind",
            "release",
            "--key-file",
            "release.key",
            "manifest.json",
        ])
        else {
            panic!("sign did not parse");
        };
        assert!(matches!(kind, sign::Kind::Release));
        assert_eq!(key.key_file, Some(PathBuf::from("release.key")));
        assert_eq!(manifest, PathBuf::from("manifest.json"));
        assert_eq!(out, None);

        for kind in ["release", "content", "rotation"] {
            assert!(
                parse(&["sign", "--kind", kind, "--key-file", "k", "m.json"]).is_ok(),
                "{kind}"
            );
        }
        assert_eq!(
            rejected(&["sign", "--kind", "release", "m.json"]),
            clap::error::ErrorKind::MissingRequiredArgument,
            "no key source"
        );
        assert_eq!(
            rejected(&["sign", "--key-file", "k", "m.json"]),
            clap::error::ErrorKind::MissingRequiredArgument,
            "no kind"
        );
        assert_eq!(
            rejected(&["sign", "--kind", "release", "--key-file", "k"]),
            clap::error::ErrorKind::MissingRequiredArgument,
            "no manifest"
        );
        assert_eq!(
            rejected(&["sign", "--kind", "nonsense", "--key-file", "k", "m.json"]),
            clap::error::ErrorKind::InvalidValue
        );
    }

    #[test]
    fn two_key_sources_are_refused() {
        assert_eq!(
            rejected(&[
                "public-key",
                "--key-file",
                "k",
                "--pkcs11",
                "m.so",
                "--pkcs11-token",
                "t",
                "--pkcs11-key",
                "k"
            ]),
            clap::error::ErrorKind::ArgumentConflict
        );
    }

    #[test]
    fn a_token_needs_its_module_and_a_module_needs_the_token_and_key_labels() {
        let Ok(Cli {
            command: Command::PublicKey { key, token },
        }) = parse(&[
            "public-key",
            "--pkcs11",
            "/usr/lib64/pkcs11/opensc-pkcs11.so",
            "--pkcs11-token",
            "release",
            "--pkcs11-key",
            "release",
            "--pkcs11-pin-file",
            "pin",
        ])
        else {
            panic!("public-key --pkcs11 did not parse");
        };
        assert_eq!(
            key.pkcs11,
            Some(PathBuf::from("/usr/lib64/pkcs11/opensc-pkcs11.so"))
        );
        assert_eq!(token.pkcs11_token.as_deref(), Some("release"));
        assert_eq!(token.pkcs11_key.as_deref(), Some("release"));
        assert_eq!(token.pkcs11_pin_file, Some(PathBuf::from("pin")));

        assert_eq!(
            rejected(&["public-key", "--pkcs11", "m.so", "--pkcs11-token", "t"]),
            clap::error::ErrorKind::MissingRequiredArgument,
            "no key label"
        );
        assert_eq!(
            rejected(&["public-key", "--key-file", "k", "--pkcs11-token", "t"]),
            clap::error::ErrorKind::MissingRequiredArgument,
            "a token label without --pkcs11"
        );
    }

    #[cfg(feature = "test-key")]
    #[test]
    fn the_test_keys_are_a_key_source_of_their_own() {
        for flag in ["--test-key", "--test-recovery-key"] {
            assert!(parse(&["public-key", flag]).is_ok(), "{flag}");
        }
        assert_eq!(
            rejected(&["public-key", "--test-key", "--key-file", "k"]),
            clap::error::ErrorKind::ArgumentConflict
        );
    }

    #[test]
    fn a_subcommand_is_required() {
        assert_eq!(
            rejected(&[]),
            clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        );
    }
}
