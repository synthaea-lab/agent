//! Seed-derived canary plans: which decoy files go where, with which names and contents.
//!
//! Everything here is pure and deterministic in the install's [`Seed`]: the same seed
//! and placements give the same plan, a different seed gives different names and
//! different contents, so a decoy list learned from one host does not describe another.

use std::{fmt, path::PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The per-install secret every decoy is derived from. Generated once per install by the
/// caller and kept in the agent's state directory; never logged.
#[derive(Clone, PartialEq, Eq)]
pub struct Seed([u8; 32]);

impl Seed {
    /// Wraps 32 bytes of install-unique randomness.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw bytes, for persisting the seed.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// 32 bytes derived from the seed, a label and an index: SHA-256 over the three.
    fn derive(&self, label: &str, index: usize) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(self.0);
        hash.update(label.as_bytes());
        hash.update((index as u64).to_le_bytes());
        hash.finalize().into()
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Seed(<redacted>)")
    }
}

/// What a canary pretends to be: the shapes attackers grep a host for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// A list of logins.
    Credentials,
    /// A financial export.
    Finance,
    /// A deployment or infrastructure config.
    Config,
    /// Personal notes.
    Notes,
}

impl Kind {
    /// Every kind, in a fixed order.
    pub const ALL: [Self; 4] = [Self::Credentials, Self::Finance, Self::Config, Self::Notes];

    const fn extension(self) -> &'static str {
        match self {
            Self::Credentials | Self::Notes => "txt",
            Self::Finance => "csv",
            Self::Config => "conf",
        }
    }

    const fn stems(self) -> [&'static str; 4] {
        match self {
            Self::Credentials => ["passwords", "logins", "creds", "vpn_access"],
            Self::Finance => ["payroll", "budget", "invoices", "bank_export"],
            Self::Config => ["backup", "prod", "deploy", "infra"],
            Self::Notes => ["notes", "todo", "meeting", "private"],
        }
    }
}

/// A directory the caller chose, and the kinds of canary to plant in it. The caller
/// picks directories (an operator's decision, not the crate's): a canary belongs where
/// nothing legitimate reads it, never where users work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placement {
    /// An existing directory.
    pub dir: PathBuf,
    /// One canary per listed kind.
    pub kinds: Vec<Kind>,
}

/// One planned decoy file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Canary {
    /// Where the file goes.
    pub path: PathBuf,
    /// What it pretends to be.
    pub kind: Kind,
    /// Its inert, machine-generated content.
    pub content: String,
}

/// The header every canary starts with, so an operator who opens one knows what it is.
pub const DECOY_HEADER: &str =
    "# SYNTHAEA DECOY: machine-generated, inert, no real credentials. Safe to delete.";

/// Plans one canary per placement and kind, named and filled from `seed`.
#[must_use]
pub fn plan(seed: &Seed, placements: &[Placement]) -> Vec<Canary> {
    let mut canaries = Vec::new();
    for (p, placement) in placements.iter().enumerate() {
        for (k, kind) in placement.kinds.iter().enumerate() {
            let index = p * Kind::ALL.len() + k;
            let name_bits = seed.derive("name", index);
            let stems = kind.stems();
            let stem = stems[usize::from(name_bits[0]) % stems.len()];
            // 4 hex bytes after the stem keep two canaries in one directory apart and make
            // a name unguessable without the seed.
            let suffix = hex(&name_bits[1..5]);
            let path = placement
                .dir
                .join(format!("{stem}_{suffix}.{}", kind.extension()));
            canaries.push(Canary {
                path,
                kind: *kind,
                content: content(seed, index, *kind),
            });
        }
    }
    canaries
}

fn content(seed: &Seed, index: usize, kind: Kind) -> String {
    let mut text = format!("{DECOY_HEADER}\n");
    for row in 0..6 {
        let bits = seed.derive(&format!("row{row}"), index);
        let (a, b) = (hex(&bits[..4]), hex(&bits[4..12]));
        let line = match kind {
            Kind::Credentials => format!("svc-{a} : {b}\n"),
            Kind::Finance => format!("{a},{b},{}\n", u32::from(bits[12]) * 100),
            Kind::Config => format!("host-{a}.internal = {b}\n"),
            Kind::Notes => format!("{a}: {b}\n"),
        };
        text.push_str(&line);
    }
    text
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn placements() -> Vec<Placement> {
        vec![
            Placement {
                dir: PathBuf::from("/srv/share"),
                kinds: Kind::ALL.to_vec(),
            },
            Placement {
                dir: PathBuf::from("/home/ops"),
                kinds: vec![Kind::Credentials],
            },
        ]
    }

    #[test]
    fn the_same_seed_gives_the_same_plan() {
        let seed = Seed::from_bytes([7; 32]);
        assert_eq!(plan(&seed, &placements()), plan(&seed, &placements()));
    }

    #[test]
    fn two_installs_get_different_names_and_contents() {
        let a = plan(&Seed::from_bytes([1; 32]), &placements());
        let b = plan(&Seed::from_bytes([2; 32]), &placements());
        assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(&b) {
            assert_ne!(
                x.path, y.path,
                "a name learned on one host must not describe another"
            );
            assert_ne!(x.content, y.content);
        }
    }

    #[test]
    fn a_plan_has_one_canary_per_placement_and_kind_with_distinct_paths() {
        let canaries = plan(&Seed::from_bytes([3; 32]), &placements());
        assert_eq!(canaries.len(), 5);
        let mut paths: Vec<_> = canaries.iter().map(|c| &c.path).collect();
        paths.sort();
        paths.dedup();
        assert_eq!(paths.len(), 5);
        for c in &canaries {
            assert!(c.path.extension().is_some());
        }
    }

    #[test]
    fn every_canary_says_it_is_a_decoy() {
        for c in plan(&Seed::from_bytes([4; 32]), &placements()) {
            assert!(c.content.starts_with(DECOY_HEADER));
        }
    }

    #[test]
    fn the_seed_is_never_printed() {
        assert_eq!(
            format!("{:?}", Seed::from_bytes([9; 32])),
            "Seed(<redacted>)"
        );
    }
}
