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

    /// Extensions a canary of this kind may carry; the plan picks one per canary.
    const fn extensions(self) -> &'static [&'static str] {
        match self {
            Self::Credentials => &["txt", "csv", "md", "json"],
            Self::Finance => &["csv", "txt", "tsv", "json"],
            Self::Config => &["conf", "ini", "env", "cfg", "yaml"],
            Self::Notes => &["txt", "md", "text"],
        }
    }

    /// The words a name of this kind is built from: what an attacker greps a host for.
    const fn stems(self) -> [&'static str; 16] {
        match self {
            Self::Credentials => [
                "passwords",
                "logins",
                "creds",
                "vpn_access",
                "accounts",
                "secrets",
                "keys",
                "admin_logins",
                "service_accounts",
                "wifi",
                "root_access",
                "tokens",
                "sso",
                "db_credentials",
                "ssh_access",
                "api_keys",
            ],
            Self::Finance => [
                "payroll",
                "budget",
                "invoices",
                "bank_export",
                "salaries",
                "forecast",
                "expenses",
                "ledger",
                "revenue",
                "tax",
                "accounts_payable",
                "transactions",
                "bonuses",
                "audit_prep",
                "cashflow",
                "quarterly",
            ],
            Self::Config => [
                "backup",
                "prod",
                "deploy",
                "infra",
                "staging",
                "ansible",
                "terraform",
                "k8s",
                "database",
                "ci",
                "hosts_prod",
                "firewall",
                "docker",
                "vault",
                "nginx",
                "env",
            ],
            Self::Notes => [
                "notes",
                "todo",
                "meeting",
                "private",
                "ideas",
                "reminders",
                "onboarding",
                "passwords_todo",
                "handover",
                "contacts",
                "plan",
                "minutes",
                "draft",
                "personal",
                "checklist",
                "reading",
            ],
        }
    }
}

/// Words and years a name may carry besides its stem, the way real files pick up versions.
const QUALIFIERS: [&str; 16] = [
    "old", "backup", "final", "new", "copy", "2023", "2024", "2025", "v2", "export", "archive",
    "draft", "shared", "internal", "latest", "orig",
];

const SEPARATORS: [char; 3] = ['_', '-', '.'];

/// The name of one canary, shaped by the seed so no single pattern describes every canary
/// of every install: the stem, the template, the separator, the qualifier, how the
/// random token is written and the extension are each drawn from the seed.
///
/// The token always carries 32 seed-derived bits, however it is written: it keeps two
/// canaries apart and a name unguessable without the seed, and the tripwire's file-name
/// fallback for relative opens relies on it.
fn canary_name(kind: Kind, bits: &[u8; 32]) -> String {
    let stems = kind.stems();
    let stem = stems[usize::from(bits[0]) % stems.len()];
    let qualifier = QUALIFIERS[usize::from(bits[2]) % QUALIFIERS.len()];
    let sep = SEPARATORS[usize::from(bits[9]) % SEPARATORS.len()];
    let value = u32::from_le_bytes([bits[4], bits[5], bits[6], bits[7]]);
    let token = match bits[3] % 4 {
        0 => format!("{value:08x}"),
        1 => format!("{value:08X}"),
        2 => value.to_string(),
        _ => base36(value),
    };
    let base = match bits[1] % 5 {
        0 => format!("{stem}{sep}{token}"),
        1 => format!("{token}{sep}{stem}"),
        2 => format!("{stem}{sep}{qualifier}{sep}{token}"),
        3 => format!("{qualifier}{sep}{stem}{sep}{token}"),
        _ => format!("{stem}{sep}{token}{sep}{qualifier}"),
    };
    let extensions = kind.extensions();
    format!(
        "{base}.{}",
        extensions[usize::from(bits[8]) % extensions.len()]
    )
}

fn base36(mut value: u32) -> String {
    const DIGITS: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    if value == 0 {
        return "0".to_string();
    }
    let mut out = Vec::new();
    while value > 0 {
        out.push(DIGITS[(value % 36) as usize]);
        value /= 36;
    }
    out.reverse();
    String::from_utf8_lossy(&out).into_owned()
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
            let path = placement
                .dir
                .join(canary_name(*kind, &seed.derive("name", index)));
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

    fn names_across_installs(installs: u8) -> Vec<String> {
        (0..installs)
            .flat_map(|i| plan(&Seed::from_bytes([i; 32]), &placements()))
            .map(|c| c.path.file_name().unwrap().to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn no_single_name_pattern_describes_every_install() {
        let old_shape = regex_free_old_shape_matches;
        let names = names_across_installs(200);
        let matching = names.iter().filter(|n| old_shape(n)).count();
        assert!(
            matching * 100 < names.len() * 20,
            "{matching} of {} names still fit stem_hex8.ext",
            names.len()
        );
    }

    /// `^[a-z_]+_[0-9a-f]{8}\.(txt|csv|conf)$`, the first slice's only shape.
    fn regex_free_old_shape_matches(name: &str) -> bool {
        let Some((base, ext)) = name.rsplit_once('.') else {
            return false;
        };
        let Some((stem, token)) = base.rsplit_once('_') else {
            return false;
        };
        ["txt", "csv", "conf"].contains(&ext)
            && !stem.is_empty()
            && stem.chars().all(|c| c.is_ascii_lowercase() || c == '_')
            && token.len() == 8
            && token.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
    }

    /// Seed bytes with every name-shaping byte pinned: stem 0, template 0, qualifier 0,
    /// token style 0, token `0x0000_00ff`, extension 0, separator 0.
    fn pinned() -> [u8; 32] {
        let mut bits = [0u8; 32];
        bits[4] = 0xff;
        bits
    }

    #[test]
    fn the_template_decides_where_stem_qualifier_and_token_sit() {
        let name = |template: u8| {
            let mut bits = pinned();
            bits[1] = template;
            canary_name(Kind::Notes, &bits)
        };
        assert_eq!(name(0), "notes_000000ff.txt");
        assert_eq!(name(1), "000000ff_notes.txt");
        assert_eq!(name(2), "notes_old_000000ff.txt");
        assert_eq!(name(3), "old_notes_000000ff.txt");
        assert_eq!(name(4), "notes_000000ff_old.txt");
    }

    #[test]
    fn the_token_is_written_in_one_of_four_styles_carrying_the_same_value() {
        let name = |style: u8| {
            let mut bits = pinned();
            bits[3] = style;
            canary_name(Kind::Notes, &bits)
        };
        assert_eq!(name(0), "notes_000000ff.txt");
        assert_eq!(name(1), "notes_000000FF.txt");
        assert_eq!(name(2), "notes_255.txt");
        assert_eq!(name(3), "notes_73.txt");
    }

    #[test]
    fn the_separator_and_extension_come_from_the_seed() {
        let name = |sep: u8, ext: u8| {
            let mut bits = pinned();
            bits[9] = sep;
            bits[8] = ext;
            canary_name(Kind::Config, &bits)
        };
        assert_eq!(name(0, 0), "backup_000000ff.conf");
        assert_eq!(name(1, 1), "backup-000000ff.ini");
        assert_eq!(name(2, 2), "backup.000000ff.env");
    }

    #[test]
    fn extensions_vary_across_installs() {
        let extensions: std::collections::HashSet<_> = names_across_installs(200)
            .iter()
            .filter_map(|n| n.rsplit_once('.').map(|(_, e)| e.to_string()))
            .collect();
        assert!(extensions.len() >= 10, "{extensions:?}");
    }

    #[test]
    fn many_canaries_of_one_install_keep_distinct_names() {
        let placements: Vec<Placement> = (0..500)
            .map(|i| Placement {
                dir: PathBuf::from(format!("/srv/d{i}")),
                kinds: Kind::ALL.to_vec(),
            })
            .collect();
        let canaries = plan(&Seed::from_bytes([11; 32]), &placements);
        let names: std::collections::HashSet<_> = canaries
            .iter()
            .map(|c| c.path.file_name().unwrap().to_owned())
            .collect();
        assert_eq!(names.len(), canaries.len());
    }

    #[test]
    fn base36_round_trips() {
        for v in [0u32, 1, 35, 36, 1_295, u32::MAX] {
            assert_eq!(u32::from_str_radix(&base36(v), 36).unwrap(), v);
        }
    }
}
