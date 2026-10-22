//! Building the unsigned key-rotation manifest (ADR-0027): the operator names the keys, this
//! refuses a manifest the agents would refuse whatever its signature, and `sign --kind rotation`
//! then signs it with the `recovery` key.

use updater::{KeyRotationManifest, rotation::ROTATION_SCHEMA_VERSION};

/// What the operator typed.
pub(crate) struct Request {
    pub(crate) release_version: u64,
    /// The new `release` key and the `release` key it replaces, together or not at all.
    pub(crate) release: Option<(String, String)>,
    /// The same for `content`.
    pub(crate) content: Option<(String, String)>,
    pub(crate) reason: String,
    pub(crate) issued_at: u64,
    pub(crate) valid_for_secs: u64,
}

/// The unsigned manifest for `request`.
///
/// # Errors
///
/// The manifest fails [`KeyRotationManifest::validate`]: no key rotated, a key that is not 64
/// lowercase hex characters, a key replaced by itself, the same new key for both roles, an empty
/// reason, or a validity longer than the maximum.
pub(crate) fn build(request: Request) -> anyhow::Result<KeyRotationManifest> {
    let (new_release_key, retired_release_key) = split(request.release);
    let (new_content_key, retired_content_key) = split(request.content);
    let manifest = KeyRotationManifest {
        expires_at: request.issued_at.saturating_add(request.valid_for_secs),
        issued_at: request.issued_at,
        new_content_key,
        new_release_key,
        reason: request.reason,
        release_version: request.release_version,
        retired_content_key,
        retired_release_key,
        schema_version: ROTATION_SCHEMA_VERSION,
        signature: String::new(),
    };
    manifest.validate()?;
    Ok(manifest)
}

fn split(pair: Option<(String, String)>) -> (Option<String>, Option<String>) {
    match pair {
        Some((new, retired)) => (Some(new), Some(retired)),
        None => (None, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Request {
        Request {
            release_version: 9,
            release: Some(("aa".repeat(32), "bb".repeat(32))),
            content: None,
            reason: "scheduled".into(),
            issued_at: 1_760_000_000,
            valid_for_secs: 7 * 24 * 3600,
        }
    }

    #[test]
    fn a_rotation_of_one_role_is_built_unsigned_with_its_window() {
        let manifest = build(request()).unwrap();
        assert_eq!(manifest.new_release_key, Some("aa".repeat(32)));
        assert_eq!(manifest.retired_release_key, Some("bb".repeat(32)));
        assert_eq!(manifest.new_content_key, None);
        assert_eq!(manifest.expires_at, 1_760_000_000 + 7 * 24 * 3600);
        assert!(manifest.signature.is_empty());
    }

    #[test]
    fn what_the_agents_would_refuse_is_not_built() {
        let mut none = request();
        none.release = None;
        assert!(build(none).is_err(), "no key rotated");

        let mut bad_key = request();
        bad_key.release = Some(("AA".repeat(32), "bb".repeat(32)));
        assert!(build(bad_key).is_err(), "uppercase hex");

        let mut too_long = request();
        too_long.valid_for_secs = 31 * 24 * 3600;
        assert!(build(too_long).is_err(), "window beyond the maximum");

        let mut shared = request();
        shared.content = Some(("aa".repeat(32), "cc".repeat(32)));
        assert!(build(shared).is_err(), "one new key for both roles");
    }
}
