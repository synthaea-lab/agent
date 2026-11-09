//! Signing with a key held on a PKCS#11 token (ADR-0027 decision 2): a PIV token or an HSM,
//! through the vendor's module (`opensc-pkcs11.so`, `libsofthsm2.so` for tests, an HSM client).
//!
//! The private key stays on the device (`CKA_SENSITIVE`, not extractable): the tool sends the
//! canonical manifest bytes to the token and gets the Ed25519 signature back (`CKM_EDDSA`, pure
//! Ed25519). The public key comes from the token's public key object with the same label, so
//! `release-tool public-key` prints the value to commit under `crates/updater/keys/`.
//!
//! The PIN is never an argument (it would show in `ps` and shell history): it is read from the
//! environment ([`PIN_ENV`]) or from a file only the owner can read.

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::{
        Mechanism,
        eddsa::{EddsaParams, EddsaSignatureScheme},
    },
    object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle},
    session::{Session, UserType},
    types::AuthPin,
};

use crate::signer::Signer;

/// Environment variable holding the user PIN of the token.
pub(crate) const PIN_ENV: &str = "RELEASE_TOOL_PKCS11_PIN";

/// Where the key is: which module, which token, which key object.
pub(crate) struct Location {
    /// The PKCS#11 module (a shared library).
    pub(crate) module: PathBuf,
    /// The token's label (`CKA_LABEL` of the token, not the slot number: slots are renumbered).
    pub(crate) token: String,
    /// The label shared by the private key and its public key object.
    pub(crate) key: String,
}

/// An Ed25519 key on a token, logged in for this process.
pub(crate) struct Pkcs11Signer {
    // Both are taken by `Drop`: the session logs out and closes before the module is finalised.
    session: Option<Session>,
    module: Option<Pkcs11>,
    key: ObjectHandle,
    public: [u8; 32],
}

impl Pkcs11Signer {
    /// Opens the module, finds the token by label, logs in as the user and locates the key.
    ///
    /// # Errors
    ///
    /// The module cannot be loaded, no token or several tokens carry the label, the PIN is
    /// refused, or there is not exactly one Ed25519 private key and one public key with that
    /// label.
    pub(crate) fn open(location: &Location, pin: &str) -> anyhow::Result<Self> {
        let module = Pkcs11::new(&location.module).with_context(|| {
            format!(
                "cannot load the PKCS#11 module {}",
                location.module.display()
            )
        })?;
        module
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .context("cannot initialise the PKCS#11 module")?;

        let mut slots = Vec::new();
        for slot in module.get_slots_with_token()? {
            if module.get_token_info(slot)?.label().trim_end() == location.token {
                slots.push(slot);
            }
        }
        let slot = match slots.as_slice() {
            [slot] => *slot,
            [] => anyhow::bail!("no token labelled {:?} is present", location.token),
            _ => anyhow::bail!(
                "{} tokens are labelled {:?}: refusing to guess which one signs",
                slots.len(),
                location.token
            ),
        };
        let session = module.open_ro_session(slot)?;
        session
            .login(UserType::User, Some(&AuthPin::new(pin.into())))
            .context("the token refused the PIN")?;

        let key = single(
            &session,
            &[
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::KeyType(KeyType::EC_EDWARDS),
                Attribute::Label(location.key.clone().into_bytes()),
            ],
            "Ed25519 private key",
            &location.key,
        )?;
        let public_object = single(
            &session,
            &[
                Attribute::Class(ObjectClass::PUBLIC_KEY),
                Attribute::KeyType(KeyType::EC_EDWARDS),
                Attribute::Label(location.key.clone().into_bytes()),
            ],
            "Ed25519 public key",
            &location.key,
        )?;
        let attributes = session.get_attributes(public_object, &[AttributeType::EcPoint])?;
        let point = attributes
            .into_iter()
            .find_map(|a| match a {
                Attribute::EcPoint(point) => Some(point),
                _ => None,
            })
            .context("the public key object has no CKA_EC_POINT")?;
        Ok(Self {
            session: Some(session),
            module: Some(module),
            key,
            public: ed25519_public_key(&point)?,
        })
    }
}

impl Drop for Pkcs11Signer {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            // Best effort: the process is ending, and a token that fails to log out is no worse
            // off than one whose process died.
            let _ = session.logout();
        }
        if let Some(module) = self.module.take() {
            let _ = module.finalize();
        }
    }
}

impl Signer for Pkcs11Signer {
    fn public_key(&self) -> Vec<u8> {
        self.public.to_vec()
    }

    fn sign(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        let session = self
            .session
            .as_ref()
            .context("the token session is closed")?;
        session
            .sign(
                &Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure)),
                self.key,
                message,
            )
            .context(
                "the token could not sign (is it still plugged in, does the key allow signing?)",
            )
    }
}

/// The one object matching `template`.
fn single(
    session: &Session,
    template: &[Attribute],
    what: &str,
    label: &str,
) -> anyhow::Result<ObjectHandle> {
    let found = session.find_objects(template)?;
    match found.as_slice() {
        [object] => Ok(*object),
        [] => anyhow::bail!("the token has no {what} labelled {label:?}"),
        _ => anyhow::bail!(
            "the token has {} {what}s labelled {label:?}: refusing to guess which one signs",
            found.len()
        ),
    }
}

/// The 32 key bytes of a `CKA_EC_POINT`: a DER OCTET STRING (`04 20 <32 bytes>`) as PKCS#11 3.0
/// requires, or the bare 32 bytes some older modules return.
fn ed25519_public_key(point: &[u8]) -> anyhow::Result<[u8; 32]> {
    let bytes = match point {
        [0x04, 0x20, rest @ ..] if rest.len() == 32 => rest,
        raw if raw.len() == 32 => raw,
        other => anyhow::bail!(
            "the public key point is {} bytes, not an Ed25519 key (32 bytes, or 34 DER-wrapped)",
            other.len()
        ),
    };
    <[u8; 32]>::try_from(bytes).context("the public key is not 32 bytes")
}

/// Reads the PIN from [`PIN_ENV`], or from `file` (mode 0600 on Unix, one line).
///
/// # Errors
///
/// Neither is given, both are given, the file is unreadable or readable by others, or the PIN is
/// empty.
pub(crate) fn read_pin(file: Option<&Path>) -> anyhow::Result<String> {
    read_pin_from(std::env::var(PIN_ENV).ok(), file)
}

fn read_pin_from(env: Option<String>, file: Option<&Path>) -> anyhow::Result<String> {
    let pin = match (env, file) {
        (Some(_), Some(_)) => {
            anyhow::bail!("give the PIN in {PIN_ENV} or with --pkcs11-pin-file, not both")
        }
        (Some(pin), None) => pin,
        (None, Some(path)) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let mode = std::fs::metadata(path)
                    .with_context(|| format!("cannot read {}", path.display()))?
                    .permissions()
                    .mode();
                if mode & 0o077 != 0 {
                    anyhow::bail!(
                        "{} is readable by group or others (mode {:o}); run `chmod 600` on it",
                        path.display(),
                        mode & 0o777
                    );
                }
            }
            std::fs::read_to_string(path)
                .with_context(|| format!("cannot read {}", path.display()))?
        }
        (None, None) => {
            anyhow::bail!("the token PIN is needed: set {PIN_ENV} or pass --pkcs11-pin-file")
        }
    };
    let pin = pin.trim_end_matches(['\r', '\n']).to_owned();
    anyhow::ensure!(!pin.is_empty(), "the token PIN is empty");
    Ok(pin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_der_wrapped_or_bare_point_gives_the_32_key_bytes() {
        let key = [9u8; 32];
        let mut wrapped = vec![0x04, 0x20];
        wrapped.extend_from_slice(&key);
        assert_eq!(ed25519_public_key(&wrapped).unwrap(), key);
        assert_eq!(ed25519_public_key(&key).unwrap(), key);
    }

    #[test]
    fn any_other_point_is_refused() {
        for point in [&[][..], &[0x04, 0x20][..], &[1u8; 31][..], &[1u8; 65][..]] {
            assert!(ed25519_public_key(point).is_err(), "{} bytes", point.len());
        }
    }

    #[test]
    fn the_pin_comes_from_the_environment_or_a_private_file_and_never_both() {
        assert_eq!(read_pin_from(Some("1234\n".into()), None).unwrap(), "1234");
        assert!(read_pin_from(None, None).is_err());
        assert!(read_pin_from(Some(String::new()), None).is_err());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pin");
        std::fs::write(&path, "4321\n").unwrap();
        assert!(read_pin_from(Some("1".into()), Some(&path)).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            let err = read_pin_from(None, Some(&path)).unwrap_err().to_string();
            assert!(err.contains("readable by group or others"), "{err}");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(read_pin_from(None, Some(&path)).unwrap(), "4321");
    }
}
