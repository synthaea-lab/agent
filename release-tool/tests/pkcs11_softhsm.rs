//! `release-tool` signing from a PKCS#11 token, end to end against `SoftHSM`: no real key, a
//! software token created here. Needs the `SoftHSM` module and a `SOFTHSM2_CONF` whose token
//! directory is private to the run: `tools/test-pkcs11.sh` sets both up and runs this test
//! (CI does the same). Without them the test skips; with `SYNTHAEA_REQUIRE_PKCS11_TESTS=1`
//! (CI, the script) a skip is a failure, so a green run means the token path really ran.

use std::{path::Path, process::Command};

use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::Mechanism,
    object::{Attribute, KeyType},
    session::UserType,
    types::AuthPin,
};
use ring::signature::{ED25519, UnparsedPublicKey};

const SO_PIN: &str = "so-pin-0000";
const PIN: &str = "user-pin-1111";
const TOKEN: &str = "release-test";
const KEY: &str = "release";
/// DER of the curve OID 1.3.101.112 (`edwards25519`), the `CKA_EC_PARAMS` of an Ed25519 key.
const ED25519_EC_PARAMS: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];

const MANIFEST: &str =
    r#"{"entries":{"agent":"00"},"release_version":3,"schema_version":1,"signature":""}"#;

/// The module and configuration, or `None` when the test is allowed to skip.
fn softhsm() -> Option<String> {
    let module = std::env::var("RELEASE_TOOL_SOFTHSM_MODULE").ok();
    if module.is_some() && std::env::var_os("SOFTHSM2_CONF").is_some() {
        return module;
    }
    assert!(
        std::env::var_os("SYNTHAEA_REQUIRE_PKCS11_TESTS").is_none(),
        "SYNTHAEA_REQUIRE_PKCS11_TESTS is set but RELEASE_TOOL_SOFTHSM_MODULE or SOFTHSM2_CONF is not: \
         run tools/test-pkcs11.sh"
    );
    eprintln!("skipped: no SoftHSM (run tools/test-pkcs11.sh)");
    None
}

/// Initialises the free token, sets the user PIN and generates one Ed25519 key pair labelled
/// [`KEY`]; returns the public key bytes. The module is finalised on return, so the binary under
/// test can load it in its own process.
fn provision(module: &str) -> [u8; 32] {
    let ctx = Pkcs11::new(module).unwrap();
    ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .unwrap();
    let so_pin = AuthPin::new(SO_PIN.into());
    let pin = AuthPin::new(PIN.into());

    let free = ctx
        .get_slots_with_token()
        .unwrap()
        .into_iter()
        .find(|slot| !ctx.get_token_info(*slot).unwrap().token_initialized())
        .expect("SoftHSM keeps one free token slot");
    ctx.init_token(free, &so_pin, TOKEN).unwrap();
    let session = open_token(&ctx);
    session.login(UserType::So, Some(&so_pin)).unwrap();
    session.init_pin(&pin).unwrap();
    session.logout().unwrap();
    session.login(UserType::User, Some(&pin)).unwrap();
    let public = generate_key(&session);
    drop(session);
    ctx.finalize().unwrap();
    public
}

/// A read-write session on the token labelled [`TOKEN`]. The slot is renumbered when the token
/// is initialised, so it is looked up by label.
fn open_token(ctx: &Pkcs11) -> cryptoki::session::Session {
    let slot = ctx
        .get_slots_with_token()
        .unwrap()
        .into_iter()
        .find(|slot| ctx.get_token_info(*slot).unwrap().label().trim_end() == TOKEN)
        .expect("the initialised token");
    ctx.open_rw_session(slot).unwrap()
}

/// Adds a second key pair with the same label as the first: the tool must then refuse to guess.
fn add_duplicate_key(module: &str) {
    let ctx = Pkcs11::new(module).unwrap();
    ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .unwrap();
    let session = open_token(&ctx);
    session
        .login(UserType::User, Some(&AuthPin::new(PIN.into())))
        .unwrap();
    generate_key(&session);
    drop(session);
    ctx.finalize().unwrap();
}

fn generate_key(session: &cryptoki::session::Session) -> [u8; 32] {
    let (public_object, _private) = session
        .generate_key_pair(
            &Mechanism::EccEdwardsKeyPairGen,
            &[
                Attribute::Token(true),
                Attribute::Verify(true),
                Attribute::KeyType(KeyType::EC_EDWARDS),
                Attribute::EcParams(ED25519_EC_PARAMS.to_vec()),
                Attribute::Label(KEY.as_bytes().to_vec()),
            ],
            &[
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Sign(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Label(KEY.as_bytes().to_vec()),
            ],
        )
        .unwrap();
    let point = session
        .get_attributes(public_object, &[cryptoki::object::AttributeType::EcPoint])
        .unwrap()
        .into_iter()
        .find_map(|a| match a {
            Attribute::EcPoint(point) => Some(point),
            _ => None,
        })
        .unwrap();
    let mut public = [0u8; 32];
    public.copy_from_slice(&point[point.len() - 32..]);
    public
}

fn release_tool(module: &str, args: &[&str], pin: Option<&str>) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_release-tool"));
    command
        .args(args)
        .args(["--pkcs11", module])
        .env_remove("RELEASE_TOOL_PKCS11_PIN");
    if let Some(pin) = pin {
        command.env("RELEASE_TOOL_PKCS11_PIN", pin);
    }
    command.output().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// One test, not several: a PKCS#11 module can be initialised once per process, and the token
/// is created once.
#[test]
fn a_manifest_is_signed_by_the_token_and_the_wrong_token_pin_or_key_is_refused() {
    let Some(module) = softhsm() else { return };
    let public = provision(&module);
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("manifest.json");
    std::fs::write(&manifest, MANIFEST).unwrap();
    let signed_path = dir.path().join("signed.json");
    let (manifest_arg, signed_arg) = (path(&manifest), path(&signed_path));
    let token = ["--pkcs11-token", TOKEN, "--pkcs11-key", KEY];

    // The public key is the token's.
    let out = release_tool(&module, &[&["public-key"], &token[..]].concat(), Some(PIN));
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout).trim(), hex(&public));

    // The manifest is signed on the token and the signature verifies under that public key.
    let args = [
        &[
            "sign",
            "--kind",
            "release",
            &manifest_arg,
            "--out",
            &signed_arg,
        ][..],
        &token[..],
    ]
    .concat();
    let out = release_tool(&module, &args, Some(PIN));
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains(&hex(&public)),
        "{}",
        text(&out.stderr)
    );
    let mut signed: updater::ReleaseManifest =
        serde_json::from_str(&std::fs::read_to_string(&signed_path).unwrap()).unwrap();
    let signature = updater_hex(&signed.signature);
    assert_eq!(signature.len(), 64);
    signed.signature.clear();
    let canonical = serde_json::to_vec_pretty(&signed).unwrap();
    UnparsedPublicKey::new(&ED25519, public)
        .verify(&canonical, &signature)
        .expect("the token's signature verifies under its public key");

    // Nothing the operator typed leaks into the output.
    let all = format!("{}{}", text(&out.stdout), text(&out.stderr));
    assert!(!all.contains(PIN));

    // A wrong PIN, a wrong token label and a wrong key label are refused, and nothing is written.
    std::fs::remove_file(&signed_path).unwrap();
    for (what, pin, token_args) in [
        ("wrong PIN", Some("not-the-pin"), token),
        ("no PIN", None, token),
        (
            "wrong token",
            Some(PIN),
            ["--pkcs11-token", "other", "--pkcs11-key", KEY],
        ),
        (
            "wrong key",
            Some(PIN),
            ["--pkcs11-token", TOKEN, "--pkcs11-key", "other"],
        ),
    ] {
        let args = [
            &[
                "sign",
                "--kind",
                "release",
                &manifest_arg,
                "--out",
                &signed_arg,
            ][..],
            &token_args[..],
        ]
        .concat();
        let out = release_tool(&module, &args, pin);
        assert!(!out.status.success(), "{what} must fail");
        assert!(!signed_path.exists(), "{what} must not write a manifest");
    }

    // Two keys with the label: the tool does not pick one.
    add_duplicate_key(&module);
    let args = [
        &[
            "sign",
            "--kind",
            "release",
            &manifest_arg,
            "--out",
            &signed_arg,
        ][..],
        &token[..],
    ]
    .concat();
    let out = release_tool(&module, &args, Some(PIN));
    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("refusing to guess"),
        "{}",
        text(&out.stderr)
    );
    assert!(!signed_path.exists());
}

fn path(p: &Path) -> String {
    p.to_str().unwrap().to_owned()
}

fn updater_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
