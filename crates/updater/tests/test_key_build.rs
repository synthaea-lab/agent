//! The lab variant of the trust set (ADR-0027, #753), seen without `cfg(test)`: what a build
//! with the `test-key` feature really embeds. The counterpart of `unprovisioned_build.rs`, and
//! what replaces a unit test that asserted the flag under `cfg(test)`, where it is always true.
#![cfg(feature = "test-key")]

use updater::key::{
    CONTENT_PUBLIC_KEY, RECOVERY_PUBLIC_KEY, RELEASE_PUBLIC_KEY, SYNTHAEA_UPDATER_TEST_KEY,
};

#[test]
fn a_build_with_the_test_key_feature_says_so_and_embeds_the_test_set() {
    assert!(std::hint::black_box(SYNTHAEA_UPDATER_TEST_KEY));
    assert!(RELEASE_PUBLIC_KEY.is_some());
    assert_eq!(
        *RELEASE_PUBLIC_KEY, *CONTENT_PUBLIC_KEY,
        "the test set shares one release/content key (ADR-0016's development shortcut)"
    );
    assert!(RECOVERY_PUBLIC_KEY.is_some());
    assert_ne!(*RECOVERY_PUBLIC_KEY, *RELEASE_PUBLIC_KEY);
}
