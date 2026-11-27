//! Real-session checks of the providers as the sensor enables them: each test starts its own
//! ETW session from the shipped [`ProviderConfig`] and runs the sensor's own decoding, so a
//! drift in a GUID, mask, id list or decoder fails here. `#[ignore]`: enabling these providers
//! needs an elevated process. Run with
//! `cargo test -p sensor-windows --lib real_session -- --ignored`.

use std::{
    collections::BTreeSet,
    process::Command,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ferrisetw::{EventRecord, parser::Parser, schema_locator::SchemaLocator, trace::UserTrace};

use super::{KERNEL_REGISTRY, ProviderConfig};
use crate::registry_keys::{KeyName, KeyedWrite, RegistryKeys, RegistryOperation};

/// A name no other process on the host will use.
fn unique_marker(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_nanos();
    format!("{prefix}-{}-{nanos}", std::process::id())
}

/// Runs `provider` in a session of its own around `act`, with time for delivery on both
/// sides.
fn while_tracing(
    provider: &ProviderConfig,
    session: &str,
    callback: impl FnMut(&EventRecord, &SchemaLocator) + Send + Sync + 'static,
    act: impl FnOnce(),
) {
    let trace = UserTrace::new()
        .named(session.to_owned())
        .enable(provider.builder().add_callback(callback).build())
        .start_and_process()
        .expect("start a real-time ETW session (elevated?)");
    thread::sleep(Duration::from_millis(500));
    act();
    thread::sleep(Duration::from_secs(2));
    trace.stop().expect("stop the ETW test session");
}

mod kernel_registry {
    use super::*;

    const REG_SZ: u32 = 1;

    #[derive(Default)]
    struct Observed {
        event_ids: BTreeSet<u16>,
        writes: Vec<KeyedWrite>,
    }

    /// Deletes the probe key, written under the user's own hive, whatever the test's outcome.
    struct ProbeKey(String);

    impl Drop for ProbeKey {
        fn drop(&mut self) {
            let _ = Command::new("reg").args(["delete", &self.0, "/f"]).output();
        }
    }

    #[test]
    #[ignore = "requires an elevated Windows process to enable Microsoft-Windows-Kernel-Registry"]
    fn a_value_write_arrives_with_the_path_of_the_key_it_was_opened_by() {
        let marker = unique_marker("synthaea-reg-probe");
        let observed = Arc::new(Mutex::new(Observed::default()));
        let keys = Mutex::new(RegistryKeys::new(crate::sensor::REGISTRY_KEY_OBJECTS_CAP));
        let callback_observed = Arc::clone(&observed);
        let callback = move |record: &EventRecord, locator: &SchemaLocator| {
            let Ok(mut observed) = callback_observed.lock() else {
                return;
            };
            observed.event_ids.insert(record.event_id());
            let Some(operation) = RegistryOperation::from_id(record.event_id()) else {
                return;
            };
            let Ok(schema) = locator.event_schema(record) else {
                return;
            };
            let parser = Parser::create(record, &schema);
            let Ok(mut keys) = keys.lock() else {
                return;
            };
            if let Some(write) = keys.on_record(operation, record.process_id(), &parser) {
                observed.writes.push(write);
            }
        };

        let key = ProbeKey(format!(r"HKCU\Software\{marker}"));
        while_tracing(&KERNEL_REGISTRY, &marker, callback, || {
            let status = Command::new("reg")
                .args([
                    "add", &key.0, "/v", "probe", "/t", "REG_SZ", "/d", "harmless", "/f",
                ])
                .status()
                .expect("run reg.exe");
            assert!(status.success(), "reg add failed: {status}");
        });

        let observed = observed.lock().expect("observed poisoned");
        let key_suffix = format!(r"\software\{marker}").to_ascii_lowercase();
        let probe = observed
            .writes
            .iter()
            .find(|keyed| keyed.write.value_name == "probe")
            .unwrap_or_else(|| {
                panic!(
                    "no write of the probe value; {} writes, ids seen {:?}",
                    observed.writes.len(),
                    observed.event_ids
                )
            });
        let KeyName::Absolute(key_path) = &probe.key else {
            panic!("the probe write's key is unresolved: {probe:?}");
        };
        let key_path = key_path.to_ascii_lowercase();
        assert!(
            key_path.starts_with(r"\registry\user\") && key_path.ends_with(&key_suffix),
            "the probe write is not under its key's NT path: {probe:?}"
        );
        assert_eq!(probe.write.data_type, REG_SZ, "{probe:?}");
        assert!(
            matches!(probe.write.data.as_deref(), None | Some("harmless")),
            "captured data decoded wrong: {probe:?}"
        );
        assert!(
            observed
                .event_ids
                .iter()
                .all(|event_id| KERNEL_REGISTRY.event_ids.contains(event_id)),
            "the keyword mask let other operations through: {:?}",
            observed.event_ids
        );
    }
}
