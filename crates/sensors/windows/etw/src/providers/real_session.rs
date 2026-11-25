//! Real-session checks of the providers as the sensor enables them: each test starts its own
//! ETW session from the shipped [`ProviderConfig`] and runs the sensor's own decoding, so a
//! drift in a GUID, mask, id list or decoder fails here. `#[ignore]`: enabling these providers
//! needs an elevated process. Run with
//! `cargo test -p sensor-windows --lib real_session -- --ignored`.

use std::{
    cell::Cell,
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener, TcpStream, UdpSocket},
    process::Command,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use ferrisetw::{EventRecord, parser::Parser, schema_locator::SchemaLocator, trace::UserTrace};

use super::{DOTNET_RUNTIME, KERNEL_NETWORK, KERNEL_REGISTRY, ProviderConfig};
use crate::{
    kernel_network::{self, Flow, IpFamily, NetworkEvent},
    payload,
    registry_keys::{KeyName, KeyedWrite, RegistryKeys, RegistryOperation},
};

/// A name no other process on the host will use.
fn unique_marker(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_nanos();
    format!("{prefix}{}x{nanos}", std::process::id())
}

/// How many times a test acts before it reports its records missing. A new real-time session
/// can take a while before it delivers: a fixed 500 ms warm-up lost every record in 4 runs of 6
/// on Windows 11 26300 (#355), so an act that ran too early is repeated instead.
const ATTEMPTS: usize = 3;

/// How long one attempt waits for its records.
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the session keeps running once the records arrived, so an event the provider's
/// filter should have kept out has time to show up in the assertions.
const SETTLE: Duration = Duration::from_secs(1);

const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Runs `provider` in a session of its own and repeats `act` until `delivered` holds, at most
/// [`ATTEMPTS`] times. The session stops on every exit, a panic included: `UserTrace` stops it
/// when dropped. A test process that is killed (not unwound) still leaves its session behind;
/// `logman stop <name> -ets` removes it.
fn while_tracing(
    provider: &ProviderConfig,
    session: &str,
    callback: impl FnMut(&EventRecord, &SchemaLocator) + Send + Sync + 'static,
    mut act: impl FnMut(),
    delivered: impl Fn() -> bool,
) {
    let trace = UserTrace::new()
        .named(session.to_owned())
        .enable(provider.builder().add_callback(callback).build())
        .start_and_process()
        .expect("start a real-time ETW session (elevated?)");
    for _ in 0..ATTEMPTS {
        act();
        if wait_until(&delivered, DELIVERY_TIMEOUT) {
            thread::sleep(SETTLE);
            break;
        }
    }
    trace.stop().expect("stop the ETW test session");
}

/// Whether `condition` held within `timeout`.
fn wait_until(condition: impl Fn() -> bool, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if condition() {
            return true;
        }
        thread::sleep(POLL_INTERVAL);
    }
    condition()
}

mod kernel_registry {
    use super::*;

    const REG_SZ: u32 = 1;

    #[derive(Default)]
    struct Observed {
        event_ids: BTreeSet<u16>,
        writes: Vec<KeyedWrite>,
    }

    fn is_the_probe_write(keyed: &KeyedWrite) -> bool {
        keyed.write.value_name == "probe"
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
        let marker = unique_marker("SynthaeaRegistryProbe");
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
        let write_the_probe_value = || {
            let status = Command::new("reg")
                .args([
                    "add", &key.0, "/v", "probe", "/t", "REG_SZ", "/d", "harmless", "/f",
                ])
                .status()
                .expect("run reg.exe");
            assert!(status.success(), "reg add failed: {status}");
        };
        let probe_written = || {
            observed
                .lock()
                .is_ok_and(|observed| observed.writes.iter().any(is_the_probe_write))
        };
        while_tracing(
            &KERNEL_REGISTRY,
            &marker,
            callback,
            write_the_probe_value,
            probe_written,
        );

        let observed = observed.lock().expect("observed poisoned");
        let key_suffix = format!(r"\software\{marker}").to_ascii_lowercase();
        let probe = observed
            .writes
            .iter()
            .find(|keyed| is_the_probe_write(keyed))
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

mod dotnet_runtime {
    use schema::fixtures;

    use super::*;

    #[derive(Default)]
    struct Observed {
        event_ids: BTreeSet<u16>,
        dynamic_assemblies: Vec<String>,
    }

    #[test]
    #[ignore = "requires an elevated Windows process to enable Microsoft-Windows-DotNETRuntime"]
    fn an_in_memory_assembly_load_is_the_only_event_delivered() {
        let marker = unique_marker("SynthaeaProbe");
        let probe_pid = Arc::new(Mutex::new(None::<u32>));
        let observed = Arc::new(Mutex::new(Observed::default()));
        let (callback_pid, callback_observed) = (Arc::clone(&probe_pid), Arc::clone(&observed));
        let callback = move |record: &EventRecord, locator: &SchemaLocator| {
            let Ok(pid) = callback_pid.lock() else {
                return;
            };
            if *pid != Some(record.process_id()) {
                return;
            }
            let Ok(mut observed) = callback_observed.lock() else {
                return;
            };
            observed.event_ids.insert(record.event_id());
            let Ok(schema) = locator.event_schema(record) else {
                return;
            };
            let parser = Parser::create(record, &schema);
            if let Some(load) = payload::assembly_load(&parser, fixtures::meta()) {
                observed.dynamic_assemblies.push(load.assembly_name);
            }
        };

        let define_a_dynamic_assembly = || {
            // The child waits for its pid to be registered before it defines the assembly.
            let script = format!(
                "Start-Sleep -Milliseconds 1500; \
                 [AppDomain]::CurrentDomain.DefineDynamicAssembly(\
                 (New-Object Reflection.AssemblyName '{marker}'), 'Run') | Out-Null"
            );
            let mut child = Command::new("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-Command", &script])
                .spawn()
                .expect("start powershell.exe");
            *probe_pid.lock().expect("pid poisoned") = Some(child.id());
            let status = child.wait().expect("wait for powershell.exe");
            assert!(status.success(), "powershell.exe failed: {status}");
        };
        let assembly_delivered = || {
            observed.lock().is_ok_and(|observed| {
                observed
                    .dynamic_assemblies
                    .iter()
                    .any(|name| name.starts_with(&marker))
            })
        };
        while_tracing(
            &DOTNET_RUNTIME,
            &marker,
            callback,
            define_a_dynamic_assembly,
            assembly_delivered,
        );

        let observed = observed.lock().expect("observed poisoned");
        assert!(
            observed
                .dynamic_assemblies
                .iter()
                .any(|name| name.starts_with(&marker)),
            "the dynamic assembly was not delivered; dynamic loads seen: {:?}",
            observed.dynamic_assemblies
        );
        assert_eq!(
            observed.event_ids.iter().copied().collect::<Vec<_>>(),
            DOTNET_RUNTIME.event_ids,
            "the keyword mask or the event-id filter let other events through"
        );
    }
}

mod kernel_network_ids {
    use super::*;

    #[derive(Default)]
    struct Observed {
        event_ids: BTreeSet<u16>,
        flows: Vec<(NetworkEvent, Flow)>,
    }

    impl Observed {
        fn saw(&self, event: NetworkEvent, daddr: IpAddr, dport: u16) -> bool {
            self.flows
                .iter()
                .any(|(seen, flow)| *seen == event && flow.daddr == daddr && flow.dport == dport)
        }
    }

    fn send_one_datagram(to: IpAddr) -> u16 {
        let receiver = UdpSocket::bind((to, 0)).expect("bind the UDP receiver");
        let port = receiver.local_addr().expect("receiver address").port();
        UdpSocket::bind((to, 0))
            .expect("bind the UDP sender")
            .send_to(b"synthaea", (to, port))
            .expect("send one datagram");
        port
    }

    fn connect_to_a_local_listener(at: IpAddr) -> u16 {
        let listener = TcpListener::bind((at, 0)).expect("bind the TCP listener");
        let port = listener.local_addr().expect("listener address").port();
        let _client = TcpStream::connect((at, port)).expect("connect to the listener");
        let _accepted = listener.accept().expect("accept the connection");
        port
    }

    #[test]
    #[ignore = "requires an elevated Windows process to enable Microsoft-Windows-Kernel-Network"]
    fn udp_sends_arrive_as_42_and_58_and_tcp_connects_as_12_and_28() {
        let own_pid = std::process::id();
        let observed = Arc::new(Mutex::new(Observed::default()));
        let callback_observed = Arc::clone(&observed);
        let callback = move |record: &EventRecord, locator: &SchemaLocator| {
            let Ok(mut observed) = callback_observed.lock() else {
                return;
            };
            observed.event_ids.insert(record.event_id());
            let Some(event) = NetworkEvent::from_id(record.event_id()) else {
                return;
            };
            let Ok(schema) = locator.event_schema(record) else {
                return;
            };
            let parser = Parser::create(record, &schema);
            if let Some(flow) = kernel_network::flow(event.family(), &parser)
                && flow.pid == own_pid
            {
                observed.flows.push((event, flow));
            }
        };

        let v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let ports = Cell::new([0u16; 4]);
        let expected_flows = || {
            let [udp_v4, udp_v6, tcp_v4, tcp_v6] = ports.get();
            [
                (NetworkEvent::UdpSend(IpFamily::V4), v4, udp_v4),
                (NetworkEvent::UdpSend(IpFamily::V6), v6, udp_v6),
                (NetworkEvent::TcpConnect(IpFamily::V4), v4, tcp_v4),
                (NetworkEvent::TcpConnect(IpFamily::V6), v6, tcp_v6),
            ]
        };
        let send_and_connect = || {
            ports.set([
                send_one_datagram(v4),
                send_one_datagram(v6),
                connect_to_a_local_listener(v4),
                connect_to_a_local_listener(v6),
            ]);
        };
        let all_flows_seen = || {
            observed.lock().is_ok_and(|observed| {
                expected_flows()
                    .into_iter()
                    .all(|(event, daddr, dport)| observed.saw(event, daddr, dport))
            })
        };
        while_tracing(
            &KERNEL_NETWORK,
            &unique_marker("SynthaeaNetworkProbe"),
            callback,
            send_and_connect,
            all_flows_seen,
        );

        let observed = observed.lock().expect("observed poisoned");
        for (event, daddr, dport) in expected_flows() {
            assert!(
                observed.saw(event, daddr, dport),
                "no {event:?} to {daddr}:{dport}; this process's flows: {:?}",
                observed.flows
            );
        }
        assert!(
            observed
                .event_ids
                .iter()
                .all(|event_id| KERNEL_NETWORK.event_ids.contains(event_id)),
            "the keyword mask or the event-id filter let other events through: {:?}",
            observed.event_ids
        );
    }
}
