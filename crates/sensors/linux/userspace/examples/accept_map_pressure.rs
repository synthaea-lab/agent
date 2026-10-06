//! Live regression for #660: blocked accept calls cannot blind later telemetry.
//!
//! Build with the eBPF toolchain, then run as root on a Linux lab host:
//! `cargo build -p sensor-linux --example accept_map_pressure`
//! `sudo target/debug/examples/accept_map_pressure`

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        error::Error,
        io,
        net::{TcpListener, TcpStream},
        sync::{
            Arc, Barrier,
            mpsc::{self, Receiver, Sender},
        },
        thread,
        time::{Duration, Instant},
    };

    use schema::{
        Event,
        sensor::{EventSink, Sensor},
    };
    use sensor_linux::LinuxSensor;

    const MAP_CAPACITY: usize = 1024;
    const EVENT_TIMEOUT: Duration = Duration::from_secs(10);

    struct AcceptSink(Sender<u16>);

    impl EventSink for AcceptSink {
        fn on_event(&self, event: Event) {
            if let Event::SocketAccept(accepted) = event {
                let _ = self.0.send(accepted.peer_port);
            }
        }
    }

    fn one_accept() -> Result<u16, Box<dyn Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let worker = thread::spawn(move || listener.accept().map(|_| ()));
        let client = TcpStream::connect(address)?;
        let peer_port = client.local_addr()?.port();
        worker
            .join()
            .map_err(|_| io::Error::other("accept worker panicked"))??;
        Ok(peer_port)
    }

    fn wait_for_port(events: &Receiver<u16>, peer_port: u16) -> Result<(), Box<dyn Error>> {
        let deadline = Instant::now() + EVENT_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::other(format!(
                    "socket_accept for peer port {peer_port} was not delivered"
                ))
                .into());
            }
            match events.recv_timeout(remaining) {
                Ok(port) if port == peer_port => return Ok(()),
                Ok(_) => {}
                Err(_) => {
                    return Err(io::Error::other(format!(
                        "socket_accept for peer port {peer_port} was not delivered"
                    ))
                    .into());
                }
            }
        }
    }

    fn block_accepts() -> Result<TcpListener, Box<dyn Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let ready = Arc::new(Barrier::new(MAP_CAPACITY + 1));
        for _ in 0..MAP_CAPACITY {
            let socket = listener.try_clone()?;
            let ready = Arc::clone(&ready);
            thread::Builder::new()
                .stack_size(64 * 1024)
                .spawn(move || {
                    ready.wait();
                    let _ = socket.accept();
                })?;
        }
        ready.wait();
        // The barrier releases the workers together; give them time to enter
        // the blocking syscall before inserting one more stash.
        thread::sleep(Duration::from_secs(2));
        Ok(listener)
    }

    pub(super) fn run() -> Result<(), Box<dyn Error>> {
        let (tx, events) = mpsc::channel();
        thread::spawn(move || {
            let mut sensor = LinuxSensor::new();
            if let Err(error) = sensor.run(Box::new(AcceptSink(tx))) {
                eprintln!("sensor-linux failed: {error}");
                std::process::exit(2);
            }
        });
        thread::sleep(Duration::from_secs(3));

        let control_port = one_accept()?;
        wait_for_port(&events, control_port)
            .map_err(|error| io::Error::other(format!("control accept: {error}")))?;
        let _blocked_listener = block_accepts()?;
        let sentinel_port = one_accept()?;
        wait_for_port(&events, sentinel_port)
            .map_err(|error| io::Error::other(format!("post-pressure accept: {error}")))?;
        println!(
            "PASS #660: socket_accept survived {MAP_CAPACITY} blocked calls (peer port {sentinel_port})"
        );
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    linux::run()
}

#[cfg(not(target_os = "linux"))]
fn main() {}
