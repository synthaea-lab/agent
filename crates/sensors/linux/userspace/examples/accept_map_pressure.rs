//! Live regression for #660: blocked accept calls cannot blind later telemetry.
//!
//! The accepts run in child processes: the sensor drops events from its own pid
//! (self-exclusion, #340), so a test that accepts in its own process observes nothing.
//!
//! Build with the eBPF toolchain, then run as root on a Linux lab host:
//! `cargo build -p sensor-linux --example accept_map_pressure`
//! `sudo sh -c "ulimit -n 8192; exec target/debug/examples/accept_map_pressure"`
//!
//! The file descriptor limit must exceed the thread count: every blocked thread holds
//! a cloned listener. Without it the run fails with "Too many open files", then
//! "child pressure failed". `ACCEPT_PRESSURE_THREADS` sets the thread count (default 1024).
//!
//! Blocked threads keep their entries in the sensor's parent-side maps (`ACCEPT_ARGS`,
//! `PENDING_SYSCALL_EXIT`) until the process exits; that is the pressure being measured.

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        error::Error,
        io,
        net::{TcpListener, TcpStream},
        process::{Command, Stdio},
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

    const DEFAULT_THREADS: usize = 1024;

    fn pressure_threads() -> usize {
        std::env::var("ACCEPT_PRESSURE_THREADS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(DEFAULT_THREADS)
    }
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

    fn block_accepts(threads: usize) -> Result<TcpListener, Box<dyn Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let ready = Arc::new(Barrier::new(threads + 1));
        for _ in 0..threads {
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
        thread::sleep(Duration::from_secs(2));
        Ok(listener)
    }

    fn child(mode: &str) -> Result<u16, Box<dyn Error>> {
        match mode {
            "control" => one_accept(),
            "pressure" => {
                let _blocked = block_accepts(pressure_threads())?;
                one_accept()
            }
            other => Err(io::Error::other(format!("unknown child mode {other}")).into()),
        }
    }

    fn run_child(mode: &str) -> Result<u16, Box<dyn Error>> {
        let output = Command::new(std::env::current_exe()?)
            .args(["--child", mode])
            .stdin(Stdio::null())
            .stderr(Stdio::inherit())
            .output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!("child {mode} failed")).into());
        }
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .find_map(|line| line.strip_prefix("PORT "))
            .and_then(|port| port.trim().parse().ok())
            .ok_or_else(|| io::Error::other(format!("child {mode} printed no port")).into())
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

    pub(super) fn run() -> Result<(), Box<dyn Error>> {
        let args: Vec<String> = std::env::args().collect();
        if args.get(1).map(String::as_str) == Some("--child") {
            let mode = args.get(2).map(String::as_str).unwrap_or("");
            println!("PORT {}", child(mode)?);
            return Ok(());
        }

        let (tx, events) = mpsc::channel();
        thread::spawn(move || {
            let mut sensor = LinuxSensor::new();
            if let Err(error) = sensor.run(Box::new(AcceptSink(tx))) {
                eprintln!("sensor-linux failed: {error}");
                std::process::exit(2);
            }
        });
        thread::sleep(Duration::from_secs(3));

        let control_port = run_child("control")?;
        wait_for_port(&events, control_port)
            .map_err(|error| io::Error::other(format!("control accept: {error}")))?;
        let sentinel_port = run_child("pressure")?;
        wait_for_port(&events, sentinel_port)
            .map_err(|error| io::Error::other(format!("post-pressure accept: {error}")))?;
        println!(
            "PASS #660: socket_accept survived {} blocked calls (peer port {sentinel_port})",
            pressure_threads()
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
