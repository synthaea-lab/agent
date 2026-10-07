//! Live regression for #672: a `PENDING_SYSCALL_EXIT` map full of threads blocked in
//! `accept()` must not blind `memfd_create` and `recvfrom`, which share the same map.
//!
//! The accepts and the control calls run in child processes: the sensor drops events
//! from its own pid (self-exclusion, #340), so a test that calls them in its own
//! process observes nothing (see #673).
//!
//! Build with the eBPF toolchain, then run as root on a Linux lab host:
//! `cargo build -p sensor-linux --example pending_syscall_exit_pressure --release`
//! `sudo sh -c "ulimit -Hn 65536; ulimit -Sn 16384; exec target/release/examples/pending_syscall_exit_pressure"`
//!
//! The file descriptor limit must exceed the pressure thread count, and on some hosts
//! the default *hard* limit (`ulimit -Hn`) is itself too low to raise the soft limit
//! past it — raise both. `PENDING_SYSCALL_EXIT_PRESSURE_THREADS` sets the thread count
//! (default 4200, the exact count #660/#672 reported as lost on the unpatched map).

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        error::Error,
        ffi::CString,
        io,
        net::{TcpListener, TcpStream, UdpSocket},
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

    const DEFAULT_THREADS: usize = 4200;

    fn pressure_threads() -> usize {
        std::env::var("PENDING_SYSCALL_EXIT_PRESSURE_THREADS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(DEFAULT_THREADS)
    }
    const EVENT_TIMEOUT: Duration = Duration::from_secs(10);

    enum Seen {
        Accept(u16),
        Memfd(i32),
        UdpRecv(u16),
    }

    struct Sink(Sender<Seen>);

    impl EventSink for Sink {
        fn on_event(&self, event: Event) {
            match event {
                Event::SocketAccept(e) => {
                    let _ = self.0.send(Seen::Accept(e.peer_port));
                }
                Event::MemfdCreate(e) => {
                    let _ = self.0.send(Seen::Memfd(e.fd));
                }
                Event::UdpRecv(e) => {
                    let _ = self.0.send(Seen::UdpRecv(e.peer_port));
                }
                _ => {}
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

    fn one_memfd() -> Result<i32, Box<dyn Error>> {
        let name = CString::new("pending-syscall-exit-pressure").unwrap();
        // SAFETY: a valid NUL-terminated name and a documented flag value; the
        // returned fd is owned by this call and checked for -1 below.
        let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(fd)
    }

    fn one_recvfrom() -> Result<u16, Box<dyn Error>> {
        let receiver = UdpSocket::bind("127.0.0.1:0")?;
        let sender = UdpSocket::bind("127.0.0.1:0")?;
        let sender_port = sender.local_addr()?.port();
        sender.connect(receiver.local_addr()?)?;
        sender.send(b"x")?;
        let mut buf = [0u8; 1];
        receiver.recv_from(&mut buf)?;
        // The receiver's `UdpRecvEvent.peer_port` names the sender, which is what
        // the pressure-test parent can observe from outside this child.
        Ok(sender_port)
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

    fn child(mode: &str) -> Result<String, Box<dyn Error>> {
        match mode {
            "control-accept" => Ok(format!("PORT {}", one_accept()?)),
            "control-memfd" => Ok(format!("FD {}", one_memfd()?)),
            "control-recvfrom" => Ok(format!("PORT {}", one_recvfrom()?)),
            "pressure" => {
                let _blocked = block_accepts(pressure_threads())?;
                Ok(format!("PORT {}", one_accept()?))
            }
            other => Err(io::Error::other(format!("unknown child mode {other}")).into()),
        }
    }

    fn run_child(mode: &str) -> Result<String, Box<dyn Error>> {
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
            .find_map(|line| line.split_once(' '))
            .map(|(_, value)| value.trim().to_string())
            .ok_or_else(|| io::Error::other(format!("child {mode} printed nothing")).into())
    }

    fn wait_for<T>(
        events: &Receiver<Seen>,
        deadline: Instant,
        matches: impl Fn(&Seen) -> Option<T>,
        what: &str,
    ) -> Result<T, Box<dyn Error>> {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::other(format!("{what} was not delivered")).into());
            }
            match events.recv_timeout(remaining) {
                Ok(seen) => {
                    if let Some(value) = matches(&seen) {
                        return Ok(value);
                    }
                }
                Err(_) => return Err(io::Error::other(format!("{what} was not delivered")).into()),
            }
        }
    }

    pub(super) fn run() -> Result<(), Box<dyn Error>> {
        let args: Vec<String> = std::env::args().collect();
        if args.get(1).map(String::as_str) == Some("--child") {
            let mode = args.get(2).map(String::as_str).unwrap_or("");
            println!("{}", child(mode)?);
            return Ok(());
        }

        let (tx, events) = mpsc::channel();
        thread::spawn(move || {
            let mut sensor = LinuxSensor::new();
            if let Err(error) = sensor.run(Box::new(Sink(tx))) {
                eprintln!("sensor-linux failed: {error}");
                std::process::exit(2);
            }
        });
        thread::sleep(Duration::from_secs(3));

        let control_port: u16 = run_child("control-accept")?.parse()?;
        wait_for(
            &events,
            Instant::now() + EVENT_TIMEOUT,
            |seen| match seen {
                Seen::Accept(port) if *port == control_port => Some(()),
                _ => None,
            },
            "control socket_accept",
        )?;

        let sentinel_port: u16 = run_child("pressure")?.parse()?;
        wait_for(
            &events,
            Instant::now() + EVENT_TIMEOUT,
            |seen| match seen {
                Seen::Accept(port) if *port == sentinel_port => Some(()),
                _ => None,
            },
            "post-pressure socket_accept",
        )?;

        let memfd_fd: i32 = run_child("control-memfd")?.parse()?;
        wait_for(
            &events,
            Instant::now() + EVENT_TIMEOUT,
            |seen| match seen {
                Seen::Memfd(fd) if *fd == memfd_fd => Some(()),
                _ => None,
            },
            "post-pressure memfd_create",
        )?;

        let recv_port: u16 = run_child("control-recvfrom")?.parse()?;
        wait_for(
            &events,
            Instant::now() + EVENT_TIMEOUT,
            |seen| match seen {
                Seen::UdpRecv(port) if *port == recv_port => Some(()),
                _ => None,
            },
            "post-pressure recvfrom",
        )?;

        println!(
            "PASS #672: accept, memfd_create and recvfrom all survived {} blocked accept() calls sharing PENDING_SYSCALL_EXIT",
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
