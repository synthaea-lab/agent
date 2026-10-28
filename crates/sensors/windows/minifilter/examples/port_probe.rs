//! Lab probe for the driver port (#136): connects the way the agent will and
//! reports the outcome. Run it through `driver/test/run-as-agent.ps1` (next to
//! this crate) to connect as the agent, or directly to see the refusal.
//!
//! `port_probe [HOLD_SECS]` keeps the connection open that long before
//! disconnecting (default 0), e.g. to check a second client is refused.

#[cfg(windows)]
fn main() {
    let hold = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    match sensor_windows_minifilter::DriverPort::connect() {
        Ok(port) => {
            println!("connected to {}", sensor_windows_minifilter::PORT_NAME);
            std::thread::sleep(std::time::Duration::from_secs(hold));
            drop(port);
            println!("disconnected");
        }
        Err(e) => {
            println!("refused: {e} ({e:?})");
            std::process::exit(1);
        }
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("port_probe is Windows-only");
}
