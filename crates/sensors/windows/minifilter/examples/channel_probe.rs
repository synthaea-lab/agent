//! Lab probe for the event channel (#136, milestone 2c): runs the agent's own receive loop
//! (`channel::run`) for a while, prints every event it forwards, then the loss figures.
//! Run it through `run-as-agent.ps1` so the driver lets it in.
//!
//! `channel_probe [SECONDS] [quiet]`: how long to listen (default 30). With `quiet`, events
//! are counted, not printed (for storms).

#[cfg(windows)]
fn main() {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    };

    use schema::{Event, sensor::EventSink};
    use sensor_windows_minifilter::{channel, stats::ChannelStats};

    struct Printer {
        quiet: bool,
        deletes: AtomicU64,
        renames: AtomicU64,
    }

    impl EventSink for Printer {
        fn on_event(&self, event: Event) {
            match &event {
                Event::FileDelete(d) => {
                    self.deletes.fetch_add(1, Ordering::Relaxed);
                    if !self.quiet {
                        println!("delete pid={} {}", d.meta.pid, d.path);
                    }
                }
                Event::FileRename(r) => {
                    self.renames.fetch_add(1, Ordering::Relaxed);
                    if !self.quiet {
                        println!("rename pid={} {} -> {}", r.meta.pid, r.old_path, r.new_path);
                    }
                }
                other => println!("unexpected event: {other:?}"),
            }
        }
    }

    let mut args = std::env::args().skip(1);
    let seconds = args
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(30);
    let quiet = args.next().is_some_and(|s| s == "quiet");

    let printer = Arc::new(Printer {
        quiet,
        deletes: AtomicU64::new(0),
        renames: AtomicU64::new(0),
    });
    let stop = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(Mutex::new(ChannelStats::default()));
    let alive = Arc::new(AtomicU64::new(0));

    let worker = {
        let (printer, stop, stats, alive) = (
            Arc::clone(&printer),
            Arc::clone(&stop),
            Arc::clone(&stats),
            Arc::clone(&alive),
        );
        std::thread::spawn(move || {
            channel::run(
                printer.as_ref(),
                &stop,
                &|| {
                    alive.fetch_add(1, Ordering::Relaxed);
                },
                &stats,
            );
        })
    };
    println!("listening {seconds} s");
    std::thread::sleep(std::time::Duration::from_secs(seconds));
    stop.store(true, Ordering::Relaxed);
    if worker.join().is_err() {
        println!("receive thread panicked");
        std::process::exit(2);
    }

    let s = *stats
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    println!(
        "done: deletes={} renames={} messages={} heartbeats={} connections={} \
         lost_by_sequence={} decode_errors={} driver(queue_full={} send_failed={} not_connected={} \
         capture_failed={}) total_lost={}",
        printer.deletes.load(Ordering::Relaxed),
        printer.renames.load(Ordering::Relaxed),
        s.received,
        s.heartbeats,
        s.connections,
        s.lost_by_sequence,
        s.decode_errors,
        s.driver.dropped_queue_full,
        s.driver.dropped_send_failed,
        s.driver.not_connected,
        s.driver.dropped_capture_failed,
        s.total_lost(),
    );
    if alive.load(Ordering::Relaxed) == 0 {
        println!("no message at all: not connected, or the driver sent nothing");
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("channel_probe is Windows-only");
}
