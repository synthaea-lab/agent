//! Lab validation harness (issue #95's "Done when"): tails the real unified
//! log through the full parse → classify → join → normalize path and prints
//! each schema event as JSON. Run on a Mac, then trigger e.g. a sudo in
//! another terminal:
//!
//! ```sh
//! cargo run -p sensor-macos-unifiedlog --example live_tail
//! ```

#[cfg(target_os = "macos")]
fn main() {
    use std::io::BufReader;

    let mut child = sensor_macos_unifiedlog::spawn_stream().expect("failed to spawn `log stream`");
    let stdout = child.stdout.take().expect("stdout is piped");
    eprintln!(
        "tailing the unified log (predicate: {})",
        sensor_macos_unifiedlog::PREDICATE
    );
    let counters = std::sync::Arc::new(sensor_macos_unifiedlog::StreamCounters::default());
    let stream = sensor_macos_unifiedlog::NormalizedLogStream::with_counters(
        BufReader::new(stdout),
        std::sync::Arc::clone(&counters),
    );
    for item in stream {
        match item {
            Ok((record, event)) => {
                println!(
                    "{}",
                    serde_json::to_string(&event).expect("schema events serialize")
                );
                eprintln!(
                    "  ^ from {} pid {:?}",
                    record.process_image_path, record.pid
                );
            }
            Err(e) => eprintln!("stream error: {e}"),
        }
    }
    // Reached only when `log stream` exits (killed externally) — report the losses and reap it.
    eprintln!("losses: {:?}", counters.totals());
    let _ = child.wait();
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("live_tail drives /usr/bin/log — macOS only");
}
