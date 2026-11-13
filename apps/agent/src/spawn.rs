//! Background threads that report a failed spawn instead of panicking.
//!
//! `thread::Builder::spawn` fails when the process or the host is out of threads (`EAGAIN`):
//! a limit on a container, a `RLIMIT_NPROC`, a full pid table. Every start-up spawner used to
//! `.expect(..)` that, so a constrained host aborted the agent with a panic backtrace and no
//! hint of which thread it was starting. [`spawn_named`] returns the error with the thread's
//! name in it, the spawners pass it up, and `agent run` exits with it as any other start-up
//! failure (the same shape as `DetectionSink::start_correlator_ticker`).

use std::{
    io,
    thread::{Builder, JoinHandle},
};

/// Spawns `body` on a thread called `name`.
///
/// # Errors
///
/// The OS refused the thread; the error keeps the OS error's kind and names the thread.
pub(crate) fn spawn_named<F, T>(name: &str, body: F) -> io::Result<JoinHandle<T>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    Builder::new()
        .name(name.to_owned())
        .spawn(body)
        .map_err(|source| spawn_error(name, &source))
}

/// What a failed spawn of the thread called `name` reports.
fn spawn_error(name: &str, source: &io::Error) -> io::Error {
    io::Error::new(
        source.kind(),
        format!("could not start the {name} thread: {source}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_thread_runs_the_body_under_its_name() {
        let handle = spawn_named("spawn-named-test", || {
            std::thread::current().name().map(str::to_owned)
        })
        .unwrap();
        assert_eq!(handle.join().unwrap().as_deref(), Some("spawn-named-test"));
    }

    #[test]
    fn a_refused_spawn_names_the_thread_and_keeps_the_kind() {
        let refused = io::Error::from(io::ErrorKind::WouldBlock);
        let error = spawn_error("heartbeat", &refused);
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        let text = error.to_string();
        assert!(text.contains("heartbeat"), "{text}");
        assert!(
            text.starts_with("could not start the heartbeat thread"),
            "{text}"
        );
    }
}
