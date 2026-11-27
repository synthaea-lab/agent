//! Worker threads done one way across the agent.
//!
//! Every long-running piece of the agent is a named thread that shares state behind a lock
//! and must stop within a deadline when the sensor returns. The three policies that go with
//! that live here, so a crate that starts a worker does not grow its own:
//!
//! - [`spawn`]: a refused thread is an error naming the thread, never a panic.
//! - [`sync`]: a lock poisoned by a panicking thread is recovered and logged once.
//! - [`shutdown`]: workers are signalled together and joined against one shared deadline.

pub mod shutdown;
pub mod spawn;
pub mod sync;
