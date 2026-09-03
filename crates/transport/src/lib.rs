//! # transport
//!
//! Agent <-> control-plane communication (new in this iteration): mTLS channel,
//! enrollment, store-and-forward event upload with backpressure, policy and content
//! download, heartbeat. Must degrade gracefully when the server is unreachable.
