//! # ipc
//!
//! The local control channel the agent exposes on the endpoint, consumed by the
//! endpoint UI (`ui/`) and the CLI. Named pipe on Windows, Unix domain socket on
//! Linux/macOS, with peer authentication (caller identity) and a versioned,
//! read-mostly protocol: agent status, sensor health, recent detections, policy
//! version. Mutating commands are policy-gated and audited.
//!
//! Defines the protocol types and both client and server halves; the server side is
//! hosted by the agent, never a separate process.
