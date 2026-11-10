//! Network activity: outbound connects, binds, listens, accepts, socket creation, UDP
//! send and receive, and DNS queries over UDP/53. `raw.rs` routes the syscalls to these
//! handlers.

pub(crate) mod accept;
pub(crate) mod bind;
pub(crate) mod connect;
pub(crate) mod dns;
pub(crate) mod listen;
pub(crate) mod recvfrom;
pub(crate) mod socket;
pub(crate) mod udp_send;
