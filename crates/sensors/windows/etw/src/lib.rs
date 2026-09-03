//! # sensor-windows
//!
//! Windows user-mode sensor built on ETW. Baseline providers: Kernel-Process,
//! Kernel-File, Kernel-Network. Planned expansion (see ../README.md, audit P1–P8):
//! real command line via PEB read (not the image-path placeholder), user/SID and
//! integrity level, Kernel-Registry, DNS-Client, image load, hash + Authenticode,
//! AMSI/script-block, WMI-Activity, IPv6 + inbound network.
//!
//! Self-defense is part of the design: randomized session name, heartbeat alerting on
//! event silence, automatic trace re-arm (a fixed session name plus `logman stop` must
//! not blind the sensor silently).
//!
//! Windows long paths and multi-kilobyte command lines are first-class: no Linux-derived
//! length limits, volume mapping via QueryDosDeviceW rather than assuming C:.
//!
//! Compiles to a stub on non-Windows targets. To be migrated from
//! `old/crates/synthaea-sensor-windows`, fixing audit findings F-1..F-7 on the way.
