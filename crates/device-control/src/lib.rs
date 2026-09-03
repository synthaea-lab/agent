//! # device-control
//!
//! Peripheral telemetry and control, USB storage first:
//!
//! - **Telemetry**: device attach/detach events (vendor/product/serial, class),
//!   file transfers to removable media (joining existing file events to the mount),
//!   BadUSB heuristics (HID appearing on a storage-class device, keystroke-speed
//!   anomalies) as detections.
//! - **Control**: policy-gated modes per device class — allow / read-only / block /
//!   notify — enforced platform-natively (Windows: device installation policies;
//!   macOS: DiskArbitration + ES auth events; Linux: udev rules + mount options),
//!   with per-device allowlists by serial.
//! - Every enforcement action is a detection-grade event: audited, case-attachable,
//!   and visible to the user via the `ui` tray (why was my stick blocked).
