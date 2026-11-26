// SPDX-License-Identifier: GPL-2.0-only OR MIT
//! The eBPF probe programs of `sensor-linux`, compiled for `bpfel-unknown-none` through its
//! `build.rs` (aya-build); the probes live in the `main.rs` binary and its modules, this library target only
//! exists so the crate has a package id to resolve.

#![no_std]

// This file exists to enable the library target.
