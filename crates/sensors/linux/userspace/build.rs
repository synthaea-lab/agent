//! Compiles the eBPF probes (`../ebpf`, excluded from the workspace) into OUT_DIR via
//! aya-build, when that is possible on this host:
//!
//! - non-Linux target: skipped (the crate compiles to a stub there anyway);
//! - Linux without `bpf-linker` on PATH (plain CI runners): skipped with a warning —
//!   the crate then compiles WITHOUT embedded probes and `load_ebpf()` returns an
//!   error at runtime. `lab/provisioning/linux-toolchain.sh` installs the full
//!   toolchain (nightly + bpf-linker with the LLVM-major alignment), so lab VMs and
//!   release builds embed the probes automatically.
//!
//! The `ebpf_embedded` cfg tells the library which of the two states it is in.

fn main() -> anyhow::Result<()> {
    println!("cargo::rustc-check-cfg=cfg(ebpf_embedded)");
    println!("cargo:rerun-if-changed=../ebpf/src");
    println!("cargo:rerun-if-changed=../wire/src");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return Ok(());
    }
    if which::which("bpf-linker").is_err() {
        println!(
            "cargo:warning=bpf-linker not found — building sensor-linux WITHOUT embedded \
             eBPF probes (load_ebpf() will error at runtime); see lab/provisioning/"
        );
        return Ok(());
    }

    // The ebpf crate is excluded from the workspace, so it is addressed by path, not
    // through cargo metadata.
    let ebpf_root = format!("{}/../ebpf", env!("CARGO_MANIFEST_DIR"));
    aya_build::build_ebpf(
        [aya_build::Package {
            name: "sensor-linux-ebpf",
            root_dir: &ebpf_root,
            ..Default::default()
        }],
        aya_build::Toolchain::default(),
    )?;
    println!("cargo::rustc-cfg=ebpf_embedded");
    Ok(())
}
