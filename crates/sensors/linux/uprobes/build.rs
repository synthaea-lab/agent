//! Compiles the eBPF probes (`../ebpf`) into `OUT_DIR`. The uprobe programs (`ssl_write`,
//! `ssl_read_entry`, `ssl_read_exit`, `readline_exit`) are part of the same eBPF object as
//! the tracepoint programs - this `build.rs` is identical to `../userspace/build.rs`,
//! compiling the same `sensor-linux-ebpf` crate.

fn main() -> anyhow::Result<()> {
    println!("cargo::rustc-check-cfg=cfg(ebpf_embedded)");
    println!("cargo:rerun-if-changed=../ebpf/src");
    println!("cargo:rerun-if-changed=../wire/src");
    println!("cargo:rerun-if-env-changed=PATH");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return Ok(());
    }
    if which::which("bpf-linker").is_err() {
        println!(
            "cargo:warning=bpf-linker not found - building sensor-linux-uprobes WITHOUT embedded \
             eBPF probes (load_ebpf() will error at runtime); see lab/provisioning/"
        );
        return Ok(());
    }

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
