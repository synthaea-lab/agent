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

    let toolchain = ebpf_toolchain()?;
    let ebpf_root = format!("{}/../ebpf", env!("CARGO_MANIFEST_DIR"));
    aya_build::build_ebpf(
        [aya_build::Package {
            name: "sensor-linux-ebpf",
            root_dir: &ebpf_root,
            ..Default::default()
        }],
        aya_build::Toolchain::Custom(&toolchain),
    )?;
    println!("cargo::rustc-cfg=ebpf_embedded");
    Ok(())
}

/// The toolchain aya-build compiles the probes with, pinned in
/// `ebpf-toolchain.txt` at the repo root: the one source for this build script,
/// CI and lab provisioning. An unpinned `nightly` breaks the probe build as soon
/// as its LLVM major moves past the one bpf-linker was cut against.
/// `SYNTHAEA_EBPF_TOOLCHAIN` overrides it for a local experiment.
fn ebpf_toolchain() -> anyhow::Result<String> {
    const PINNED: &str = include_str!("../../../../ebpf-toolchain.txt");
    println!("cargo:rerun-if-changed=../../../../ebpf-toolchain.txt");
    println!("cargo:rerun-if-env-changed=SYNTHAEA_EBPF_TOOLCHAIN");
    let toolchain =
        std::env::var("SYNTHAEA_EBPF_TOOLCHAIN").unwrap_or_else(|_| PINNED.trim().to_owned());

    // Check with `rustup toolchain list`, which never installs anything: `rustup
    // run` and even `rustup component list --toolchain` auto-install a missing
    // toolchain (rustup >= 1.28), without the rust-src the probe build needs.
    let rustup = |args: &[&str]| {
        std::process::Command::new("rustup")
            .args(args)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default()
    };
    let prefix = format!("{toolchain}-");
    let installed = rustup(&["toolchain", "list"]).lines().any(|line| {
        line.split_whitespace()
            .next()
            .is_some_and(|name| name == toolchain || name.starts_with(&prefix))
    });
    let has_src = installed
        && rustup(&[
            "component",
            "list",
            "--installed",
            "--toolchain",
            &toolchain,
        ])
        .lines()
        .any(|line| line.starts_with("rust-src"));
    anyhow::ensure!(
        has_src,
        "the eBPF probe toolchain {toolchain} (ebpf-toolchain.txt) is not installed with \
         rust-src; run: rustup toolchain install {toolchain} --profile minimal --component rust-src"
    );
    Ok(toolchain)
}
