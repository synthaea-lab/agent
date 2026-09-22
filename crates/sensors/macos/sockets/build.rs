//! Compiles the libproc socket-walk C shim (see `shim/sockets_shim.h` for why
//! it exists) — for macOS targets only; the crate is a stub elsewhere and the
//! workspace builds everywhere. Same pattern as `sensor-macos`'s build script.

fn main() {
    println!("cargo:rerun-if-changed=shim/sockets_shim.c");
    println!("cargo:rerun-if-changed=shim/sockets_shim.h");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }

    cc::Build::new()
        .file("shim/sockets_shim.c")
        .warnings(true)
        .warnings_into_errors(true)
        .compile("synthaea_sockets_shim");
    // libproc lives in libSystem — no extra link line needed.
}
