//! Compiles the `EndpointSecurity` C shim (see `shim/es_shim.h` for why it
//! exists) and links libEndpointSecurity + libbsm — for macOS targets only. On
//! every other target this crate is a stub (`src/lib.rs` gates all modules), so
//! the build script does nothing there and the workspace builds everywhere.
//!
//! Cross-compiling *to* macOS from a non-Apple host is not supported: the shim
//! compiles against Apple's SDK headers, which only a macOS host has. `cc`
//! would fail to find a cross-clang/SDK there anyway — loudly, which is the
//! behavior we want (never link a sensor with no capture path).

fn main() {
    println!("cargo:rerun-if-changed=shim/es_shim.c");
    println!("cargo:rerun-if-changed=shim/es_shim.h");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }

    cc::Build::new()
        .file("shim/es_shim.c")
        // Blocks are on by default for Darwin clang, but be explicit — the
        // shim's es_new_client handler is an Objective-C block, the reason the
        // shim is C compiled against the SDK instead of Rust FFI.
        .flag("-fblocks")
        .warnings(true)
        .warnings_into_errors(true)
        .compile("synthaea_es_shim");

    println!("cargo:rustc-link-lib=dylib=EndpointSecurity");
    // audit_token_to_pid/euid/egid.
    println!("cargo:rustc-link-lib=dylib=bsm");
}
