//! ELF symbol resolution for uprobe attachment.
//!
//! Scans system library paths for SSL libraries (OpenSSL, `GnuTLS`) and readline libraries
//! (libreadline, libedit), parses their ELF symbol tables with goblin, and returns offsets for
//! uprobe attachment. Built from the Phase 1 spike (`examples/symbol_resolution_spike.rs`,
//! since deleted — it only compiled on Linux and this module supersedes it; see git
//! history), now production-ready: deduplication, error handling, library type detection.

use std::{
    collections::HashSet,
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use goblin::elf::Elf;

/// ELF symbol with its offset and source library.
#[derive(Debug, Clone)]
pub struct SymbolInfo {
    pub name: String,
    pub offset: u64,
    pub library_path: PathBuf,
    pub library_type: LibraryType,
}

/// SSL/TLS library type identified from path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LibraryType {
    OpenSSL,
    BoringSSL,
    GnuTLS,
    Unknown,
}

impl LibraryType {
    fn from_path(path: &Path) -> Self {
        let filename = path.file_name().and_then(|s| s.to_str()).unwrap_or("");

        if filename.contains("libssl") {
            Self::OpenSSL
        } else if filename.contains("libgnutls") {
            Self::GnuTLS
        } else {
            Self::Unknown
        }
    }
}

/// Symbol resolution error.
#[derive(Debug, thiserror::Error)]
pub enum ResolverError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("ELF parse error: {0}")]
    Elf(#[from] goblin::error::Error),
}

/// Library directories searched for every library family, relative to the filesystem root:
/// the classic and lib64 trees plus the Debian/Ubuntu multiarch trees. One list for all
/// families so no search can drift (the TLS search once skipped the arm64 trees).
const LIBRARY_DIRS: &[&str] = &[
    "lib",
    "usr/lib",
    "lib64",
    "usr/lib64",
    "lib/x86_64-linux-gnu",
    "usr/lib/x86_64-linux-gnu",
    "lib/aarch64-linux-gnu",
    "usr/lib/aarch64-linux-gnu",
];

/// OpenSSL/BoringSSL (`libssl`) and `GnuTLS`.
const SSL_LIBRARY_PREFIXES: &[&str] = &["libssl.so", "libgnutls.so"];

/// Some bash builds link libedit instead of libreadline.
const READLINE_LIBRARY_PREFIXES: &[&str] = &["libreadline.so", "libedit.so"];

/// glibc's `libc.so.6` / `libc-2.31.so`, and musl's `ld-musl-<arch>.so.1`, which is
/// musl's libc and its dynamic loader in one file and exports `getaddrinfo`. On Alpine,
/// `/usr/lib/libc.so` points at that file but ships in `musl-dev`, so a host without
/// build tools has only `ld-musl-*` and the `libc.musl-*` symlink to it.
const LIBC_LIBRARY_PREFIXES: &[&str] = &["libc.so", "libc-", "ld-musl-"];

/// The libc functions [`resolve_dns_symbols`] looks up.
pub(crate) const DNS_SYMBOLS: [&str; 3] = ["getaddrinfo", "gethostbyname_r", "gethostbyname2_r"];

/// Lists the regular files under `root`/[`LIBRARY_DIRS`] whose name starts with one of
/// `prefixes`, one path per inode so a library reached through several symlinks is resolved once.
/// Missing or unreadable directories are skipped: not every layout exists on every distro.
fn find_libraries(root: &Path, prefixes: &[&str]) -> Vec<PathBuf> {
    let mut seen_inodes = HashSet::new();
    LIBRARY_DIRS
        .iter()
        .filter_map(|dir| fs::read_dir(root.join(dir)).ok())
        .flat_map(|entries| entries.flatten().map(|entry| entry.path()))
        .filter(|path| has_any_prefix(path, prefixes))
        .filter(|path| {
            fs::metadata(path)
                .is_ok_and(|metadata| metadata.is_file() && seen_inodes.insert(metadata.ino()))
        })
        .collect()
}

fn has_any_prefix(path: &Path, prefixes: &[&str]) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| prefixes.iter().any(|prefix| name.starts_with(prefix)))
}

/// Resolves the DNS lookup symbols from system libc libraries: `getaddrinfo(3)` (issue
/// #267 Phase 1) and the reentrant `gethostbyname_r`/`gethostbyname2_r` that the legacy
/// `gethostbyname`/`gethostbyname2` call on glibc and musl (agent#240).
///
/// # Errors
///
/// Returns [`ResolverError`] if library discovery or symbol parsing fails.
pub fn resolve_dns_symbols() -> Result<Vec<SymbolInfo>, ResolverError> {
    let libraries = find_libraries(Path::new("/"), LIBC_LIBRARY_PREFIXES);
    let target_symbols = DNS_SYMBOLS;

    let mut all_symbols = Vec::new();
    for lib in &libraries {
        match resolve_symbols(lib, &target_symbols) {
            Ok(mut symbols) => all_symbols.append(&mut symbols),
            Err(e) => {
                tracing::warn!(library = %lib.display(), error = %e, "symbol_resolver: parse failed");
            }
        }
    }

    tracing::info!(
        symbols = all_symbols.len(),
        libraries = libraries.len(),
        "symbol_resolver: resolved DNS symbols"
    );
    Ok(all_symbols)
}

/// Resolves ELF symbols from a library's dynamic symbol table.
///
/// # Errors
///
/// Returns [`ResolverError`] if file reading or ELF parsing fails.
pub fn resolve_symbols(
    library_path: &Path,
    target_symbols: &[&str],
) -> Result<Vec<SymbolInfo>, ResolverError> {
    let buffer = fs::read(library_path)?;
    let elf = Elf::parse(&buffer)?;

    let mut found_symbols = Vec::new();
    let library_type = LibraryType::from_path(library_path);

    // Search dynamic symbol table (.dynsyms) for shared libraries
    for sym in &elf.dynsyms {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            for &target in target_symbols {
                if name == target && sym.st_value > 0 {
                    found_symbols.push(SymbolInfo {
                        name: name.to_string(),
                        offset: sym.st_value,
                        library_path: library_path.to_path_buf(),
                        library_type,
                    });
                    tracing::debug!(
                        symbol = name,
                        offset = format_args!("0x{:x}", sym.st_value),
                        library = %library_path.display(),
                        "symbol_resolver: found symbol"
                    );
                }
            }
        }
    }

    // Fallback to static symbol table (.syms) for statically-linked binaries (e.g., bash)
    if found_symbols.is_empty() {
        for sym in &elf.syms {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                for &target in target_symbols {
                    if name == target && sym.st_value > 0 {
                        found_symbols.push(SymbolInfo {
                            name: name.to_string(),
                            offset: sym.st_value,
                            library_path: library_path.to_path_buf(),
                            library_type,
                        });
                        tracing::debug!(
                            symbol = name,
                            offset = format_args!("0x{:x}", sym.st_value),
                            library = %library_path.display(),
                            "symbol_resolver: found symbol (static table)"
                        );
                    }
                }
            }
        }
    }

    Ok(found_symbols)
}

/// Resolves all TLS symbols (`SSL_read`, `SSL_write`) from system SSL libraries.
///
/// # Errors
///
/// Returns [`ResolverError`] if library discovery or symbol parsing fails.
pub fn resolve_tls_symbols() -> Result<Vec<SymbolInfo>, ResolverError> {
    let libraries = find_libraries(Path::new("/"), SSL_LIBRARY_PREFIXES);
    // OpenSSL/BoringSSL: SSL_read, SSL_write, SSL_read_ex, SSL_write_ex
    // GnuTLS: gnutls_record_recv, gnutls_record_send
    let target_symbols = [
        "SSL_read",
        "SSL_write",
        "SSL_read_ex",
        "SSL_write_ex",
        "gnutls_record_recv",
        "gnutls_record_send",
    ];

    let mut all_symbols = Vec::new();
    for lib in &libraries {
        match resolve_symbols(lib, &target_symbols) {
            Ok(mut symbols) => all_symbols.append(&mut symbols),
            Err(e) => {
                tracing::warn!(library = %lib.display(), error = %e, "symbol_resolver: parse failed");
            }
        }
    }

    tracing::info!(
        symbols = all_symbols.len(),
        libraries = libraries.len(),
        "symbol_resolver: resolved TLS symbols"
    );
    Ok(all_symbols)
}

/// Resolves readline symbols from readline libraries (libreadline.so, libedit.so).
///
/// Searches for the `readline` function in readline libraries, not shell binaries.
/// Shell binaries (bash, zsh) import `readline` from these libraries - the symbol is
/// undefined (U) in bash itself, only defined in libreadline.so/libedit.so.
///
/// # Errors
///
/// Returns [`ResolverError`] if library discovery or symbol parsing fails.
pub fn resolve_readline_symbols() -> Result<Vec<SymbolInfo>, ResolverError> {
    let libraries = find_libraries(Path::new("/"), READLINE_LIBRARY_PREFIXES);
    let target_symbols = ["readline"];

    let mut all_symbols = Vec::new();
    for lib in &libraries {
        match resolve_symbols(lib, &target_symbols) {
            Ok(mut symbols) => all_symbols.append(&mut symbols),
            Err(e) => {
                tracing::warn!(library = %lib.display(), error = %e, "symbol_resolver: parse failed");
            }
        }
    }

    tracing::info!(
        symbols = all_symbols.len(),
        libraries = libraries.len(),
        "symbol_resolver: resolved readline symbols"
    );
    Ok(all_symbols)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn library_type_from_path() {
        assert_eq!(
            LibraryType::from_path(Path::new("/lib/libssl.so.3")),
            LibraryType::OpenSSL
        );
        assert_eq!(
            LibraryType::from_path(Path::new("/usr/lib/libgnutls.so.30")),
            LibraryType::GnuTLS
        );
        assert_eq!(
            LibraryType::from_path(Path::new("/lib/libc.so.6")),
            LibraryType::Unknown
        );
    }

    fn library_tree(files: &[&str]) -> tempfile::TempDir {
        let root = tempfile::tempdir().expect("create temp root");
        for file in files {
            let path = root.path().join(file);
            fs::create_dir_all(path.parent().expect("file has a parent dir"))
                .expect("create library dir");
            fs::write(&path, b"not really an ELF").expect("write library file");
        }
        root
    }

    fn found_names(root: &Path, prefixes: &[&str]) -> Vec<String> {
        let mut names: Vec<String> = find_libraries(root, prefixes)
            .iter()
            .map(|path| {
                path.strip_prefix(root)
                    .expect("found path is under root")
                    .display()
                    .to_string()
            })
            .collect();
        names.sort();
        names
    }

    #[test]
    fn find_libraries_matches_only_the_requested_prefixes() {
        let root = library_tree(&[
            "usr/lib/libssl.so.3",
            "usr/lib/libgnutls.so.30",
            "usr/lib/libcrypto.so.3",
            "usr/lib/notlibssl.so",
        ]);

        assert_eq!(
            found_names(root.path(), SSL_LIBRARY_PREFIXES),
            ["usr/lib/libgnutls.so.30", "usr/lib/libssl.so.3"]
        );
    }

    #[test]
    fn find_libraries_returns_one_path_per_inode_across_symlinks() {
        let root = library_tree(&["usr/lib/libedit.so.2.0.70"]);
        std::os::unix::fs::symlink(
            "libedit.so.2.0.70",
            root.path().join("usr/lib/libedit.so.2"),
        )
        .expect("create symlink");

        assert_eq!(
            find_libraries(root.path(), READLINE_LIBRARY_PREFIXES).len(),
            1
        );
    }

    #[test]
    fn find_libraries_skips_directories_with_a_library_name() {
        let root = library_tree(&["lib/libc.so.6.d/placeholder"]);

        assert!(find_libraries(root.path(), LIBC_LIBRARY_PREFIXES).is_empty());
    }

    #[test]
    fn find_libraries_skips_missing_search_dirs() {
        let root = library_tree(&["lib64/libc.so.6"]);

        assert_eq!(
            found_names(root.path(), LIBC_LIBRARY_PREFIXES),
            ["lib64/libc.so.6"]
        );
    }

    #[test]
    fn tls_library_search_finds_libssl_in_arm64_multiarch_dirs() {
        let root = library_tree(&[
            "lib/aarch64-linux-gnu/libgnutls.so.30",
            "usr/lib/aarch64-linux-gnu/libssl.so.3",
        ]);

        assert_eq!(
            found_names(root.path(), SSL_LIBRARY_PREFIXES),
            [
                "lib/aarch64-linux-gnu/libgnutls.so.30",
                "usr/lib/aarch64-linux-gnu/libssl.so.3"
            ]
        );
    }

    #[test]
    fn dns_library_search_finds_musl_without_the_dev_symlink() {
        // An Alpine host without musl-dev has no /usr/lib/libc.so: the getaddrinfo
        // uprobe found no library there, so lookups kept only the UDP/53 query and
        // lost their resolved addresses.
        let root = library_tree(&["lib/ld-musl-x86_64.so.1"]);
        std::os::unix::fs::symlink(
            "ld-musl-x86_64.so.1",
            root.path().join("lib/libc.musl-x86_64.so.1"),
        )
        .expect("create symlink");

        assert_eq!(
            found_names(root.path(), LIBC_LIBRARY_PREFIXES),
            ["lib/ld-musl-x86_64.so.1"]
        );
    }

    #[test]
    fn find_libraries_matches_glibc_versioned_libc_names() {
        let root = library_tree(&["lib/libc-2.31.so", "lib/libcap.so.2"]);

        assert_eq!(
            found_names(root.path(), LIBC_LIBRARY_PREFIXES),
            ["lib/libc-2.31.so"]
        );
    }
}
