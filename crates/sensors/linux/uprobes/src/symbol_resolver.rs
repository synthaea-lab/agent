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

/// Shell type for readline probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellType {
    Bash,
    Zsh,
}

/// Symbol resolution error.
#[derive(Debug, thiserror::Error)]
pub enum ResolverError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("ELF parse error: {0}")]
    Elf(#[from] goblin::error::Error),
}

/// Finds SSL libraries in common system paths, deduplicating symlinks.
///
/// # Errors
///
/// Returns [`ResolverError`] if directory traversal fails.
pub fn find_ssl_libraries() -> Result<Vec<PathBuf>, ResolverError> {
    let search_paths = [
        "/lib",
        "/usr/lib",
        "/lib64",
        "/usr/lib64",
        "/lib/x86_64-linux-gnu",
        "/usr/lib/x86_64-linux-gnu",
    ];

    let mut libraries = Vec::new();
    let mut seen_inodes = HashSet::new();

    for &search_path in &search_paths {
        let path = Path::new(search_path);
        if !path.exists() {
            continue;
        }

        let entries = match fs::read_dir(path) {
            Ok(e) => e,
            Err(_) => continue, // Skip inaccessible dirs
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let filename = match path.file_name().and_then(|s| s.to_str()) {
                Some(f) => f,
                None => continue,
            };

            // Look for libssl.so* or libgnutls.so*
            if !filename.starts_with("libssl.so") && !filename.starts_with("libgnutls.so") {
                continue;
            }

            // Deduplicate symlinks by inode
            if let Ok(metadata) = fs::metadata(&path) {
                #[cfg(target_os = "linux")]
                {
                    use std::os::unix::fs::MetadataExt;
                    let inode = metadata.ino();
                    if metadata.is_file() && seen_inodes.insert(inode) {
                        libraries.push(path);
                    }
                }
                #[cfg(not(target_os = "linux"))]
                {
                    if metadata.is_file() {
                        libraries.push(path);
                    }
                }
            }
        }
    }

    Ok(libraries)
}

/// Finds shell binaries (bash, zsh) for readline probes.
///
/// # Errors
///
/// Returns [`ResolverError`] if filesystem access fails.
pub fn find_shell_binaries() -> Result<Vec<(PathBuf, ShellType)>, ResolverError> {
    let shells = [
        ("/bin/bash", ShellType::Bash),
        ("/usr/bin/bash", ShellType::Bash),
        ("/bin/zsh", ShellType::Zsh),
        ("/usr/bin/zsh", ShellType::Zsh),
    ];

    Ok(shells
        .iter()
        .filter_map(|(path, shell_type)| {
            let p = Path::new(path);
            p.exists().then(|| (p.to_path_buf(), *shell_type))
        })
        .collect())
}

/// Finds readline libraries in common system paths, deduplicating symlinks.
///
/// Searches for `libreadline.so*` and `libedit.so*` (some bash builds use libedit instead).
///
/// # Errors
///
/// Returns [`ResolverError`] if directory traversal fails.
pub fn find_readline_libraries() -> Result<Vec<PathBuf>, ResolverError> {
    let search_paths = [
        "/lib",
        "/usr/lib",
        "/lib64",
        "/usr/lib64",
        "/lib/x86_64-linux-gnu",
        "/usr/lib/x86_64-linux-gnu",
        "/lib/aarch64-linux-gnu",
        "/usr/lib/aarch64-linux-gnu",
    ];

    let mut libraries = Vec::new();
    let mut seen_inodes = HashSet::new();

    for &search_path in &search_paths {
        let path = Path::new(search_path);
        if !path.exists() {
            continue;
        }

        let entries = match fs::read_dir(path) {
            Ok(e) => e,
            Err(_) => continue, // Skip inaccessible dirs
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let filename = match path.file_name().and_then(|s| s.to_str()) {
                Some(f) => f,
                None => continue,
            };

            // Look for libreadline.so* or libedit.so*
            if !filename.starts_with("libreadline.so") && !filename.starts_with("libedit.so") {
                continue;
            }

            // Deduplicate symlinks by inode
            if let Ok(metadata) = fs::metadata(&path) {
                #[cfg(target_os = "linux")]
                {
                    use std::os::unix::fs::MetadataExt;
                    let inode = metadata.ino();
                    if metadata.is_file() && seen_inodes.insert(inode) {
                        libraries.push(path);
                    }
                }
                #[cfg(not(target_os = "linux"))]
                {
                    if metadata.is_file() {
                        libraries.push(path);
                    }
                }
            }
        }
    }

    Ok(libraries)
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
    let libraries = find_ssl_libraries()?;
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
    let libraries = find_readline_libraries()?;
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

    #[test]
    #[cfg(target_os = "linux")]
    fn find_ssl_libraries_returns_deduplicated_paths() {
        // This test runs against the real filesystem, so it is nondeterministic.
        // The assertion: if any libraries are found, they should have distinct inodes.
        if let Ok(libs) = find_ssl_libraries() {
            let mut inodes = HashSet::new();
            for lib in &libs {
                if let Ok(metadata) = fs::metadata(lib) {
                    use std::os::unix::fs::MetadataExt;
                    assert!(inodes.insert(metadata.ino()), "duplicate inode for {lib:?}");
                }
            }
        }
    }
}
