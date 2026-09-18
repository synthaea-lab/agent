//! Symbol resolution spike for uprobe attachment
//!
//! This spike demonstrates how to:
//! 1. Find SSL libraries on the system
//! 2. Parse ELF symbols using goblin
//! 3. Resolve `SSL_read/SSL_write` offsets for uprobe attachment
//!
//! Run with: `cargo run --example symbol_resolution_spike`

use goblin::elf::Elf;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
struct SymbolInfo {
    name: String,
    offset: u64,
    library_path: PathBuf,
    library_type: LibraryType,
}

#[derive(Debug, Clone)]
enum LibraryType {
    OpenSSL,
    #[allow(dead_code)]
    BoringSSL,
    GnuTLS,
    Unknown,
}

impl LibraryType {
    fn from_path(path: &Path) -> Self {
        let filename = path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("");

        if filename.contains("libssl") {
            LibraryType::OpenSSL
        } else if filename.contains("libgnutls") {
            LibraryType::GnuTLS
        } else {
            LibraryType::Unknown
        }
    }
}

/// Find SSL libraries in common system paths
fn find_ssl_libraries() -> Vec<PathBuf> {
    let search_paths = vec![
        "/lib",
        "/usr/lib",
        "/lib64",
        "/usr/lib64",
        "/lib/x86_64-linux-gnu",
        "/usr/lib/x86_64-linux-gnu",
    ];

    let mut libraries = Vec::new();

    for search_path in search_paths {
        let path = Path::new(search_path);
        if !path.exists() {
            continue;
        }

        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let path = entry.path();
                let filename = path.file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("");

                // Look for libssl.so* or libgnutls.so*
                if filename.starts_with("libssl.so") || filename.starts_with("libgnutls.so") {
                    // Skip symlinks, prefer actual .so files
                    if let Ok(metadata) = fs::metadata(&path)
                        && metadata.is_file() {
                            libraries.push(path);
                        }
                }
            }
        }
    }

    libraries
}

/// Parse ELF file and find exported symbols matching the target names
fn resolve_symbols(library_path: &Path, target_symbols: &[&str]) -> Result<Vec<SymbolInfo>, Box<dyn std::error::Error>> {
    // Read the ELF file
    let buffer = fs::read(library_path)?;
    let elf = Elf::parse(&buffer)?;

    let mut found_symbols = Vec::new();
    let library_type = LibraryType::from_path(library_path);

    // Search in dynamic symbol table
    for sym in &elf.dynsyms {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            // Check if this is one of our target symbols
            for &target in target_symbols {
                if name == target {
                    found_symbols.push(SymbolInfo {
                        name: name.to_string(),
                        offset: sym.st_value,
                        library_path: library_path.to_path_buf(),
                        library_type: library_type.clone(),
                    });
                    println!("✓ Found symbol: {} at offset 0x{:x} in {:?}",
                             name, sym.st_value, library_path);
                }
            }
        }
    }

    Ok(found_symbols)
}

/// Scan system for readline symbols in bash/zsh
fn find_readline_symbols() -> Result<Vec<SymbolInfo>, Box<dyn std::error::Error>> {
    let shell_paths = vec![
        "/bin/bash",
        "/usr/bin/bash",
        "/bin/zsh",
        "/usr/bin/zsh",
    ];

    let found_symbols = Vec::new();

    for shell_path in shell_paths {
        let path = Path::new(shell_path);
        if !path.exists() {
            continue;
        }

        println!("\nScanning {} for readline symbols...", shell_path);

        let buffer = fs::read(path)?;
        let elf = Elf::parse(&buffer)?;

        // Look for readline-related symbols
        for sym in &elf.syms {
            if let Some(name) = elf.strtab.get_at(sym.st_name)
                && name.contains("readline") && sym.st_value > 0 {
                    println!("  Found: {} at 0x{:x}", name, sym.st_value);
                }
        }
    }

    Ok(found_symbols)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Symbol Resolution Spike for sensor-linux-uprobes ===\n");

    // Phase 1: Find SSL libraries
    println!("Phase 1: Finding SSL libraries on system...");
    let ssl_libs = find_ssl_libraries();

    if ssl_libs.is_empty() {
        println!("⚠ No SSL libraries found!");
        return Ok(());
    }

    println!("Found {} SSL libraries:\n", ssl_libs.len());
    for lib in &ssl_libs {
        println!("  - {:?}", lib);
    }

    // Phase 2: Resolve SSL_read and SSL_write symbols
    println!("\nPhase 2: Resolving SSL_read/SSL_write symbols...\n");
    let target_symbols = vec!["SSL_read", "SSL_write", "SSL_read_ex", "SSL_write_ex"];

    let mut all_symbols = Vec::new();

    for lib in &ssl_libs {
        match resolve_symbols(lib, &target_symbols) {
            Ok(symbols) => {
                all_symbols.extend(symbols);
            }
            Err(e) => {
                println!("✗ Failed to parse {:?}: {}", lib, e);
            }
        }
    }

    // Phase 3: Summary
    println!("\n=== Summary ===");
    println!("Total symbols found: {}", all_symbols.len());
    println!("\nUprobe attachment targets:");

    for sym in &all_symbols {
        println!("  Symbol: {}", sym.name);
        println!("    Path: {:?}", sym.library_path);
        println!("    Offset: 0x{:x}", sym.offset);
        println!("    Library: {:?}", sym.library_type);
        println!();
    }

    // Phase 4: Readline exploration (optional)
    println!("=== Readline Symbol Exploration ===");
    if let Err(e) = find_readline_symbols() {
        println!("⚠ Readline scan failed: {}", e);
    }

    // Phase 5: Recommendations
    println!("\n=== Recommendations for Implementation ===");
    println!("1. Use goblin::elf::Elf::parse() to read symbol tables");
    println!("2. Search dynsyms for dynamic libraries, syms for binaries");
    println!("3. Cache resolved symbols and track library mtime for updates");
    println!("4. For BoringSSL (statically linked), scan /proc/<pid>/maps + parse binary ELF");
    println!("5. Consider fallback: if symbol resolution fails, skip that library");

    Ok(())
}
