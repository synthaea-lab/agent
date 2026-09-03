//! # enrich
//!
//! Enrichment shared by all platforms: file hashing (SHA-256, cached by path+mtime),
//! code-signature verification (Authenticode on Windows, codesign on macOS, IMA/GPG
//! where present on Linux), and file metadata. Feeds rules, YARA triggers, and ML
//! features — one implementation, not three platform copies.
