//! Configuration for uprobe sensor: allowlists, budgets, and compliance modes.
//!
//! This module defines the configuration structure for controlling which processes
//! and libraries are allowed to be monitored, what rate limits apply, and what
//! compliance requirements are enforced (GDPR, HIPAA, PCI-DSS).

use std::collections::HashSet;
use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid budget value: {0}")]
    InvalidBudget(String),
}

/// Compliance mode presets for regulatory frameworks.
///
/// Each mode applies specific configuration constraints to meet compliance requirements:
/// - **Budget limits:** Reduce data capture volume
/// - **Retention hints:** Maximum event age (enforced by downstream systems)
/// - **Redaction:** Field-level masking (already applied for all modes)
/// - **Audit requirements:** Access logging, breach notification
///
/// **Note:** Compliance modes are **guidance**, not guarantees. Operators must:
/// - Review legal requirements with DPO/legal counsel
/// - Implement encryption at rest (spool, database)
/// - Configure appropriate retention policies
/// - Enable audit logging in query API
/// - Document legal basis for capture
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComplianceMode {
    /// No compliance constraints (default). Suitable for:
    /// - Development/testing environments
    /// - Environments with no PII/PHI/cardholder data
    /// - Internal security monitoring with explicit employee consent
    None,

    /// GDPR (General Data Protection Regulation) mode.
    ///
    /// **Constraints:**
    /// - Reduced TLS budget: 2048 bytes/sec (minimize PII capture)
    /// - Reduced readline budget: 5 commands/sec
    /// - Retention hint: 30 days (operator must configure downstream)
    ///
    /// **Requirements (operator must implement):**
    /// - Document legal basis (legitimate interest: security monitoring)
    /// - Right to erasure: Delete events by subject ID
    /// - Data breach notification: 72 hours if plaintext exposed
    /// - DPO review before production deployment
    ///
    /// **Limitations:**
    /// - Redaction is best-effort (not all PII patterns caught)
    /// - No automatic deletion by subject ID (future work)
    Gdpr,

    /// HIPAA (Health Insurance Portability and Accountability Act) mode.
    ///
    /// **Constraints:**
    /// - Reduced TLS budget: 1024 bytes/sec (minimize PHI capture)
    /// - Reduced readline budget: 5 commands/sec
    /// - Retention hint: 30 days (minimum necessary)
    ///
    /// **Requirements (operator must implement):**
    /// - Encryption at rest: LUKS/dm-crypt for spool, `PostgreSQL` TDE
    /// - Access audit: Log all event queries (who/what/when)
    /// - Business Associate Agreement: Vendor must sign BAA
    /// - Minimum necessary: Use allowlist to limit capture scope
    ///
    /// **Limitations:**
    /// - No encryption at rest by default (operator must enable)
    /// - Comprehensive audit trail not yet implemented (future work)
    Hipaa,

    /// PCI-DSS (Payment Card Industry Data Security Standard) mode.
    ///
    /// **⚠️ WARNING:** PCI-DSS prohibits storing full PAN (Primary Account Number)
    /// after authorization. Current redaction does NOT mask credit card numbers.
    ///
    /// **DO NOT use in PCI-DSS environments** until PAN redaction implemented.
    ///
    /// **Constraints (if PAN redaction added in future):**
    /// - Reduced TLS budget: 1024 bytes/sec (minimize cardholder data)
    /// - Redaction: Mask credit card numbers (Luhn algorithm validation)
    /// - Retention hint: 90 days maximum
    ///
    /// **Requirements (operator must implement):**
    /// - Encryption at rest: Required for spool and database
    /// - Strict access control: Limit who can query events
    /// - Audit trail: Comprehensive logging
    ///
    /// **Recommendations:**
    /// - Disable TLS capture entirely for payment processing systems
    /// - Use allowlist to exclude payment-related processes
    PciDss,
}

/// Configuration for TLS capture uprobes.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Enable TLS capture (default: false for security).
    pub enabled: bool,
    /// Maximum bytes captured per process per second (budget enforcement).
    /// Default: 4096 bytes/sec (enough for ~16 HTTP requests with headers).
    pub bytes_per_process_per_sec: u32,
    /// Process names allowed for TLS capture (allowlist). Empty = all processes.
    /// Example: ["curl", "wget", "python3"].
    pub process_allowlist: HashSet<String>,
    /// Library paths to exclude from capture. Example: ["/lib/libcurl.so.4"].
    pub library_denylist: HashSet<PathBuf>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default (sensitive data)
            bytes_per_process_per_sec: 4096,
            process_allowlist: HashSet::new(), // Empty = all processes allowed
            library_denylist: HashSet::new(),
        }
    }
}

/// Configuration for readline capture uprobes.
#[derive(Debug, Clone)]
pub struct ReadlineConfig {
    /// Enable readline capture (default: false).
    pub enabled: bool,
    /// Maximum commands captured per process per second.
    /// Default: 10 commands/sec (interactive shells rarely exceed this).
    pub commands_per_process_per_sec: u32,
    /// Process names allowed for readline capture (allowlist). Empty = all shells.
    /// Example: ["bash", "zsh"].
    pub process_allowlist: HashSet<String>,
}

impl Default for ReadlineConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default
            commands_per_process_per_sec: 10,
            process_allowlist: HashSet::new(), // Empty = all shells allowed
        }
    }
}

/// Complete uprobe sensor configuration.
#[derive(Debug, Clone)]
pub struct UprobesConfig {
    /// TLS capture configuration.
    pub tls: TlsConfig,
    /// Readline capture configuration.
    pub readline: ReadlineConfig,
    /// Compliance mode (applies preset constraints for regulatory frameworks).
    pub compliance_mode: ComplianceMode,
}

impl Default for UprobesConfig {
    fn default() -> Self {
        Self {
            tls: TlsConfig::default(),
            readline: ReadlineConfig::default(),
            compliance_mode: ComplianceMode::None,
        }
    }
}

impl UprobesConfig {
    /// Create a new configuration with default values (all captures disabled).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable TLS capture with default budget and no allowlist.
    #[must_use]
    pub fn with_tls_enabled(mut self) -> Self {
        self.tls.enabled = true;
        self
    }

    /// Enable readline capture with default budget and no allowlist.
    #[must_use]
    pub fn with_readline_enabled(mut self) -> Self {
        self.readline.enabled = true;
        self
    }

    /// Set compliance mode (applies preset constraints for regulatory frameworks).
    ///
    /// **Effect:** Adjusts budget limits to meet compliance requirements:
    /// - `None`: No constraints (default budgets)
    /// - `Gdpr`: TLS 2048 bytes/sec, readline 5 cmd/sec, 30-day retention hint
    /// - `Hipaa`: TLS 1024 bytes/sec, readline 5 cmd/sec, 30-day retention hint
    /// - `PciDss`: TLS 1024 bytes/sec (⚠️ DO NOT USE - no PAN redaction yet)
    ///
    /// **Note:** Budgets can be overridden with `tls_budget()` / `readline_budget()`
    /// after setting compliance mode.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sensor_linux_uprobes::{UprobesConfig, config::ComplianceMode};
    /// let config = UprobesConfig::new()
    ///     .with_compliance_mode(ComplianceMode::Gdpr)
    ///     .with_tls_enabled();
    /// assert_eq!(config.tls.bytes_per_process_per_sec, 2048); // GDPR preset
    /// ```
    #[must_use]
    pub fn with_compliance_mode(mut self, mode: ComplianceMode) -> Self {
        self.compliance_mode = mode;

        // Apply preset budget constraints
        match mode {
            ComplianceMode::None => {
                // No constraints (keep defaults: TLS 4096, readline 10)
            }
            ComplianceMode::Gdpr => {
                // GDPR: Minimize PII capture
                self.tls.bytes_per_process_per_sec = 2048;
                self.readline.commands_per_process_per_sec = 5;
            }
            ComplianceMode::Hipaa => {
                // HIPAA: Minimize PHI capture (stricter than GDPR)
                self.tls.bytes_per_process_per_sec = 1024;
                self.readline.commands_per_process_per_sec = 5;
            }
            ComplianceMode::PciDss => {
                // PCI-DSS: Minimize cardholder data capture
                // ⚠️ WARNING: Do not use in production until PAN redaction implemented
                self.tls.bytes_per_process_per_sec = 1024;
                self.readline.commands_per_process_per_sec = 5;
            }
        }

        self
    }

    /// Set TLS bytes budget per process per second.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidBudget`] if the budget is 0.
    pub fn tls_budget(mut self, bytes_per_sec: u32) -> Result<Self, ConfigError> {
        if bytes_per_sec == 0 {
            return Err(ConfigError::InvalidBudget(
                "bytes_per_process_per_sec must be > 0".to_string(),
            ));
        }
        self.tls.bytes_per_process_per_sec = bytes_per_sec;
        Ok(self)
    }

    /// Set readline commands budget per process per second.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidBudget`] if the budget is 0.
    pub fn readline_budget(mut self, commands_per_sec: u32) -> Result<Self, ConfigError> {
        if commands_per_sec == 0 {
            return Err(ConfigError::InvalidBudget(
                "commands_per_process_per_sec must be > 0".to_string(),
            ));
        }
        self.readline.commands_per_process_per_sec = commands_per_sec;
        Ok(self)
    }

    /// Add processes to TLS capture allowlist.
    #[must_use]
    pub fn tls_allow_processes(mut self, processes: &[&str]) -> Self {
        self.tls.process_allowlist = processes.iter().map(|s| (*s).to_string()).collect();
        self
    }

    /// Add processes to readline capture allowlist.
    #[must_use]
    pub fn readline_allow_processes(mut self, processes: &[&str]) -> Self {
        self.readline.process_allowlist = processes.iter().map(|s| (*s).to_string()).collect();
        self
    }

    /// Add libraries to TLS capture denylist.
    #[must_use]
    pub fn tls_deny_libraries(mut self, libraries: &[PathBuf]) -> Self {
        self.tls.library_denylist = libraries.iter().cloned().collect();
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_captures_disabled() {
        let config = UprobesConfig::new();
        assert!(!config.tls.enabled);
        assert!(!config.readline.enabled);
    }

    #[test]
    fn can_enable_tls() {
        let config = UprobesConfig::new().with_tls_enabled();
        assert!(config.tls.enabled);
        assert_eq!(config.tls.bytes_per_process_per_sec, 4096);
    }

    #[test]
    fn can_enable_readline() {
        let config = UprobesConfig::new().with_readline_enabled();
        assert!(config.readline.enabled);
        assert_eq!(config.readline.commands_per_process_per_sec, 10);
    }

    #[test]
    fn can_set_tls_budget() {
        let config = UprobesConfig::new().tls_budget(8192).unwrap();
        assert_eq!(config.tls.bytes_per_process_per_sec, 8192);
    }

    #[test]
    fn rejects_zero_tls_budget() {
        let result = UprobesConfig::new().tls_budget(0);
        assert!(result.is_err());
    }

    #[test]
    fn can_set_readline_budget() {
        let config = UprobesConfig::new().readline_budget(20).unwrap();
        assert_eq!(config.readline.commands_per_process_per_sec, 20);
    }

    #[test]
    fn rejects_zero_readline_budget() {
        let result = UprobesConfig::new().readline_budget(0);
        assert!(result.is_err());
    }

    #[test]
    fn can_set_tls_allowlist() {
        let config = UprobesConfig::new().tls_allow_processes(&["curl", "wget"]);
        assert_eq!(config.tls.process_allowlist.len(), 2);
        assert!(config.tls.process_allowlist.contains("curl"));
        assert!(config.tls.process_allowlist.contains("wget"));
    }

    #[test]
    fn can_set_readline_allowlist() {
        let config = UprobesConfig::new().readline_allow_processes(&["bash", "zsh"]);
        assert_eq!(config.readline.process_allowlist.len(), 2);
        assert!(config.readline.process_allowlist.contains("bash"));
    }

    #[test]
    fn can_set_library_denylist() {
        let libs = vec![PathBuf::from("/lib/libcurl.so.4")];
        let config = UprobesConfig::new().tls_deny_libraries(&libs);
        assert_eq!(config.tls.library_denylist.len(), 1);
    }

    #[test]
    fn empty_allowlist_means_all_allowed() {
        let config = UprobesConfig::new();
        assert!(config.tls.process_allowlist.is_empty());
        assert!(config.readline.process_allowlist.is_empty());
    }

    #[test]
    fn builder_pattern_works() {
        let config = UprobesConfig::new()
            .with_tls_enabled()
            .with_readline_enabled()
            .tls_budget(8192)
            .unwrap()
            .readline_budget(20)
            .unwrap()
            .tls_allow_processes(&["curl"])
            .readline_allow_processes(&["bash"]);

        assert!(config.tls.enabled);
        assert!(config.readline.enabled);
        assert_eq!(config.tls.bytes_per_process_per_sec, 8192);
        assert_eq!(config.readline.commands_per_process_per_sec, 20);
    }

    #[test]
    fn default_compliance_mode_is_none() {
        let config = UprobesConfig::new();
        assert_eq!(config.compliance_mode, ComplianceMode::None);
        assert_eq!(config.tls.bytes_per_process_per_sec, 4096); // Default budget
        assert_eq!(config.readline.commands_per_process_per_sec, 10);
    }

    #[test]
    fn gdpr_mode_reduces_budgets() {
        let config = UprobesConfig::new().with_compliance_mode(ComplianceMode::Gdpr);
        assert_eq!(config.compliance_mode, ComplianceMode::Gdpr);
        assert_eq!(config.tls.bytes_per_process_per_sec, 2048); // GDPR preset
        assert_eq!(config.readline.commands_per_process_per_sec, 5);
    }

    #[test]
    fn hipaa_mode_reduces_budgets_more() {
        let config = UprobesConfig::new().with_compliance_mode(ComplianceMode::Hipaa);
        assert_eq!(config.compliance_mode, ComplianceMode::Hipaa);
        assert_eq!(config.tls.bytes_per_process_per_sec, 1024); // HIPAA preset (stricter)
        assert_eq!(config.readline.commands_per_process_per_sec, 5);
    }

    #[test]
    fn pcidss_mode_reduces_budgets() {
        let config = UprobesConfig::new().with_compliance_mode(ComplianceMode::PciDss);
        assert_eq!(config.compliance_mode, ComplianceMode::PciDss);
        assert_eq!(config.tls.bytes_per_process_per_sec, 1024);
        assert_eq!(config.readline.commands_per_process_per_sec, 5);
    }

    #[test]
    fn can_override_compliance_budgets() {
        // Compliance mode sets presets, but can be overridden
        let config = UprobesConfig::new()
            .with_compliance_mode(ComplianceMode::Gdpr) // Sets TLS to 2048
            .tls_budget(8192) // Override to 8192
            .unwrap();

        assert_eq!(config.compliance_mode, ComplianceMode::Gdpr);
        assert_eq!(config.tls.bytes_per_process_per_sec, 8192); // Overridden
    }

    #[test]
    fn compliance_mode_works_with_builder_pattern() {
        let config = UprobesConfig::new()
            .with_compliance_mode(ComplianceMode::Hipaa)
            .with_tls_enabled()
            .with_readline_enabled()
            .tls_allow_processes(&["curl"]);

        assert_eq!(config.compliance_mode, ComplianceMode::Hipaa);
        assert!(config.tls.enabled);
        assert!(config.readline.enabled);
        assert_eq!(config.tls.bytes_per_process_per_sec, 1024); // HIPAA preset
        assert_eq!(config.tls.process_allowlist.len(), 1);
    }
}
