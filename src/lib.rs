//! SigmaOS sec-audit — security audit scanner.
//!
//! Scans directories for common security issues: world-writable files,
//! private keys with loose permissions, hardcoded secrets in configs,
//! and setuid/setgid binaries. Read-only; reports findings.

#![forbid(unsafe_code)]

use serde::Serialize;
use std::path::{Path, PathBuf};

/// Errors produced by this component.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("walk error: {0}")]
    Walk(String),
}

/// Severity of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

/// A single audit finding.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub category: String,
    pub path: PathBuf,
    pub message: String,
}

/// Audit report.
#[derive(Debug, Clone, Serialize, Default)]
pub struct AuditReport {
    pub findings: Vec<Finding>,
    pub scanned_files: usize,
}

impl AuditReport {
    /// True if any critical findings exist.
    pub fn has_critical(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity == Severity::Critical)
    }

    /// Count by severity.
    pub fn count(&self, sev: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == sev).count()
    }
}

/// Patterns that indicate hardcoded secrets (checked in text files).
const SECRET_PATTERNS: &[&str] = &[
    "PRIVATE KEY-----",
    "aws_secret_access_key",
    "AKIA",
    "password =",
    "passwd =",
    "api_key =",
    "apikey =",
    "secret =",
    "token =",
];

/// File names that should never be world-readable.
const PRIVATE_KEY_NAMES: &[&str] = &["id_rsa", "id_ed25519", "id_ecdsa", ".pem", "id_dsa"];

/// Max file size to scan for secrets (bytes).
const MAX_SCAN_BYTES: u64 = 1024 * 1024; // 1 MiB

/// Scan a directory recursively.
pub fn scan(root: &Path) -> Result<AuditReport, AuditError> {
    let mut report = AuditReport::default();
    for entry in walkdir::WalkDir::new(root).follow_links(false) {
        let entry = entry.map_err(|e| AuditError::Walk(e.to_string()))?;
        let path = entry.path();
        if !entry.file_type().is_file() {
            continue;
        }
        report.scanned_files += 1;

        // Permission checks via metadata.
        if let Ok(meta) = entry.metadata() {
            use std::os::unix::fs::PermissionsExt;
            let mode = meta.permissions().mode();
            // World-writable (o+w) on regular files.
            if mode & 0o002 != 0 {
                report.findings.push(Finding {
                    severity: Severity::Warning,
                    category: "permissions".into(),
                    path: path.to_path_buf(),
                    message: "world-writable file".into(),
                });
            }
            // Private key files readable by group/other.
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if PRIVATE_KEY_NAMES.iter().any(|p| name.contains(p)) && mode & 0o077 != 0 {
                report.findings.push(Finding {
                    severity: Severity::Critical,
                    category: "permissions".into(),
                    path: path.to_path_buf(),
                    message: "private key readable by group/other".into(),
                });
            }
            // Setuid/setgid bits.
            if mode & 0o6000 != 0 {
                report.findings.push(Finding {
                    severity: Severity::Info,
                    category: "permissions".into(),
                    path: path.to_path_buf(),
                    message: format!("setuid/setgid bit set (mode {:o})", mode & 0o7777),
                });
            }
        }

        // Secret scan for small text-ish files.
        if let Ok(meta) = entry.metadata() {
            if meta.len() <= MAX_SCAN_BYTES {
                if let Ok(bytes) = std::fs::read(path) {
                    if let Ok(text) = String::from_utf8(bytes) {
                        for pat in SECRET_PATTERNS {
                            if text.contains(pat) {
                                report.findings.push(Finding {
                                    severity: Severity::Warning,
                                    category: "secrets".into(),
                                    path: path.to_path_buf(),
                                    message: format!("possible hardcoded secret (pattern: {pat})"),
                                });
                                break; // one finding per file is enough
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(report)
}

/// Render report as text.
pub fn render_text(report: &AuditReport) -> String {
    let mut out = format!(
        "Scanned {} files — {} findings ({} critical, {} warning, {} info)\n",
        report.scanned_files,
        report.findings.len(),
        report.count(Severity::Critical),
        report.count(Severity::Warning),
        report.count(Severity::Info),
    );
    for f in &report.findings {
        out.push_str(&format!(
            "[{:?}] {} — {}: {}\n",
            f.severity,
            f.category,
            f.path.display(),
            f.message
        ));
    }
    out
}
