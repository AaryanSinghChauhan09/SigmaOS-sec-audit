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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn fixture() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn world_writable_flagged() {
        let dir = fixture();
        let f = dir.path().join("pub.txt");
        fs::write(&f, "data").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o666)).unwrap();
        let report = scan(dir.path()).unwrap();
        assert_eq!(report.scanned_files, 1);
        assert!(report
            .findings
            .iter()
            .any(|f| f.category == "permissions" && f.severity == Severity::Warning));
        assert!(!report.has_critical());
    }

    #[test]
    fn loose_private_key_is_critical() {
        let dir = fixture();
        let key = dir.path().join("id_rsa");
        fs::write(&key, "fake key").unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        let report = scan(dir.path()).unwrap();
        assert!(report.has_critical());
        // Tighten perms -> no critical finding.
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        let report = scan(dir.path()).unwrap();
        assert!(!report.has_critical());
    }

    #[test]
    fn hardcoded_secret_flagged_once() {
        let dir = fixture();
        fs::write(
            dir.path().join("config.env"),
            "api_key = abc123\npassword = hunter2\n",
        )
        .unwrap();
        let report = scan(dir.path()).unwrap();
        let secrets: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.category == "secrets")
            .collect();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].severity, Severity::Warning);
    }

    #[test]
    fn setuid_bit_is_info() {
        let dir = fixture();
        let f = dir.path().join("helper");
        fs::write(&f, "bin").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o4755)).unwrap();
        let report = scan(dir.path()).unwrap();
        assert!(report
            .findings
            .iter()
            .any(|f| f.severity == Severity::Info && f.message.contains("setuid")));
    }

    #[test]
    fn clean_tree_has_no_findings() {
        let dir = fixture();
        fs::write(dir.path().join("ok.txt"), "hello\n").unwrap();
        fs::create_dir(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("sub/ok2.txt"), "world\n").unwrap();
        let report = scan(dir.path()).unwrap();
        assert_eq!(report.scanned_files, 2);
        assert!(report.findings.is_empty());
        assert_eq!(report.count(Severity::Critical), 0);
    }

    #[test]
    fn render_text_summarizes() {
        let dir = fixture();
        let f = dir.path().join("w.txt");
        fs::write(&f, "x").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o666)).unwrap();
        let report = scan(dir.path()).unwrap();
        let text = render_text(&report);
        assert!(text.contains("Scanned 1 files"));
        assert!(text.contains("1 findings"));
        assert!(text.contains("Warning"));
    }
}
