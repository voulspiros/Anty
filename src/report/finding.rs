use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

/// Severity level of a security finding
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "CRITICAL" => Severity::Critical,
            "HIGH" => Severity::High,
            "MEDIUM" => Severity::Medium,
            _ => Severity::Low,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Confidence level of a finding
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Confidence::Low => "LOW",
            Confidence::Medium => "MEDIUM",
            Confidence::High => "HIGH",
        }
    }
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A single security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Deterministic ID (hash-based) e.g. "ANTY-a1b2c3d4"
    pub id: String,

    /// Rule ID that triggered this finding, e.g. "ANTY-SEC-001"
    pub rule_id: String,

    /// Severity level
    pub severity: Severity,

    /// Confidence level
    pub confidence: Confidence,

    /// Which agent found this
    pub agent: String,

    /// Short title
    pub title: String,

    /// Human-readable description
    pub description: String,

    /// File where the issue was found
    pub file_path: PathBuf,

    /// Starting line number (1-based)
    pub line_start: usize,

    /// Ending line number (1-based)
    pub line_end: usize,

    /// Evidence snippet (code)
    pub evidence: String,

    /// Actionable recommendation
    pub recommendation: String,

    /// Optional CWE ID
    pub cwe_id: Option<String>,
}

impl Finding {
    /// Generate a deterministic ID based on rule, file, and location
    pub fn generate_id(rule_id: &str, file_path: &std::path::Path, line_start: usize) -> String {
        let mut hasher = Sha256::new();
        hasher.update(rule_id.as_bytes());
        hasher.update(file_path.to_string_lossy().as_bytes());
        hasher.update(line_start.to_string().as_bytes());
        let result = hasher.finalize();
        let hex = format!("{:x}", result);
        format!("ANTY-{}", &hex[..8])
    }
}

/// The complete scan report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    /// Anty version
    pub version: String,

    /// When the scan was performed
    pub timestamp: String,

    /// Root path that was scanned
    pub scan_path: PathBuf,

    /// Total files scanned
    pub files_scanned: usize,

    /// Total files skipped
    pub files_skipped: usize,

    /// Duration in milliseconds
    pub duration_ms: u64,

    /// All findings, sorted by severity (critical first)
    pub findings: Vec<Finding>,

    /// Summary counts
    pub summary: ScanSummary,
}

impl ScanReport {
    /// Check if there are findings at or above a severity threshold
    pub fn has_findings_at_or_above(&self, threshold: Severity) -> bool {
        self.findings.iter().any(|f| f.severity >= threshold)
    }
}

/// Summary statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

impl ScanSummary {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut summary = ScanSummary {
            total: findings.len(),
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
        };
        for f in findings {
            match f.severity {
                Severity::Critical => summary.critical += 1,
                Severity::High => summary.high += 1,
                Severity::Medium => summary.medium += 1,
                Severity::Low => summary.low += 1,
            }
        }
        summary
    }
}
