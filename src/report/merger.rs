use std::collections::HashSet;
use crate::report::finding::Finding;

/// Deduplicate and sort findings
pub fn merge_findings(mut findings: Vec<Finding>) -> Vec<Finding> {
    // Deduplicate by deterministic ID
    let mut seen = HashSet::new();
    findings.retain(|f| seen.insert(f.id.clone()));

    // Sort by severity (critical first), then by file path, then by line
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.file_path.cmp(&b.file_path))
            .then_with(|| a.line_start.cmp(&b.line_start))
    });

    findings
}
