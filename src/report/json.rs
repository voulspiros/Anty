use anyhow::Result;
use crate::report::finding::ScanReport;

/// Render a scan report as pretty-printed JSON
pub fn render(report: &ScanReport) -> Result<String> {
    let json = serde_json::to_string_pretty(report)?;
    Ok(json)
}
