use owo_colors::OwoColorize;
// comfy-table available for future use

use crate::report::finding::{ScanReport, Severity};

/// Render a scan report to the terminal with colors
pub fn render(report: &ScanReport) {
    println!();
    println!(
        "{}  Anty v{} — Scanned {} files in {:.2}s",
        "🔍".bold(),
        report.version,
        report.files_scanned,
        report.duration_ms as f64 / 1000.0
    );
    println!();

    if report.findings.is_empty() {
        println!(
            "  {}  No security issues found!",
            "✅".bold()
        );
        println!();
        return;
    }

    // Print each finding
    for finding in &report.findings {
        let severity_display = format!(" {} ", finding.severity);
        let severity_colored = match finding.severity {
            Severity::Critical => severity_display.on_red().white().bold().to_string(),
            Severity::High => severity_display.on_yellow().black().bold().to_string(),
            Severity::Medium => severity_display.on_blue().white().bold().to_string(),
            Severity::Low => severity_display.on_white().black().to_string(),
        };

        println!(
            "  {}  {}:{}",
            severity_colored,
            finding.file_path.display().dimmed(),
            finding.line_start.to_string().dimmed(),
        );
        println!(
            "           {}",
            finding.title.bold()
        );

        // Evidence (trimmed, max 120 chars per line)
        let evidence = finding.evidence.trim();
        if !evidence.is_empty() {
            for line in evidence.lines().take(3) {
                let trimmed = if line.len() > 120 {
                    format!("{}…", &line[..119])
                } else {
                    line.to_string()
                };
                println!("           → {}", trimmed.dimmed());
            }
        }

        // Recommendation
        println!(
            "           {} {}",
            "⮕".green(),
            finding.recommendation.green()
        );
        println!();
    }

    // Summary bar
    println!("{}", "━".repeat(60));

    let mut summary_parts = Vec::new();
    if report.summary.critical > 0 {
        summary_parts.push(
            format!("{} critical", report.summary.critical).red().bold().to_string()
        );
    }
    if report.summary.high > 0 {
        summary_parts.push(
            format!("{} high", report.summary.high).yellow().bold().to_string()
        );
    }
    if report.summary.medium > 0 {
        summary_parts.push(
            format!("{} medium", report.summary.medium).blue().to_string()
        );
    }
    if report.summary.low > 0 {
        summary_parts.push(
            format!("{} low", report.summary.low).white().to_string()
        );
    }

    println!(
        " Found {} issues: {}",
        report.summary.total.to_string().bold(),
        summary_parts.join(", ")
    );

    if report.files_skipped > 0 {
        println!(
            " ({} files skipped)",
            report.files_skipped.to_string().dimmed()
        );
    }

    println!("{}", "━".repeat(60));
    println!();
}
