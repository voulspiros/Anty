use regex::Regex;
use tracing::debug;

use crate::agents::{Language, ScannedFile, SecurityAgent};
use crate::report::finding::{Confidence, Finding, Severity};

/// Detects dangerous configuration patterns like CORS wildcards,
/// debug mode enabled, insecure headers, etc.
///
/// Level A agent — regex-based, language-aware.
pub struct ConfigIssuesAgent {
    patterns: Vec<ConfigPattern>,
}

struct ConfigPattern {
    rule_id: &'static str,
    title: &'static str,
    description: &'static str,
    pattern: Regex,
    severity: Severity,
    confidence: Confidence,
    recommendation: &'static str,
    cwe_id: &'static str,
    file_types: FileTypeFilter,
}

#[derive(Debug, Clone)]
enum FileTypeFilter {
    /// Matches any file
    Any,
    /// Only matches specific languages
    Languages(Vec<Language>),
    /// Only matches config-like files
    #[allow(dead_code)]
    ConfigFiles,
}

impl ConfigPattern {
    fn applies_to(&self, file: &ScannedFile) -> bool {
        match &self.file_types {
            FileTypeFilter::Any => true,
            FileTypeFilter::Languages(langs) => {
                file.language.is_none_or(|l| langs.contains(&l))
            }
            FileTypeFilter::ConfigFiles => {
                matches!(
                    file.language,
                    Some(Language::Yaml | Language::Json | Language::Toml | Language::Env)
                ) || {
                    let name = file.rel_path.file_name()
                        .map(|n| n.to_string_lossy().to_lowercase())
                        .unwrap_or_default();
                    name.contains("config")
                        || name.contains("settings")
                        || name.ends_with(".env")
                        || name == "docker-compose.yml"
                        || name == "docker-compose.yaml"
                }
            }
        }
    }
}

impl ConfigIssuesAgent {
    pub fn new() -> Self {
        let patterns = vec![
            // ── CORS ─────────────────────────────────────────
            ConfigPattern {
                rule_id: "ANTY-CFG-001",
                title: "CORS Wildcard Origin",
                description: "CORS is configured to allow all origins (*), which may expose the API to cross-origin attacks",
                pattern: Regex::new(r#"(?i)(access-control-allow-origin|cors|origin)\s*[:=]\s*["']\*["']"#).unwrap(),
                severity: Severity::Medium,
                confidence: Confidence::High,
                recommendation: "Restrict CORS to specific trusted origins instead of using '*'.",
                cwe_id: "CWE-942",
                file_types: FileTypeFilter::Any,
            },

            // ── Debug Mode ───────────────────────────────────
            ConfigPattern {
                rule_id: "ANTY-CFG-002",
                title: "Debug Mode Enabled",
                description: "Application appears to have debug mode enabled, which can leak sensitive information",
                pattern: Regex::new(r#"(?i)(DEBUG|debug)\s*[=:]\s*(true|True|1|"true"|'true')"#).unwrap(),
                severity: Severity::Medium,
                confidence: Confidence::Low,
                recommendation: "Ensure DEBUG is disabled in production. Use environment-specific configuration.",
                cwe_id: "CWE-489",
                file_types: FileTypeFilter::Any,
            },

            // ── HTTPS disabled ───────────────────────────────
            ConfigPattern {
                rule_id: "ANTY-CFG-003",
                title: "Insecure HTTP URL",
                description: "HTTP URL found where HTTPS should be used (API endpoints, webhook URLs)",
                pattern: Regex::new(r#"(?i)(api_url|endpoint|webhook|callback_url|base_url|server_url)\s*[=:]\s*["']http://[^"']+"#).unwrap(),
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                recommendation: "Use HTTPS for all external API endpoints and webhooks.",
                cwe_id: "CWE-319",
                file_types: FileTypeFilter::Any,
            },

            // ── Insecure cookie ──────────────────────────────
            ConfigPattern {
                rule_id: "ANTY-CFG-004",
                title: "Cookie Without Secure Flag",
                description: "Cookie is set without the Secure flag, allowing transmission over HTTP",
                pattern: Regex::new(r#"(?i)(secure|httponly)\s*[:=]\s*(false|False|0)"#).unwrap(),
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                recommendation: "Set secure: true and httpOnly: true on all authentication cookies.",
                cwe_id: "CWE-614",
                file_types: FileTypeFilter::Languages(vec![
                    Language::JavaScript,
                    Language::TypeScript,
                    Language::Python,
                ]),
            },

            // ── Binding to 0.0.0.0 ──────────────────────────
            ConfigPattern {
                rule_id: "ANTY-CFG-005",
                title: "Server Binding to All Interfaces",
                description: "Server is configured to listen on 0.0.0.0, exposing it to all network interfaces",
                pattern: Regex::new(r#"(?i)(host|bind|listen)\s*[=:(]\s*["']?0\.0\.0\.0["']?"#).unwrap(),
                severity: Severity::Low,
                confidence: Confidence::Low,
                recommendation: "In production, bind to specific interfaces. Use 127.0.0.1 for local-only access.",
                cwe_id: "CWE-668",
                file_types: FileTypeFilter::Any,
            },

            // ── Docker/Container issues ──────────────────────
            ConfigPattern {
                rule_id: "ANTY-CFG-006",
                title: "Docker Container Running as Root",
                description: "Dockerfile does not set a non-root user",
                pattern: Regex::new(r"(?i)^FROM\s+.+").unwrap(), // Will check for absence of USER
                severity: Severity::Low,
                confidence: Confidence::Low,
                recommendation: "Add a USER directive in your Dockerfile to run as a non-root user.",
                cwe_id: "CWE-250",
                file_types: FileTypeFilter::Languages(vec![Language::Dockerfile]),
            },

            // ── TLS verification disabled ────────────────────
            ConfigPattern {
                rule_id: "ANTY-CFG-007",
                title: "TLS/SSL Verification Disabled",
                description: "SSL certificate verification is disabled, making connections vulnerable to MITM attacks",
                pattern: Regex::new(r#"(?i)(verify\s*[=:]\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*["']?0|CURLOPT_SSL_VERIFYPEER\s*[=:,]\s*false|InsecureSkipVerify\s*:\s*true|rejectUnauthorized\s*:\s*false)"#).unwrap(),
                severity: Severity::High,
                confidence: Confidence::High,
                recommendation: "Never disable SSL verification in production. Use proper certificate management.",
                cwe_id: "CWE-295",
                file_types: FileTypeFilter::Any,
            },

            // ── Rate limiting absent indicators ──────────────
            ConfigPattern {
                rule_id: "ANTY-CFG-008",
                title: "Sensitive Endpoint Without Rate Limiting",
                description: "Login or authentication endpoint found without apparent rate limiting",
                pattern: Regex::new(r#"(?i)(app\.(post|put)\s*\(\s*["'](/login|/auth|/signin|/register|/signup|/reset-password))"#).unwrap(),
                severity: Severity::Low,
                confidence: Confidence::Low,
                recommendation: "Implement rate limiting on authentication endpoints to prevent brute-force attacks.",
                cwe_id: "CWE-307",
                file_types: FileTypeFilter::Languages(vec![
                    Language::JavaScript,
                    Language::TypeScript,
                ]),
            },
        ];

        ConfigIssuesAgent { patterns }
    }
}

impl SecurityAgent for ConfigIssuesAgent {
    fn name(&self) -> &str {
        "config-issues"
    }

    fn description(&self) -> &str {
        "Detects dangerous configurations: CORS wildcards, debug mode, insecure cookies, TLS issues"
    }

    fn scan_file(&self, file: &ScannedFile) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (line_num, line) in file.content.lines().enumerate() {
            let line_number = line_num + 1;
            let trimmed = line.trim();

            // Skip empty lines and pure comments
            if trimmed.is_empty()
                || trimmed.starts_with("//")
                || trimmed.starts_with("#")
                || trimmed.starts_with("<!--")
            {
                continue;
            }

            for pattern in &self.patterns {
                if !pattern.applies_to(file) {
                    continue;
                }

                if pattern.pattern.is_match(line) {
                    let finding = Finding {
                        id: Finding::generate_id(
                            pattern.rule_id,
                            &file.rel_path,
                            line_number,
                        ),
                        rule_id: pattern.rule_id.to_string(),
                        severity: pattern.severity,
                        confidence: pattern.confidence,
                        agent: "config-issues".to_string(),
                        title: pattern.title.to_string(),
                        description: pattern.description.to_string(),
                        file_path: file.rel_path.clone(),
                        line_start: line_number,
                        line_end: line_number,
                        evidence: trimmed.to_string(),
                        recommendation: pattern.recommendation.to_string(),
                        cwe_id: Some(pattern.cwe_id.to_string()),
                    };

                    debug!(
                        "Config issue: {} in {}:{}",
                        pattern.rule_id,
                        file.rel_path.display(),
                        line_number
                    );

                    findings.push(finding);
                    break;
                }
            }
        }

        findings
    }
}
