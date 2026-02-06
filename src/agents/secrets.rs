use regex::Regex;
use tracing::debug;

use crate::agents::{ScannedFile, SecurityAgent};
use crate::report::finding::{Confidence, Finding, Severity};

/// Secret pattern definition
struct SecretPattern {
    rule_id: &'static str,
    title: &'static str,
    description: &'static str,
    pattern: Regex,
    severity: Severity,
    confidence: Confidence,
    recommendation: &'static str,
    cwe_id: &'static str,
}

/// The Secrets agent detects hardcoded secrets, API keys, tokens,
/// and credentials in source code.
///
/// This is a Level A agent — no AST required. Uses regex + known patterns.
pub struct SecretsAgent {
    patterns: Vec<SecretPattern>,
}

impl SecretsAgent {
    pub fn new() -> Self {
        let patterns = vec![
            // ── AWS ──────────────────────────────────────────
            SecretPattern {
                rule_id: "ANTY-SEC-001",
                title: "AWS Access Key ID",
                description: "Hardcoded AWS Access Key ID found in source code",
                pattern: Regex::new(r"(?i)(^|[^a-zA-Z0-9])(AKIA[0-9A-Z]{16})([^a-zA-Z0-9]|$)").unwrap(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                recommendation: "Use environment variables or AWS IAM roles. Never commit AWS keys to source control.",
                cwe_id: "CWE-798",
            },
            SecretPattern {
                rule_id: "ANTY-SEC-002",
                title: "AWS Secret Access Key",
                description: "Potential AWS Secret Access Key found",
                pattern: Regex::new(r#"(?i)(aws_secret_access_key|aws_secret_key|secret_access_key)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?"#).unwrap(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                recommendation: "Remove the secret key and rotate it immediately. Use AWS IAM roles or environment variables.",
                cwe_id: "CWE-798",
            },

            // ── GitHub ───────────────────────────────────────
            SecretPattern {
                rule_id: "ANTY-SEC-003",
                title: "GitHub Personal Access Token",
                description: "GitHub personal access token (classic or fine-grained) found",
                pattern: Regex::new(r"(?i)(^|[^a-zA-Z0-9])(ghp_[a-zA-Z0-9]{36,255})([^a-zA-Z0-9]|$)").unwrap(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                recommendation: "Revoke this token on GitHub and use environment variables or a secrets manager.",
                cwe_id: "CWE-798",
            },
            SecretPattern {
                rule_id: "ANTY-SEC-004",
                title: "GitHub OAuth Access Token",
                description: "GitHub OAuth access token found",
                pattern: Regex::new(r"(?i)(^|[^a-zA-Z0-9])(gho_[a-zA-Z0-9]{36,255})([^a-zA-Z0-9]|$)").unwrap(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                recommendation: "Revoke this token immediately and use proper OAuth flow with secure token storage.",
                cwe_id: "CWE-798",
            },

            // ── Stripe ───────────────────────────────────────
            SecretPattern {
                rule_id: "ANTY-SEC-005",
                title: "Stripe Secret Key",
                description: "Stripe secret API key found in source code",
                pattern: Regex::new(r"(?i)(^|[^a-zA-Z0-9])(sk_live_[a-zA-Z0-9]{24,99})([^a-zA-Z0-9]|$)").unwrap(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                recommendation: "Remove the Stripe key and rotate it in the Stripe dashboard. Use environment variables.",
                cwe_id: "CWE-798",
            },
            SecretPattern {
                rule_id: "ANTY-SEC-006",
                title: "Stripe Restricted Key",
                description: "Stripe restricted API key found",
                pattern: Regex::new(r"(?i)(^|[^a-zA-Z0-9])(rk_live_[a-zA-Z0-9]{24,99})([^a-zA-Z0-9]|$)").unwrap(),
                severity: Severity::High,
                confidence: Confidence::High,
                recommendation: "Remove the key and rotate it in the Stripe dashboard.",
                cwe_id: "CWE-798",
            },

            // ── OpenAI ───────────────────────────────────────
            SecretPattern {
                rule_id: "ANTY-SEC-007",
                title: "OpenAI API Key",
                description: "OpenAI API key found in source code",
                pattern: Regex::new(r"(?i)(^|[^a-zA-Z0-9])(sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})([^a-zA-Z0-9]|$)").unwrap(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                recommendation: "Rotate the key in your OpenAI dashboard and use environment variables.",
                cwe_id: "CWE-798",
            },
            // Newer OpenAI key format
            SecretPattern {
                rule_id: "ANTY-SEC-008",
                title: "OpenAI API Key (project-scoped)",
                description: "OpenAI project-scoped API key found",
                pattern: Regex::new(r"(?i)(^|[^a-zA-Z0-9])(sk-proj-[a-zA-Z0-9_-]{40,200})([^a-zA-Z0-9]|$)").unwrap(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                recommendation: "Rotate the key in your OpenAI dashboard and use environment variables.",
                cwe_id: "CWE-798",
            },

            // ── Slack ────────────────────────────────────────
            SecretPattern {
                rule_id: "ANTY-SEC-009",
                title: "Slack Bot Token",
                description: "Slack bot token found in source code",
                pattern: Regex::new(r"(?i)(^|[^a-zA-Z0-9])(xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34})([^a-zA-Z0-9]|$)").unwrap(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                recommendation: "Revoke this token in Slack and use environment variables.",
                cwe_id: "CWE-798",
            },
            SecretPattern {
                rule_id: "ANTY-SEC-010",
                title: "Slack Webhook URL",
                description: "Slack incoming webhook URL found",
                pattern: Regex::new(r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24,}").unwrap(),
                severity: Severity::High,
                confidence: Confidence::High,
                recommendation: "Remove the webhook URL and store it in environment variables or a secrets manager.",
                cwe_id: "CWE-798",
            },

            // ── Generic Passwords ────────────────────────────
            SecretPattern {
                rule_id: "ANTY-SEC-011",
                title: "Hardcoded Password",
                description: "Potential hardcoded password assignment found",
                pattern: Regex::new(r#"(?i)(password|passwd|pwd|pass)\s*[=:]\s*["'][^"']{8,}["']"#).unwrap(),
                severity: Severity::High,
                confidence: Confidence::Medium,
                recommendation: "Never hardcode passwords. Use environment variables, a secrets manager, or configuration files excluded from version control.",
                cwe_id: "CWE-798",
            },

            // ── Database URLs ────────────────────────────────
            SecretPattern {
                rule_id: "ANTY-SEC-012",
                title: "Database Connection String with Credentials",
                description: "Database connection string with embedded credentials found",
                pattern: Regex::new(r#"(?i)(mongodb(\+srv)?|postgres(ql)?|mysql|redis|amqp)://[a-zA-Z0-9_]+:[^@\s]{3,}@[^\s"']{3,}"#).unwrap(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                recommendation: "Use environment variables for database connection strings. Never embed credentials in code.",
                cwe_id: "CWE-798",
            },

            // ── Private Keys ─────────────────────────────────
            SecretPattern {
                rule_id: "ANTY-SEC-013",
                title: "Private Key",
                description: "Private key found in source code",
                pattern: Regex::new(r"-----BEGIN\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----").unwrap(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                recommendation: "Remove the private key from source code. Store keys in a secure vault or use managed key services.",
                cwe_id: "CWE-321",
            },

            // ── JWT Secrets ──────────────────────────────────
            SecretPattern {
                rule_id: "ANTY-SEC-014",
                title: "Hardcoded JWT Secret",
                description: "Potential hardcoded JWT signing secret found",
                pattern: Regex::new(r#"(?i)(jwt[_-]?secret|jwt[_-]?key|token[_-]?secret)\s*[=:]\s*["'][^"']{8,}["']"#).unwrap(),
                severity: Severity::High,
                confidence: Confidence::Medium,
                recommendation: "Use environment variables for JWT secrets and ensure they are cryptographically random.",
                cwe_id: "CWE-798",
            },

            // ── Google ───────────────────────────────────────
            SecretPattern {
                rule_id: "ANTY-SEC-015",
                title: "Google API Key",
                description: "Google API key found in source code",
                pattern: Regex::new(r"(?i)(^|[^a-zA-Z0-9])(AIza[0-9A-Za-z\-_]{35})([^a-zA-Z0-9]|$)").unwrap(),
                severity: Severity::High,
                confidence: Confidence::Medium,
                recommendation: "Restrict the API key in Google Cloud Console and use environment variables.",
                cwe_id: "CWE-798",
            },

            // ── Heroku ───────────────────────────────────────
            SecretPattern {
                rule_id: "ANTY-SEC-016",
                title: "Heroku API Key",
                description: "Heroku API key found",
                pattern: Regex::new(r"(?i)(heroku[_-]?api[_-]?key|HEROKU_API_KEY)\s*[=:]\s*[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}").unwrap(),
                severity: Severity::High,
                confidence: Confidence::High,
                recommendation: "Remove the Heroku API key and regenerate it. Use environment variables.",
                cwe_id: "CWE-798",
            },

            // ── SendGrid ─────────────────────────────────────
            SecretPattern {
                rule_id: "ANTY-SEC-017",
                title: "SendGrid API Key",
                description: "SendGrid API key found in source code",
                pattern: Regex::new(r"(?i)(^|[^a-zA-Z0-9])(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})([^a-zA-Z0-9]|$)").unwrap(),
                severity: Severity::High,
                confidence: Confidence::High,
                recommendation: "Revoke the SendGrid key and use environment variables.",
                cwe_id: "CWE-798",
            },

            // ── Twilio ───────────────────────────────────────
            SecretPattern {
                rule_id: "ANTY-SEC-018",
                title: "Twilio API Key",
                description: "Twilio API key or auth token found",
                pattern: Regex::new(r"(?i)(twilio[_-]?(auth[_-]?token|api[_-]?key|api[_-]?secret))\s*[=:]\s*[a-f0-9]{32}").unwrap(),
                severity: Severity::High,
                confidence: Confidence::High,
                recommendation: "Rotate the Twilio credentials and use environment variables.",
                cwe_id: "CWE-798",
            },

            // ── Generic API Key ──────────────────────────────
            SecretPattern {
                rule_id: "ANTY-SEC-019",
                title: "Generic API Key Assignment",
                description: "Potential API key or secret assignment found",
                pattern: Regex::new(r#"(?i)(api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?key)\s*[=:]\s*["'][a-zA-Z0-9_\-/.+=]{16,}["']"#).unwrap(),
                severity: Severity::Medium,
                confidence: Confidence::Low,
                recommendation: "Verify if this is a real secret. If so, use environment variables or a secrets manager.",
                cwe_id: "CWE-798",
            },

            // ── .env file patterns ───────────────────────────
            SecretPattern {
                rule_id: "ANTY-SEC-020",
                title: "Secret in Environment File",
                description: "Potential secret value found in an environment file that may be committed to source control",
                pattern: Regex::new(r#"(?im)^(DB_PASSWORD|DATABASE_PASSWORD|SECRET_KEY|API_SECRET|PRIVATE_KEY|AUTH_TOKEN|ENCRYPTION_KEY)\s*=\s*\S{4,}"#).unwrap(),
                severity: Severity::High,
                confidence: Confidence::Medium,
                recommendation: "Ensure .env files are in .gitignore. Use .env.example with placeholder values instead.",
                cwe_id: "CWE-798",
            },
        ];

        SecretsAgent { patterns }
    }

    /// Check if a file should be skipped (binary, lock files, etc.)
    fn should_skip(file: &ScannedFile) -> bool {
        let path_str = file.rel_path.to_string_lossy().to_lowercase();

        // Skip common non-source files
        let skip_patterns = [
            "node_modules/",
            ".git/",
            "vendor/",
            "target/",
            ".next/",
            "dist/",
            "build/",
            "__pycache__/",
            ".pyc",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "Cargo.lock",
            "go.sum",
            "poetry.lock",
            "Gemfile.lock",
            ".min.js",
            ".min.css",
            ".map",
            ".wasm",
        ];

        skip_patterns.iter().any(|p| path_str.contains(p))
    }

    /// Redact the actual secret value in evidence
    fn redact_evidence(line: &str, secret_match: &str) -> String {
        if secret_match.len() <= 8 {
            return line.replace(secret_match, "****");
        }
        let prefix = &secret_match[..4];
        let suffix = &secret_match[secret_match.len() - 4..];
        let redacted = format!("{}…****…{}", prefix, suffix);
        line.replace(secret_match, &redacted)
    }
}

impl SecurityAgent for SecretsAgent {
    fn name(&self) -> &str {
        "secrets"
    }

    fn description(&self) -> &str {
        "Detects hardcoded secrets, API keys, tokens, and credentials"
    }

    fn scan_file(&self, file: &ScannedFile) -> Vec<Finding> {
        if Self::should_skip(file) {
            return Vec::new();
        }

        let mut findings = Vec::new();

        for (line_num, line) in file.content.lines().enumerate() {
            let line_number = line_num + 1; // 1-based

            // Skip comment-only lines that look like documentation
            let trimmed = line.trim();
            if trimmed.starts_with("//") && trimmed.contains("example") {
                continue;
            }

            for pattern in &self.patterns {
                if let Some(m) = pattern.pattern.find(line) {
                    let matched_text = m.as_str().trim();

                    // Build evidence with redacted secrets
                    let evidence = Self::redact_evidence(line.trim(), matched_text);

                    let finding = Finding {
                        id: Finding::generate_id(
                            pattern.rule_id,
                            &file.rel_path,
                            line_number,
                        ),
                        rule_id: pattern.rule_id.to_string(),
                        severity: pattern.severity,
                        confidence: pattern.confidence,
                        agent: "secrets".to_string(),
                        title: pattern.title.to_string(),
                        description: pattern.description.to_string(),
                        file_path: file.rel_path.clone(),
                        line_start: line_number,
                        line_end: line_number,
                        evidence,
                        recommendation: pattern.recommendation.to_string(),
                        cwe_id: Some(pattern.cwe_id.to_string()),
                    };

                    debug!(
                        "Secret found: {} in {}:{}",
                        pattern.rule_id,
                        file.rel_path.display(),
                        line_number
                    );

                    findings.push(finding);
                    break; // One finding per line per agent
                }
            }
        }

        findings
    }
}
