use regex::Regex;
use tracing::debug;

use crate::agents::{Language, ScannedFile, SecurityAgent};
use crate::report::finding::{Confidence, Finding, Severity};

/// Pattern for a dangerous function call
struct DangerousPattern {
    rule_id: &'static str,
    title: &'static str,
    description: &'static str,
    pattern: Regex,
    severity: Severity,
    confidence: Confidence,
    recommendation: &'static str,
    cwe_id: &'static str,
    languages: &'static [Language],
}

impl DangerousPattern {
    fn applies_to(&self, lang: Option<Language>) -> bool {
        if self.languages.is_empty() {
            return true; // language-agnostic
        }
        match lang {
            Some(l) => self.languages.contains(&l),
            None => true, // unknown language = check anyway
        }
    }
}

/// Detects usage of dangerous functions and patterns that commonly
/// lead to security vulnerabilities.
///
/// Level A agent — regex/string-based, no AST required.
pub struct DangerousFunctionsAgent {
    patterns: Vec<DangerousPattern>,
}

impl DangerousFunctionsAgent {
    pub fn new() -> Self {
        let patterns = vec![
            // ── eval / exec ──────────────────────────────────
            DangerousPattern {
                rule_id: "ANTY-DNG-001",
                title: "Use of eval()",
                description: "eval() executes arbitrary code and is a common injection vector",
                pattern: Regex::new(r"\beval\s*\(").unwrap(),
                severity: Severity::High,
                confidence: Confidence::Medium,
                recommendation: "Avoid eval(). Use JSON.parse() for data, or safer alternatives for dynamic execution.",
                cwe_id: "CWE-95",
                languages: &[Language::JavaScript, Language::TypeScript, Language::Python],
            },
            DangerousPattern {
                rule_id: "ANTY-DNG-002",
                title: "Use of exec()",
                description: "exec() can execute arbitrary system commands",
                pattern: Regex::new(r"(?i)\b(child_process\.exec|subprocess\.call|os\.system|exec)\s*\(").unwrap(),
                severity: Severity::High,
                confidence: Confidence::Medium,
                recommendation: "Use parameterized command execution (e.g., subprocess.run with a list of args, execFile instead of exec).",
                cwe_id: "CWE-78",
                languages: &[Language::JavaScript, Language::TypeScript, Language::Python],
            },

            // ── SQL string building ──────────────────────────
            DangerousPattern {
                rule_id: "ANTY-DNG-003",
                title: "SQL Query String Concatenation",
                description: "SQL query built using string concatenation — potential SQL injection",
                pattern: Regex::new(r#"(?i)(SELECT|INSERT|UPDATE|DELETE|DROP)\s+.{0,30}["']\s*\+|\+\s*["'].{0,30}(SELECT|INSERT|UPDATE|DELETE|DROP)"#).unwrap(),
                severity: Severity::High,
                confidence: Confidence::Medium,
                recommendation: "Use parameterized queries or prepared statements instead of string concatenation.",
                cwe_id: "CWE-89",
                languages: &[],
            },
            DangerousPattern {
                rule_id: "ANTY-DNG-004",
                title: "SQL Query Template Literal Interpolation",
                description: "SQL query built using template literal interpolation — potential SQL injection",
                pattern: Regex::new(r"(?i)(SELECT|INSERT|UPDATE|DELETE)\s+.*\$\{").unwrap(),
                severity: Severity::High,
                confidence: Confidence::Medium,
                recommendation: "Use parameterized queries. Template literals with user input are as dangerous as string concatenation.",
                cwe_id: "CWE-89",
                languages: &[Language::JavaScript, Language::TypeScript],
            },
            DangerousPattern {
                rule_id: "ANTY-DNG-005",
                title: "SQL Query f-string / format()",
                description: "SQL query built using Python f-string or .format() — potential SQL injection",
                pattern: Regex::new(r#"(?i)(SELECT|INSERT|UPDATE|DELETE)\s+.*(\{[a-zA-Z_]|\.format\(|%\s*[^%])"#).unwrap(),
                severity: Severity::High,
                confidence: Confidence::Medium,
                recommendation: "Use parameterized queries with cursor.execute(sql, params) instead of f-strings.",
                cwe_id: "CWE-89",
                languages: &[Language::Python],
            },

            // ── Deserialization ───────────────────────────────
            DangerousPattern {
                rule_id: "ANTY-DNG-006",
                title: "Unsafe Deserialization (pickle)",
                description: "pickle.loads() can execute arbitrary code during deserialization",
                pattern: Regex::new(r"\bpickle\.(loads?|Unpickler)\s*\(").unwrap(),
                severity: Severity::High,
                confidence: Confidence::High,
                recommendation: "Avoid pickle for untrusted data. Use JSON or a safe serialization format.",
                cwe_id: "CWE-502",
                languages: &[Language::Python],
            },
            DangerousPattern {
                rule_id: "ANTY-DNG-007",
                title: "Unsafe YAML Loading",
                description: "yaml.load() without SafeLoader can execute arbitrary code",
                pattern: Regex::new(r"\byaml\.load\s*\([^)]*\)").unwrap(),
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                recommendation: "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).",
                cwe_id: "CWE-502",
                languages: &[Language::Python],
            },

            // ── XSS patterns ─────────────────────────────────
            DangerousPattern {
                rule_id: "ANTY-DNG-008",
                title: "innerHTML Assignment",
                description: "Setting innerHTML with dynamic content can lead to XSS",
                pattern: Regex::new(r"\.innerHTML\s*=").unwrap(),
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                recommendation: "Use textContent for text, or sanitize HTML with a library like DOMPurify.",
                cwe_id: "CWE-79",
                languages: &[Language::JavaScript, Language::TypeScript],
            },
            DangerousPattern {
                rule_id: "ANTY-DNG-009",
                title: "dangerouslySetInnerHTML in React",
                description: "dangerouslySetInnerHTML can introduce XSS if input is not sanitized",
                pattern: Regex::new(r"dangerouslySetInnerHTML").unwrap(),
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                recommendation: "Sanitize the HTML content with DOMPurify before passing it to dangerouslySetInnerHTML.",
                cwe_id: "CWE-79",
                languages: &[Language::JavaScript, Language::TypeScript],
            },

            // ── Crypto ───────────────────────────────────────
            DangerousPattern {
                rule_id: "ANTY-DNG-010",
                title: "Use of MD5 Hashing",
                description: "MD5 is cryptographically broken and should not be used for security purposes",
                pattern: Regex::new(r#"(?i)(md5|createHash\s*\(\s*["']md5["']|hashlib\.md5)"#).unwrap(),
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                recommendation: "Use SHA-256 or better. For password hashing, use bcrypt, scrypt, or Argon2.",
                cwe_id: "CWE-328",
                languages: &[],
            },
            DangerousPattern {
                rule_id: "ANTY-DNG-011",
                title: "Use of SHA-1 Hashing",
                description: "SHA-1 is deprecated for security use cases due to collision attacks",
                pattern: Regex::new(r#"(?i)(createHash\s*\(\s*["']sha1["']|hashlib\.sha1|SHA1|DigestUtils\.sha1)"#).unwrap(),
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                recommendation: "Use SHA-256 or SHA-3. For password hashing, use bcrypt, scrypt, or Argon2.",
                cwe_id: "CWE-328",
                languages: &[],
            },

            // ── Shell injection ──────────────────────────────
            DangerousPattern {
                rule_id: "ANTY-DNG-012",
                title: "Shell Command with shell=True",
                description: "subprocess with shell=True is vulnerable to shell injection",
                pattern: Regex::new(r"subprocess\.\w+\s*\([^)]*shell\s*=\s*True").unwrap(),
                severity: Severity::High,
                confidence: Confidence::High,
                recommendation: "Use subprocess.run() with a list of arguments and shell=False (default).",
                cwe_id: "CWE-78",
                languages: &[Language::Python],
            },
        ];

        DangerousFunctionsAgent { patterns }
    }
}

impl SecurityAgent for DangerousFunctionsAgent {
    fn name(&self) -> &str {
        "dangerous-functions"
    }

    fn description(&self) -> &str {
        "Detects dangerous function calls: eval, exec, SQL injection patterns, unsafe deserialization, weak crypto"
    }

    fn scan_file(&self, file: &ScannedFile) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (line_num, line) in file.content.lines().enumerate() {
            let line_number = line_num + 1;

            // Skip comment lines
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with("#") || trimmed.starts_with("*") {
                continue;
            }

            for pattern in &self.patterns {
                if !pattern.applies_to(file.language) {
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
                        agent: "dangerous-functions".to_string(),
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
                        "Dangerous function: {} in {}:{}",
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
