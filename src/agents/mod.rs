pub mod secrets;
pub mod dangerous_functions;
pub mod config_issues;

use crate::report::finding::Finding;

/// A scanned file with its content ready for analysis
#[derive(Debug, Clone)]
pub struct ScannedFile {
    /// Relative path from scan root
    pub rel_path: std::path::PathBuf,
    /// Absolute path
    #[allow(dead_code)]
    pub abs_path: std::path::PathBuf,
    /// File content as string
    pub content: String,
    /// Detected language (if any)
    pub language: Option<Language>,
}

/// Supported languages
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    JavaScript,
    TypeScript,
    Python,
    Rust,
    Go,
    Java,
    Ruby,
    Php,
    CSharp,
    Shell,
    Yaml,
    Json,
    Toml,
    Dockerfile,
    Env,
    Unknown,
}

impl Language {
    /// Detect language from file extension
    pub fn from_extension(ext: &str) -> Self {
        match ext.to_lowercase().as_str() {
            "js" | "mjs" | "cjs" | "jsx" => Language::JavaScript,
            "ts" | "tsx" | "mts" | "cts" => Language::TypeScript,
            "py" | "pyw" => Language::Python,
            "rs" => Language::Rust,
            "go" => Language::Go,
            "java" => Language::Java,
            "rb" => Language::Ruby,
            "php" => Language::Php,
            "cs" => Language::CSharp,
            "sh" | "bash" | "zsh" => Language::Shell,
            "yml" | "yaml" => Language::Yaml,
            "json" => Language::Json,
            "toml" => Language::Toml,
            "env" => Language::Env,
            _ => Language::Unknown,
        }
    }

    /// Detect from filename (for files without extension)
    pub fn from_filename(name: &str) -> Self {
        match name.to_lowercase().as_str() {
            "dockerfile" | "containerfile" => Language::Dockerfile,
            ".env" | ".env.local" | ".env.production" | ".env.development" => Language::Env,
            _ => Language::Unknown,
        }
    }
}

/// The core security agent trait.
/// Each agent is an independent security reviewer focused on a specific domain.
pub trait SecurityAgent: Send + Sync {
    /// Agent name (e.g. "secrets", "injection")
    fn name(&self) -> &str;

    /// Short description of what this agent looks for
    fn description(&self) -> &str;

    /// Run the agent against a single file and return findings
    fn scan_file(&self, file: &ScannedFile) -> Vec<Finding>;
}

/// Registry of all available agents
pub fn all_agents() -> Vec<Box<dyn SecurityAgent>> {
    vec![
        Box::new(secrets::SecretsAgent::new()),
        Box::new(dangerous_functions::DangerousFunctionsAgent::new()),
        Box::new(config_issues::ConfigIssuesAgent::new()),
    ]
}

/// Get agents filtered by name (comma-separated)
pub fn agents_by_names(names: &str) -> Vec<Box<dyn SecurityAgent>> {
    let requested: Vec<&str> = names.split(',').map(|s| s.trim()).collect();
    all_agents()
        .into_iter()
        .filter(|a| requested.iter().any(|name| a.name().eq_ignore_ascii_case(name)))
        .collect()
}
