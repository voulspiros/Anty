use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

/// Anty configuration (loaded from .anty.toml)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntyConfig {
    #[serde(default)]
    pub scan: ScanConfig,

    #[serde(default)]
    pub agents: AgentsConfig,

    #[serde(default)]
    pub output: OutputConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanConfig {
    /// Glob patterns to exclude
    #[serde(default)]
    pub exclude: Vec<String>,

    /// Glob patterns to include
    #[serde(default)]
    pub include: Vec<String>,

    /// Max file size in bytes
    #[serde(default = "default_max_file_size")]
    pub max_file_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentsConfig {
    /// Agents to enable (empty = all)
    #[serde(default)]
    pub enable: Vec<String>,

    /// Agents to disable
    #[serde(default)]
    pub disable: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OutputConfig {
    /// Default output format
    #[serde(default = "default_format")]
    pub format: String,

    /// Minimum severity to report
    #[serde(default)]
    pub min_severity: Option<String>,
}

fn default_max_file_size() -> u64 {
    1_048_576 // 1MB
}

fn default_format() -> String {
    "terminal".to_string()
}

impl AntyConfig {
    /// Try to load .anty.toml from the given directory or its parents
    pub fn load(scan_path: &Path) -> Option<Self> {
        let config_path = find_config_file(scan_path)?;
        debug!("Found config: {}", config_path.display());

        match std::fs::read_to_string(&config_path) {
            Ok(content) => match toml::from_str::<AntyConfig>(&content) {
                Ok(config) => {
                    info!("Loaded config from {}", config_path.display());
                    Some(config)
                }
                Err(e) => {
                    tracing::warn!("Failed to parse {}: {}", config_path.display(), e);
                    None
                }
            },
            Err(e) => {
                debug!("Could not read {}: {}", config_path.display(), e);
                None
            }
        }
    }
}

/// Walk up from the scan path to find .anty.toml
fn find_config_file(start: &Path) -> Option<std::path::PathBuf> {
    let mut current = start.to_path_buf();
    loop {
        let config = current.join(".anty.toml");
        if config.exists() {
            return Some(config);
        }
        if !current.pop() {
            return None;
        }
    }
}

/// Create a default .anty.toml in the current directory
pub fn init_config() -> Result<()> {
    let config_path = std::env::current_dir()?.join(".anty.toml");

    if config_path.exists() {
        println!("⚠️  .anty.toml already exists in this directory");
        return Ok(());
    }

    let default_config = r#"# Anty Security Scanner Configuration
# https://anty.dev/docs/config

[scan]
# Glob patterns to exclude from scanning
exclude = [
    "tests/fixtures/**",
    "**/*.test.*",
    "**/*.spec.*",
]

# Max file size to scan (bytes). Default: 1MB
# max_file_size = 1048576

[agents]
# Enable specific agents (empty = all)
# enable = ["secrets", "dangerous-functions", "config-issues"]

# Disable specific agents
# disable = []

[output]
# Default output format: "terminal" or "json"
format = "terminal"

# Minimum severity to report: "LOW", "MEDIUM", "HIGH", "CRITICAL"
# min_severity = "LOW"
"#;

    std::fs::write(&config_path, default_config)?;
    println!("✅ Created .anty.toml");
    println!("   Edit it to customize your scan settings.");

    Ok(())
}
