use clap::Subcommand;
use std::path::PathBuf;

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Scan a directory for security issues
    Scan(ScanArgs),

    /// Initialize an .anty.toml config file in the current directory
    Init,

    /// List all available security rules
    ListRules,
}

#[derive(clap::Args, Debug)]
pub struct ScanArgs {
    /// Path to scan (defaults to current directory)
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Output format: "terminal" or "json"
    #[arg(short, long, default_value = "terminal")]
    pub format: String,

    /// Write report to file
    #[arg(short, long)]
    pub out: Option<PathBuf>,

    /// Fail (exit code 1) if findings at or above this severity are found.
    /// Values: CRITICAL, HIGH, MEDIUM, LOW
    #[arg(long)]
    pub fail_on: Option<String>,

    /// Maximum file size in bytes to scan (skip larger files)
    #[arg(long, default_value = "1048576")]
    pub max_file_size: u64,

    /// Glob patterns to include (can be repeated)
    #[arg(long)]
    pub include: Vec<String>,

    /// Glob patterns to exclude (can be repeated)
    #[arg(long)]
    pub exclude: Vec<String>,

    /// Only scan files changed in git (compared to HEAD)
    #[arg(long)]
    pub changed_only: bool,

    /// Agents to run (comma-separated). Default: all
    #[arg(long)]
    pub agents: Option<String>,

    /// Ignore .anty.toml config files found in the scanned repository.
    /// Recommended when scanning untrusted code.
    #[arg(long)]
    pub no_config: bool,

    /// Maximum number of findings to report (0 = unlimited)
    #[arg(long, default_value = "1000")]
    pub max_findings: usize,
}
