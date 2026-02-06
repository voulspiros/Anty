pub mod commands;
pub mod wizard;

use clap::Parser;

pub use commands::{Commands, ScanArgs};

/// Anty — Developer-first security scanner
///
/// Like a team of security reviewers reading your code.
/// Finds hardcoded secrets, injection vulnerabilities, auth issues, and more.
#[derive(Parser, Debug)]
#[command(
    name = "anty",
    version,
    about = "🐜 Anty — Developer-first security scanner",
    long_about = "Anty scans your source code for security issues.\nIt works locally, never uploads your code, and gives fast feedback.\n\nLike a team of security reviewers reading your code."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Enable verbose output (debug level)
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Suppress all output except errors
    #[arg(short, long, global = true)]
    pub quiet: bool,
}
