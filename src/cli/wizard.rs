use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use inquire::{Confirm, Select, Text};
use owo_colors::OwoColorize;

use crate::cli::{Cli, ScanArgs};
use crate::engine::Scanner;
use crate::report;

// ── Constants ────────────────────────────────────────────────────────

/// Large ASCII logo — rendered in yellow at runtime.
const LOGO: &str = r#"
     █████╗  ███╗   ██╗ ████████╗ ██╗   ██╗
    ██╔══██╗ ████╗  ██║ ╚══██╔══╝ ╚██╗ ██╔╝
    ███████║ ██╔██╗ ██║    ██║     ╚████╔╝
    ██╔══██║ ██║╚██╗██║    ██║      ╚██╔╝
    ██║  ██║ ██║ ╚████║    ██║       ██║
    ╚═╝  ╚═╝ ╚═╝  ╚═══╝    ╚═╝       ╚═╝
"#;

/// File extensions we consider "binary" and skip in file pickers.
const BINARY_EXTENSIONS: &[&str] = &[
    "exe", "dll", "so", "dylib", "o", "a", "lib", "obj", "bin", "class",
    "jar", "war", "ear", "pyc", "pyo", "wasm", "png", "jpg", "jpeg",
    "gif", "bmp", "ico", "svg", "webp", "mp3", "mp4", "avi", "mov",
    "mkv", "flac", "wav", "ogg", "zip", "tar", "gz", "bz2", "xz",
    "7z", "rar", "iso", "dmg", "pdf", "doc", "docx", "xls", "xlsx",
    "ppt", "pptx", "ttf", "otf", "woff", "woff2", "eot",
];

// ── Helpers ──────────────────────────────────────────────────────────

/// Read a line of input from stdin, trimmed.
fn read_line() -> String {
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).unwrap_or_default();
    buf.trim().to_string()
}

/// Pause until the user presses Enter.
fn press_enter(prompt: &str) {
    print!("{}", prompt.dimmed());
    io::stdout().flush().ok();
    let _ = read_line();
}

/// Print a horizontal separator.
fn separator() {
    println!("{}", "━".repeat(60));
}

/// Expand a user-entered path: handle `~` and trim quotes.
fn expand_path(input: &str) -> PathBuf {
    let trimmed = input.trim().trim_matches('"').trim_matches('\'');

    // Expand ~ on any OS
    if trimmed.starts_with('~') {
        if let Some(home) = home_dir() {
            let rest = trimmed.strip_prefix("~/").or(trimmed.strip_prefix("~\\")).unwrap_or("");
            return home.join(rest);
        }
    }

    PathBuf::from(trimmed)
}

/// Best-effort home directory.
fn home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var("USERPROFILE").ok().map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        std::env::var("HOME").ok().map(PathBuf::from)
    }
}

/// Get a good starting directory for browsing.
fn default_browse_dir() -> PathBuf {
    #[cfg(windows)]
    {
        // Try Desktop first, then USERPROFILE, then cwd
        if let Some(home) = home_dir() {
            let desktop = home.join("Desktop");
            if desktop.is_dir() {
                return desktop;
            }
            return home;
        }
    }
    #[cfg(not(windows))]
    {
        if let Some(home) = home_dir() {
            return home;
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

/// Check if a file extension looks binary.
fn is_binary_ext(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| BINARY_EXTENSIONS.contains(&ext.to_lowercase().as_str()))
}

// ── Scan execution (reuses the engine) ──────────────────────────────

/// Build default ScanArgs for a given path.
fn default_scan_args(path: &Path) -> ScanArgs {
    ScanArgs {
        path: PathBuf::from(path),
        format: "terminal".to_string(),
        out: None,
        fail_on: None,
        max_file_size: 1_048_576,
        include: Vec::new(),
        exclude: Vec::new(),
        changed_only: false,
        agents: None,
        no_config: false,
        max_findings: 1000,
    }
}

/// Run the scan engine with wizard-friendly defaults and display results.
fn execute_scan(path: &Path) -> Result<()> {
    let args = default_scan_args(path);

    let cli = Cli {
        command: crate::cli::Commands::Scan(default_scan_args(path)),
        verbose: false,
        quiet: false,
    };

    println!();
    println!(
        "  {} Scanning {}",
        "🔍".bold(),
        path.display().to_string().cyan()
    );
    println!();

    let scanner = Scanner::new(&cli, &args)?;
    let scan_report = scanner.run()?;

    // Render to terminal
    report::terminal::render(&scan_report);

    // Summary bar
    separator();
    println!(
        "  {} {}  |  {} critical  {} high  {} medium  {} low",
        "📊".bold(),
        format!("{} issues found", scan_report.summary.total).bold(),
        scan_report.summary.critical.to_string().red().bold(),
        scan_report.summary.high.to_string().yellow().bold(),
        scan_report.summary.medium.to_string().blue(),
        scan_report.summary.low.to_string().dimmed(),
    );
    separator();
    println!();

    // Ask if the user wants a JSON report saved
    let save = Confirm::new("Save JSON report?")
        .with_default(false)
        .prompt()
        .unwrap_or(false);

    if save {
        let filename = Text::new("Filename:")
            .with_default("anty-report.json")
            .prompt()
            .unwrap_or_else(|_| "anty-report.json".to_string());

        let json = report::json::render(&scan_report)?;
        std::fs::write(&filename, &json)?;
        println!(
            "  {} Report written to {}",
            "✅".bold(),
            filename.green()
        );
    }

    println!();
    Ok(())
}

// ── Interactive pickers ─────────────────────────────────────────────

/// B) Pick a target folder — text input or interactive browser.
fn pick_target_folder() -> Result<PathBuf> {
    println!();
    separator();
    println!(
        "  📂 {}",
        "Where do you want to scan?".bold()
    );
    separator();
    println!();

    loop {
        let input = Text::new("Type a folder path (or press Enter to browse):")
            .with_help_message("Paste a path, or leave empty to browse directories")
            .prompt()
            .context("Wizard cancelled")?;

        if input.trim().is_empty() {
            // Interactive folder browser
            match browse_folders(default_browse_dir()) {
                Ok(Some(p)) => return Ok(p),
                Ok(None) => {
                    // User cancelled browsing, re-prompt
                    println!("  {}", "Browsing cancelled. Try typing a path instead.".dimmed());
                    continue;
                }
                Err(e) => {
                    println!("  {} {}", "⚠".yellow(), e);
                    continue;
                }
            }
        }

        let path = expand_path(&input);
        if path.is_dir() {
            return Ok(std::fs::canonicalize(&path).unwrap_or(path));
        } else if path.is_file() {
            println!(
                "  {} That's a file. Please enter a {} path.",
                "⚠".yellow(),
                "folder".bold()
            );
        } else {
            println!(
                "  {} \"{}\" does not exist. Please try again.",
                "⚠".yellow(),
                path.display()
            );
        }
    }
}

/// Interactive folder browser using Select prompts.
fn browse_folders(start: PathBuf) -> Result<Option<PathBuf>> {
    let mut current = start;

    loop {
        let mut entries = vec![">>> [Select this folder] <<<".to_string()];
        entries.push(".. (parent directory)".to_string());

        // List subdirectories
        let mut dirs: Vec<String> = Vec::new();
        if let Ok(read_dir) = std::fs::read_dir(&current) {
            for entry in read_dir.flatten() {
                if let Ok(ft) = entry.file_type() {
                    if ft.is_dir() {
                        if let Some(name) = entry.file_name().to_str() {
                            // Skip hidden directories
                            if !name.starts_with('.') {
                                dirs.push(name.to_string());
                            }
                        }
                    }
                }
            }
        }
        dirs.sort_by_key(|a| a.to_lowercase());

        for d in &dirs {
            entries.push(format!("📁 {d}"));
        }

        let prompt_msg = format!("Browse: {}", current.display());
        let selection = Select::new(&prompt_msg, entries)
            .with_help_message("↑/↓ navigate, Enter to open/select, Esc to cancel")
            .prompt_skippable()
            .context("Browse cancelled")?;

        match selection {
            None => return Ok(None), // Esc pressed
            Some(ref s) if s.starts_with(">>> ") => {
                return Ok(Some(current));
            }
            Some(ref s) if s.starts_with(".. ") => {
                if let Some(parent) = current.parent() {
                    current = parent.to_path_buf();
                }
            }
            Some(ref s) if s.starts_with("📁 ") => {
                let dir_name = s.trim_start_matches("📁 ");
                current = current.join(dir_name);
            }
            _ => {}
        }
    }
}

/// C) Trust prompt for a specific path.
fn confirm_trust(target: &Path) -> bool {
    println!();
    separator();
    println!(
        "  🔒 {}",
        "Do you trust the files in this folder?".bold()
    );
    separator();
    println!();
    println!("    {}", target.display().to_string().cyan().bold());
    println!();
    println!(
        "  {}",
        "Anty will read files in this folder to scan for security issues.".dimmed()
    );
    println!(
        "  {}",
        "It will NOT execute code.".dimmed()
    );
    println!();

    Confirm::new("Proceed with scan?")
        .with_default(true)
        .prompt()
        .unwrap_or(false)
}

/// D) Scope selection — scan whole folder or single file.
#[derive(Debug, Clone, Copy)]
enum ScanScope {
    Folder,
    SingleFile,
}

fn pick_scope() -> Result<ScanScope> {
    let options = vec![
        "Entire folder (all files)",
        "A single file",
    ];

    let choice = Select::new("What do you want to scan?", options)
        .with_help_message("↑/↓ navigate, Enter to select")
        .prompt()
        .context("Wizard cancelled")?;

    if choice.starts_with("A single") {
        Ok(ScanScope::SingleFile)
    } else {
        Ok(ScanScope::Folder)
    }
}

/// E) Interactive file picker inside a directory.
fn pick_single_file(dir: &Path) -> Result<Option<PathBuf>> {
    let mut files: Vec<String> = Vec::new();

    if let Ok(read_dir) = std::fs::read_dir(dir) {
        for entry in read_dir.flatten() {
            if let Ok(ft) = entry.file_type() {
                if ft.is_file() {
                    let path = entry.path();
                    // Skip binary files
                    if is_binary_ext(&path) {
                        continue;
                    }
                    // Skip files > 2 MB
                    if let Ok(meta) = entry.metadata() {
                        if meta.len() > 2_097_152 {
                            continue;
                        }
                    }
                    if let Some(name) = entry.file_name().to_str() {
                        if !name.starts_with('.') {
                            files.push(name.to_string());
                        }
                    }
                }
            }
        }
    }

    if files.is_empty() {
        println!(
            "  {} No scannable files found in {}",
            "⚠".yellow(),
            dir.display()
        );
        return Ok(None);
    }

    files.sort_by_key(|a| a.to_lowercase());

    let prompt_msg = format!("Select a file from {}", dir.display());
    let selection = Select::new(&prompt_msg, files)
        .with_help_message("↑/↓ navigate, Enter to select, Esc to cancel")
        .with_page_size(15)
        .prompt_skippable()
        .context("File selection cancelled")?;

    match selection {
        Some(name) => Ok(Some(dir.join(name))),
        None => Ok(None),
    }
}

// ── Wizard screens ──────────────────────────────────────────────────

/// A) Welcome screen — large yellow ASCII logo
fn screen_welcome() {
    println!();
    for line in LOGO.lines() {
        println!("{}", line.yellow().bold());
    }

    println!(
        "  🐜  {}",
        format!("v{}", env!("CARGO_PKG_VERSION")).dimmed()
    );
    println!();
    println!(
        "  {}",
        "Developer-first security scanner".bold()
    );
    println!(
        "  {}",
        "Anty scans your code locally and never uploads it.".dimmed()
    );
    println!();
    separator();
    println!();
    press_enter("  Press Enter to continue...");
}

/// B) Security & privacy notes
fn screen_security_notes() {
    println!();
    println!("  {}", "Security & Privacy".bold().underline());
    println!();
    println!(
        "  {}  Anty {} executes scanned code — it only reads files.",
        "•".green(),
        "never".bold()
    );
    println!(
        "  {}  Scans run {} on your machine. Nothing is uploaded.",
        "•".green(),
        "locally".bold()
    );
    println!(
        "  {}  No telemetry, no tracking, no network calls.",
        "•".green(),
    );
    println!();
    press_enter("  Press Enter to continue...");
}

// ── Public entry-points ─────────────────────────────────────────────

/// Interactive onboarding wizard (no-args mode).
pub fn run_wizard() -> Result<()> {
    init_quiet_logging();

    // A) Welcome
    screen_welcome();

    // B) Security notes
    screen_security_notes();

    // C) Target selection — user picks a folder
    let target = match pick_target_folder() {
        Ok(t) => t,
        Err(_) => {
            println!();
            println!("  {}", "Wizard cancelled. Goodbye! 👋".dimmed());
            press_enter("  Press Enter to exit...");
            return Ok(());
        }
    };

    // D) Trust prompt for the chosen target
    if !confirm_trust(&target) {
        println!();
        println!("  {}", "Scan cancelled. Goodbye! 👋".dimmed());
        press_enter("  Press Enter to exit...");
        return Ok(());
    }

    // E) Scope selection
    let scope = match pick_scope() {
        Ok(s) => s,
        Err(_) => {
            println!();
            println!("  {}", "Wizard cancelled. Goodbye! 👋".dimmed());
            press_enter("  Press Enter to exit...");
            return Ok(());
        }
    };

    // F) Execute scan
    match scope {
        ScanScope::Folder => {
            execute_scan(&target)?;
        }
        ScanScope::SingleFile => {
            match pick_single_file(&target) {
                Ok(Some(file_path)) => {
                    execute_scan(&file_path)?;
                }
                Ok(None) => {
                    println!("  {}", "No file selected.".dimmed());
                }
                Err(_) => {
                    println!("  {}", "File selection cancelled.".dimmed());
                }
            }
        }
    }

    press_enter("  Press Enter to exit...");
    Ok(())
}

/// Drag-and-drop mode: a single directory was passed without a subcommand.
pub fn run_drag_drop(path: &Path) -> Result<()> {
    init_quiet_logging();

    println!();
    for line in LOGO.lines() {
        println!("{}", line.yellow().bold());
    }
    separator();
    println!();

    let proceed = Confirm::new(&format!("Scan this folder?  {}", path.display()))
        .with_default(true)
        .prompt()
        .unwrap_or(false);

    if proceed {
        execute_scan(path)?;
    } else {
        println!("  {}", "Scan cancelled.".dimmed());
    }

    press_enter("  Press Enter to exit...");
    Ok(())
}

/// Set up minimal tracing so the scan engine works without the full CLI
/// log initialisation (which requires the parsed Cli struct).
fn init_quiet_logging() {
    use tracing_subscriber::EnvFilter;

    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("anty=info"))
        .with_target(false)
        .without_time()
        .try_init();
}
