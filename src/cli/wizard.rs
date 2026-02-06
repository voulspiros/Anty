use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;
use owo_colors::OwoColorize;

use crate::cli::{Cli, ScanArgs};
use crate::config;
use crate::engine::Scanner;
use crate::report;
use crate::rules;

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

    // Minimal Cli struct to satisfy Scanner::new's signature.
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
    print!("  {} ", "Save JSON report? (y/N):".bold());
    io::stdout().flush().ok();
    let answer = read_line();

    if answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes") {
        let default_name = "anty-report.json";
        print!("  Filename [{}]: ", default_name.dimmed());
        io::stdout().flush().ok();
        let filename = read_line();
        let filename = if filename.is_empty() {
            default_name.to_string()
        } else {
            filename
        };

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

// ── Wizard screens ──────────────────────────────────────────────────

/// A) Welcome screen — large yellow ASCII logo
fn screen_welcome() {
    println!();

    // Print logo in yellow
    for line in LOGO.lines() {
        println!("{}", line.yellow().bold());
    }

    println!(
        "  {}  {}",
        "🐜",
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

/// C) Trust folder prompt — returns `true` if user trusts the folder.
fn screen_trust_folder() -> bool {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    println!();
    separator();
    println!(
        "  {} {}",
        "📂",
        "Do you trust the files in this folder?".bold()
    );
    separator();
    println!();
    println!("    {}", cwd.display().to_string().cyan().bold());
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
    println!("    {} Yes, proceed", "1)".bold());
    println!("    {} No, exit", "2)".bold());
    println!();

    loop {
        print!("  Your choice [1/2]: ");
        io::stdout().flush().ok();
        let choice = read_line();
        match choice.as_str() {
            "1" | "yes" | "y" => return true,
            "2" | "no" | "n" => return false,
            _ => println!("  {}", "Please enter 1 or 2.".yellow()),
        }
    }
}

/// D) Quick-actions menu — returns the chosen action.
enum QuickAction {
    ScanCwd,
    ScanPath(PathBuf),
    InitConfig,
    ListRules,
    Exit,
}

fn screen_quick_actions() -> QuickAction {
    println!();
    separator();
    println!(
        "  {} {}",
        "⚡",
        "What would you like to do?".bold()
    );
    separator();
    println!();
    println!("    {}  Scan current folder", "[1]".yellow().bold());
    println!("    {}  Scan another folder", "[2]".yellow().bold());
    println!("    {}  Initialize .anty.toml", "[3]".yellow().bold());
    println!("    {}  List security rules", "[4]".yellow().bold());
    println!("    {}  Exit", "[5]".yellow().bold());
    println!();

    loop {
        print!("  Your choice [1-5]: ");
        io::stdout().flush().ok();
        let choice = read_line();
        match choice.as_str() {
            "1" => return QuickAction::ScanCwd,
            "2" => {
                print!("  Path to scan: ");
                io::stdout().flush().ok();
                let p = read_line();
                let path = PathBuf::from(&p);
                if path.is_dir() {
                    return QuickAction::ScanPath(path);
                } else {
                    println!(
                        "  {} \"{}\" is not a valid directory.",
                        "⚠".yellow(),
                        p
                    );
                    // re-prompt menu
                }
            }
            "3" => return QuickAction::InitConfig,
            "4" => return QuickAction::ListRules,
            "5" => return QuickAction::Exit,
            _ => println!("  {}", "Please enter a number from 1 to 5.".yellow()),
        }
    }
}

// ── Public entry-points ─────────────────────────────────────────────

/// Interactive onboarding wizard (no-args mode).
pub fn run_wizard() -> Result<()> {
    init_quiet_logging();

    // A) Welcome
    screen_welcome();

    // B) Security notes
    screen_security_notes();

    // C) Trust folder
    if !screen_trust_folder() {
        println!();
        println!("  {}", "Goodbye! 👋".dimmed());
        std::process::exit(0);
    }

    // D) Quick actions
    match screen_quick_actions() {
        QuickAction::ScanCwd => {
            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            execute_scan(&cwd)?;
        }
        QuickAction::ScanPath(p) => {
            execute_scan(&p)?;
        }
        QuickAction::InitConfig => {
            config::init_config()?;
            println!();
            println!(
                "  {} .anty.toml created in current directory.",
                "✅".bold()
            );
        }
        QuickAction::ListRules => {
            println!();
            rules::list_rules();
        }
        QuickAction::Exit => {
            println!();
            println!("  {}", "Goodbye! 👋".dimmed());
        }
    }

    println!();
    press_enter("  Press Enter to exit...");
    Ok(())
}

/// Drag-and-drop mode: a single directory was passed without a subcommand.
pub fn run_drag_drop(path: &Path) -> Result<()> {
    init_quiet_logging();

    // Print a compact header
    println!();
    for line in LOGO.lines() {
        println!("{}", line.yellow().bold());
    }
    separator();
    println!();
    println!(
        "  Scan this folder?  {}",
        path.display().to_string().cyan().bold()
    );
    println!();
    print!("  {} ", "(Y/n):".bold());
    io::stdout().flush().ok();
    let answer = read_line();

    if answer.is_empty()
        || answer.eq_ignore_ascii_case("y")
        || answer.eq_ignore_ascii_case("yes")
    {
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
