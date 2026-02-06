use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;
use owo_colors::OwoColorize;

use crate::cli::{Cli, ScanArgs};
use crate::engine::Scanner;
use crate::report;

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

/// Run the scan engine with wizard-friendly defaults and display results.
fn execute_scan(path: &Path) -> Result<()> {
    // Build a minimal ScanArgs pointing at the chosen path.
    let args = ScanArgs {
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
    };

    // We need a Cli struct just to satisfy Scanner::new's signature.
    // verbose=false, quiet=false are safe defaults.
    let cli = Cli {
        command: crate::cli::Commands::Scan(ScanArgs {
            path: args.path.clone(),
            format: args.format.clone(),
            out: None,
            fail_on: None,
            max_file_size: args.max_file_size,
            include: Vec::new(),
            exclude: Vec::new(),
            changed_only: false,
            agents: None,
            no_config: false,
            max_findings: args.max_findings,
        }),
        verbose: false,
        quiet: false,
    };

    let scanner = Scanner::new(&cli, &args)?;
    let scan_report = scanner.run()?;

    // Render to terminal
    report::terminal::render(&scan_report);

    // Ask if the user wants a JSON report saved
    print!(
        "  {} ",
        "Save JSON report? (y/N):".bold()
    );
    io::stdout().flush().ok();
    let answer = read_line();

    if answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes") {
        let default_name = "anty-report.json";
        print!(
            "  Filename [{}]: ",
            default_name.dimmed()
        );
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

    // Summary line
    println!();
    separator();
    println!(
        "  {} findings: {} critical, {} high, {} medium, {} low",
        scan_report.summary.total.to_string().bold(),
        scan_report.summary.critical.to_string().red(),
        scan_report.summary.high.to_string().yellow(),
        scan_report.summary.medium.to_string().blue(),
        scan_report.summary.low,
    );
    separator();
    println!();

    Ok(())
}

// ── Wizard screens ──────────────────────────────────────────────────

/// A) Welcome screen
fn screen_welcome() {
    println!();
    separator();
    println!(
        "  {} {}",
        "🐜".bold(),
        format!("Welcome to Anty v{}", env!("CARGO_PKG_VERSION")).bold()
    );
    println!(
        "  {}",
        "Developer-first security scanner — like a team of security reviewers reading your code.".dimmed()
    );
    separator();
    println!();
    press_enter("  Press Enter to continue...");
}

/// B) Security notes
fn screen_security_notes() {
    println!();
    println!("  {}", "Security & Privacy".bold().underline());
    println!();
    println!(
        "  {} Anty {} executes scanned code — it only reads files.",
        "•".bold(),
        "never".bold()
    );
    println!(
        "  {} Scans run {} on your machine. Nothing is uploaded.",
        "•".bold(),
        "locally".bold()
    );
    println!();
    press_enter("  Press Enter to continue...");
}

/// C) Trust folder prompt – returns `true` if user trusts the folder.
fn screen_trust_folder() -> bool {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    println!();
    println!(
        "  {} {}",
        "📂".bold(),
        "Trust Folder".bold().underline()
    );
    println!();
    println!("  Current directory:");
    println!("    {}", cwd.display().to_string().cyan());
    println!();
    println!("  Do you trust the files in this folder?");
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

/// D) Quick-actions menu – returns the chosen action.
enum QuickAction {
    ScanCwd,
    ScanPath(PathBuf),
    ShowHelp,
    Exit,
}

fn screen_quick_actions() -> QuickAction {
    println!();
    println!(
        "  {} {}",
        "⚡".bold(),
        "Quick Actions".bold().underline()
    );
    println!();
    println!("    {} Scan current folder (.)", "1)".bold());
    println!("    {} Scan another folder", "2)".bold());
    println!("    {} Show help", "3)".bold());
    println!("    {} Exit", "4)".bold());
    println!();

    loop {
        print!("  Your choice [1/2/3/4]: ");
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
            "3" => return QuickAction::ShowHelp,
            "4" => return QuickAction::Exit,
            _ => println!("  {}", "Please enter 1, 2, 3, or 4.".yellow()),
        }
    }
}

// ── Public entry-points ─────────────────────────────────────────────

/// Interactive onboarding wizard (no-args mode).
pub fn run_wizard() -> Result<()> {
    // Initialize minimal logging so the scan engine can emit info lines.
    init_quiet_logging();

    // A) Welcome
    screen_welcome();

    // B) Security notes
    screen_security_notes();

    // C) Trust folder
    if !screen_trust_folder() {
        println!();
        println!("  {}", "Goodbye!".dimmed());
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
        QuickAction::ShowHelp => {
            // Print clap's built-in help then exit.
            use clap::CommandFactory;
            Cli::command().print_help().ok();
            println!();
        }
        QuickAction::Exit => {
            println!();
            println!("  {}", "Goodbye!".dimmed());
        }
    }

    press_enter("  Press Enter to exit...");
    Ok(())
}

/// Drag-and-drop mode: a single directory was passed without a subcommand.
pub fn run_drag_drop(path: &Path) -> Result<()> {
    init_quiet_logging();

    println!();
    separator();
    println!(
        "  {} {}",
        "🐜".bold(),
        format!("Anty v{}", env!("CARGO_PKG_VERSION")).bold()
    );
    separator();
    println!();
    println!(
        "  Scan this folder? {}",
        path.display().to_string().cyan()
    );
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
        .try_init(); // try_init to avoid panic if already initialised
}
