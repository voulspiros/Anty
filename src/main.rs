mod cli;
mod engine;
mod agents;
mod report;
mod rules;
mod config;

use anyhow::Result;
use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

use cli::Cli;
use engine::Scanner;

fn main() -> Result<()> {
    // Parse CLI arguments
    let cli = Cli::parse();

    // Initialize logging
    let filter = if cli.verbose {
        EnvFilter::new("anty=debug")
    } else if cli.quiet {
        EnvFilter::new("anty=error")
    } else {
        EnvFilter::new("anty=info")
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .init();

    info!("Anty v{}", env!("CARGO_PKG_VERSION"));

    match &cli.command {
        cli::Commands::Scan(args) => {
            let scanner = Scanner::new(&cli, args)?;
            let report = scanner.run()?;

            // Output the report
            match args.format.as_str() {
                "json" => {
                    let output = report::json::render(&report)?;
                    if let Some(ref path) = args.out {
                        std::fs::write(path, &output)?;
                        info!("Report written to {}", path.display());
                    } else {
                        println!("{}", output);
                    }
                }
                _ => {
                    report::terminal::render(&report);
                    if let Some(ref path) = args.out {
                        let json_output = report::json::render(&report)?;
                        std::fs::write(path, &json_output)?;
                        info!("JSON report also written to {}", path.display());
                    }
                }
            }

            // Exit code based on findings
            if let Some(ref fail_on) = args.fail_on {
                let threshold = report::finding::Severity::from_str(fail_on);
                if report.has_findings_at_or_above(threshold) {
                    std::process::exit(1);
                }
            }
        }
        cli::Commands::Init => {
            config::init_config()?;
        }
        cli::Commands::ListRules => {
            rules::list_rules();
        }
    }

    Ok(())
}
