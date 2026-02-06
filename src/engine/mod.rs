pub mod file_walker;

use std::path::PathBuf;
use std::time::Instant;

use anyhow::Result;
use rayon::prelude::*;
use tracing::{debug, info};

use crate::agents::{self, Language, ScannedFile, SecurityAgent};
use crate::cli::{Cli, ScanArgs};
use crate::config::AntyConfig;
use crate::report::finding::{ScanReport, ScanSummary};
use crate::report::merger;

/// The core scan engine. Orchestrates file discovery, agent dispatch,
/// and report generation.
pub struct Scanner {
    /// Root path to scan
    scan_path: PathBuf,
    /// Agents to run
    agents: Vec<Box<dyn SecurityAgent>>,
    /// Maximum file size (bytes)
    max_file_size: u64,
    /// Include patterns
    include: Vec<String>,
    /// Exclude patterns
    exclude: Vec<String>,
    /// Only scan changed files
    #[allow(dead_code)]
    changed_only: bool,
}

impl Scanner {
    pub fn new(_cli: &Cli, args: &ScanArgs) -> Result<Self> {
        let scan_path = std::fs::canonicalize(&args.path)?;

        // Load optional config
        let config = AntyConfig::load(&scan_path);

        // Determine which agents to run
        let agents = if let Some(ref names) = args.agents {
            agents::agents_by_names(names)
        } else {
            agents::all_agents()
        };

        info!("Loaded {} agents: {}", agents.len(),
            agents.iter().map(|a| a.name()).collect::<Vec<_>>().join(", "));

        // Merge exclude patterns from config and CLI
        let mut exclude = args.exclude.clone();
        if let Some(ref cfg) = config {
            exclude.extend(cfg.scan.exclude.clone());
        }

        let mut include = args.include.clone();
        if let Some(ref cfg) = config {
            include.extend(cfg.scan.include.clone());
        }

        Ok(Scanner {
            scan_path,
            agents,
            max_file_size: args.max_file_size,
            include,
            exclude,
            changed_only: args.changed_only,
        })
    }

    /// Run the full scan pipeline
    pub fn run(&self) -> Result<ScanReport> {
        let start = Instant::now();

        // Step 1: Discover files
        info!("Discovering files in {}", self.scan_path.display());
        let file_paths = file_walker::walk_files(
            &self.scan_path,
            &self.include,
            &self.exclude,
            self.max_file_size,
        )?;

        info!("Found {} files to scan", file_paths.len());

        // Step 2: Read and classify files (parallel)
        let (files, skipped): (Vec<_>, Vec<_>) = file_paths
            .par_iter()
            .map(|path| {
                let rel_path = path.strip_prefix(&self.scan_path)
                    .unwrap_or(path)
                    .to_path_buf();

                // Read file
                match std::fs::read_to_string(path) {
                    Ok(content) => {
                        // Detect language
                        let language = path
                            .extension()
                            .and_then(|e| e.to_str())
                            .map(Language::from_extension)
                            .or_else(|| {
                                path.file_name()
                                    .and_then(|n| n.to_str())
                                    .map(Language::from_filename)
                            });

                        Ok(ScannedFile {
                            rel_path,
                            abs_path: path.clone(),
                            content,
                            language,
                        })
                    }
                    Err(e) => {
                        debug!("Skipping {}: {}", path.display(), e);
                        Err(())
                    }
                }
            })
            .partition_map(|r| match r {
                Ok(f) => rayon::iter::Either::Left(f),
                Err(()) => rayon::iter::Either::Right(()),
            });

        let files_scanned = files.len();
        let files_skipped = skipped.len();

        info!("Read {} files ({} skipped)", files_scanned, files_skipped);

        // Step 3: Run all agents on all files (parallel over files)
        let all_findings: Vec<_> = files
            .par_iter()
            .flat_map(|file| {
                let mut file_findings = Vec::new();
                for agent in &self.agents {
                    file_findings.extend(agent.scan_file(file));
                }
                file_findings
            })
            .collect();

        info!("Raw findings: {}", all_findings.len());

        // Step 4: Merge, dedup, and sort
        let findings = merger::merge_findings(all_findings);

        info!("Final findings after dedup: {}", findings.len());

        let duration = start.elapsed();
        let summary = ScanSummary::from_findings(&findings);

        Ok(ScanReport {
            version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            scan_path: self.scan_path.clone(),
            files_scanned,
            files_skipped,
            duration_ms: duration.as_millis() as u64,
            findings,
            summary,
        })
    }
}
