use std::path::PathBuf;

use anyhow::Result;
use ignore::WalkBuilder;
use tracing::debug;

/// Walk a directory tree and collect file paths to scan.
///
/// - Respects .gitignore automatically (via the `ignore` crate)
/// - Skips binary files
/// - Skips files larger than max_file_size
/// - Applies include/exclude filters
pub fn walk_files(
    root: &std::path::Path,
    include: &[String],
    exclude: &[String],
    max_file_size: u64,
) -> Result<Vec<PathBuf>> {
    let mut builder = WalkBuilder::new(root);

    // Standard settings
    builder
        .hidden(true)          // skip hidden files
        .git_ignore(true)      // respect .gitignore
        .git_global(true)      // respect global gitignore
        .git_exclude(true)     // respect .git/info/exclude
        .follow_links(false)   // don't follow symlinks
        .max_filesize(Some(max_file_size));

    // Add custom exclude patterns via overrides
    if !exclude.is_empty() {
        let mut overrides = ignore::overrides::OverrideBuilder::new(root);
        for pattern in exclude {
            // Negate the pattern so matching files are excluded
            let neg = format!("!{}", pattern);
            if let Err(e) = overrides.add(&neg) {
                tracing::warn!("Invalid exclude pattern '{}': {}", pattern, e);
            }
        }
        if let Ok(built) = overrides.build() {
            builder.overrides(built);
        }
    }

    let mut files = Vec::new();

    for entry in builder.build() {
        match entry {
            Ok(entry) => {
                // Only process files (not dirs)
                if !entry.file_type().map_or(false, |ft| ft.is_file()) {
                    continue;
                }

                let path = entry.path().to_path_buf();

                // Skip common non-source directories/files by path
                let path_str = path.to_string_lossy().to_lowercase();
                if is_excluded_path(&path_str) {
                    debug!("Excluded: {}", path.display());
                    continue;
                }

                // Skip binary files (quick heuristic check)
                if is_likely_binary(&path) {
                    debug!("Binary skip: {}", path.display());
                    continue;
                }

                // Apply include filter if specified
                if !include.is_empty() {
                    let name = path.file_name()
                        .map(|n| n.to_string_lossy().to_lowercase())
                        .unwrap_or_default();
                    let ext = path.extension()
                        .map(|e| e.to_str().unwrap_or(""))
                        .unwrap_or("");

                    let matches = include.iter().any(|pattern| {
                        name.contains(pattern) || ext == pattern.trim_start_matches('.')
                    });

                    if !matches {
                        continue;
                    }
                }

                files.push(path);
            }
            Err(e) => {
                debug!("Walk error: {}", e);
            }
        }
    }

    Ok(files)
}

/// Check if a path should be excluded based on common patterns
fn is_excluded_path(path: &str) -> bool {
    let exclusions = [
        "node_modules",
        ".git",
        "target/debug",
        "target/release",
        "__pycache__",
        ".pyc",
        "venv/",
        ".venv/",
        ".tox/",
        "dist/",
        "build/",
        ".next/",
        ".nuxt/",
        ".output/",
        "coverage/",
        ".nyc_output/",
        ".cache/",
        ".idea/",
        ".vscode/",
        ".vs/",
    ];

    exclusions.iter().any(|ex| path.contains(ex))
}

/// Quick heuristic to detect binary files by extension
fn is_likely_binary(path: &std::path::Path) -> bool {
    let binary_extensions = [
        "exe", "dll", "so", "dylib", "bin", "obj", "o", "a", "lib",
        "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg", "webp",
        "mp3", "mp4", "avi", "mov", "mkv", "wav", "flac",
        "zip", "tar", "gz", "bz2", "xz", "7z", "rar",
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
        "woff", "woff2", "ttf", "otf", "eot",
        "wasm", "class", "pyc", "pyo",
        "db", "sqlite", "sqlite3",
    ];

    path.extension()
        .and_then(|e| e.to_str())
        .map(|ext| binary_extensions.contains(&ext.to_lowercase().as_str()))
        .unwrap_or(false)
}
