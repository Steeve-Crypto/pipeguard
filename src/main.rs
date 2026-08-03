mod convert;
mod report;
mod scanner;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "pipeguard",
    about = "CI/CD pipeline security scanner + multi-format config converter (YAML ↔ JSON ↔ TOML)",
    version,
    author = "Steeve-Crypto"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Convert between JSON, YAML, and TOML
    Convert {
        /// Input file path
        input: PathBuf,

        /// Output format
        #[arg(short, long, value_enum)]
        to: Format,

        /// Optional output file (defaults to stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Scan CI/CD pipeline files for security issues
    Scan {
        /// File or directory to scan (e.g. .github/workflows or a single .yml)
        path: PathBuf,

        /// Output findings as JSON
        #[arg(long)]
        json: bool,

        /// Only show findings of this severity or higher
        #[arg(long, value_enum, default_value = "low")]
        min_severity: Severity,
    },
}

#[derive(Clone, ValueEnum)]
pub enum Format {
    Json,
    Yaml,
    Toml,
}

#[derive(Clone, ValueEnum, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Convert { input, to, output } => {
            convert::run(&input, to, output.as_deref())?;
        }
        Commands::Scan {
            path,
            json,
            min_severity,
        } => {
            let findings = scanner::scan(&path).context("scan failed")?;
            report::print_findings(&findings, json, min_severity);
        }
    }

    Ok(())
}
