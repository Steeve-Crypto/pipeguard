mod convert;
mod report;
mod scanner;
mod telemetry;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use tracing::{info, info_span};

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

        /// Output findings as SARIF (for GitHub Code Scanning)
        #[arg(long)]
        sarif: bool,

        /// Only show findings of this severity or higher
        #[arg(long, value_enum, default_value = "low")]
        min_severity: Severity,
    },
}

#[derive(Clone, ValueEnum, Debug)]
pub enum Format {
    Json,
    Yaml,
    Toml,
}

#[derive(Clone, ValueEnum, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

fn main() -> Result<()> {
    telemetry::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Convert { input, to, output } => {
            let span = info_span!(
                "convert",
                input = %input.display(),
                to = ?to,
            );
            let _enter = span.enter();
            info!("starting conversion");
            convert::run(&input, to, output.as_deref())?;
            info!("conversion completed");
        }
        Commands::Scan {
            path,
            json,
            sarif,
            min_severity,
        } => {
            let span = info_span!(
                "scan.start",
                path = %path.display(),
                min_severity = ?min_severity,
                json = json,
                sarif = sarif,
            );
            let _enter = span.enter();
            info!("starting scan");

            let findings = scanner::scan(&path).context("scan failed")?;

            info!(
                findings_total = findings.len(),
                "scan completed"
            );

            let report_span = info_span!("report.generate", findings = findings.len());
            let _rg = report_span.enter();
            report::print_findings(&findings, json, sarif, min_severity);
        }
    }

    Ok(())
}
