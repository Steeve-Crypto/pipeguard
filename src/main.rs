mod convert;
mod report;
mod scanner;
mod telemetry;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use std::process;
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
        input: PathBuf,
        #[arg(short, long, value_enum)]
        to: Format,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Scan CI/CD pipeline files for security issues
    Scan {
        path: PathBuf,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        sarif: bool,
        #[arg(long, value_enum, default_value = "low")]
        min_severity: Severity,
        #[arg(long, value_enum)]
        fail_on: Option<Severity>,
        #[arg(long, value_delimiter = ',')]
        exclude: Vec<String>,
    },

    /// List built-in rule IDs
    Rules,
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
            fail_on,
            exclude,
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
            info!(findings_total = findings.len(), "scan completed");

            let report_span = info_span!("report.generate", findings = findings.len());
            let _rg = report_span.enter();
            let _shown = report::print_findings(&findings, json, sarif, min_severity, &exclude);

            if let Some(threshold) = fail_on {
                let should_fail = findings.iter().any(|f| {
                    f.severity >= threshold && !exclude.iter().any(|id| id == &f.rule_id)
                });
                if should_fail {
                    process::exit(1);
                }
            }
        }
        Commands::Rules => {
            for (id, sev, title) in scanner::rules::catalog() {
                println!("{:<32} {:<10} {}", id, sev, title);
            }
        }
    }

    Ok(())
}
