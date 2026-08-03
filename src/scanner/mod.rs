pub mod rules;
pub mod secrets;

use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::Severity;
use rules::RuleFinding;

#[derive(Debug, Clone)]
pub struct Finding {
    pub file: PathBuf,
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub line: Option<usize>,
    pub snippet: Option<String>,
}

pub fn scan(path: &Path) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    if path.is_file() {
        scan_file(path, &mut findings)?;
    } else if path.is_dir() {
        for entry in WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let p = entry.path();
            if is_pipeline_file(p) {
                scan_file(p, &mut findings)?;
            }
        }
    } else {
        anyhow::bail!("path does not exist: {}", path.display());
    }

    // Sort by severity (Critical first)
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));
    Ok(findings)
}

fn is_pipeline_file(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();

    name.ends_with(".yml")
        || name.ends_with(".yaml")
        || name == "jenkinsfile"
        || name.ends_with(".toml") // some tools use TOML
}

fn scan_file(path: &Path, findings: &mut Vec<Finding>) -> Result<()> {
    let content = fs::read_to_string(path)?;
    let lines: Vec<&str> = content.lines().collect();

    // 1. Secret / credential patterns
    for finding in secrets::scan_secrets(path, &content, &lines) {
        findings.push(finding);
    }

    // 2. GitHub Actions / generic pipeline rules
    for finding in rules::scan_rules(path, &content, &lines) {
        findings.push(finding);
    }

    Ok(())
}

impl From<RuleFinding> for Finding {
    fn from(r: RuleFinding) -> Self {
        Finding {
            file: r.file,
            rule_id: r.rule_id,
            title: r.title,
            description: r.description,
            severity: r.severity,
            line: r.line,
            snippet: r.snippet,
        }
    }
}
