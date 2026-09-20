pub mod ignore;
pub mod rules;
pub mod secrets;

use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info, info_span, warn};
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

#[tracing::instrument(skip(path), fields(path = %path.display()))]
pub fn scan(path: &Path) -> Result<Vec<Finding>> {
    let ignore = ignore::load(path);
    let mut findings = Vec::new();
    let mut files_scanned = 0u64;

    if path.is_file() {
        if !ignore.ignores_path(path) {
            scan_file(path, &mut findings)?;
            files_scanned = 1;
        }
    } else if path.is_dir() {
        for entry in WalkDir::new(path)
            .into_iter()
            .filter_entry(|e| !is_skipped_dir(e.path()))
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let p = entry.path();
            if is_pipeline_file(p) && !ignore.ignores_path(p) {
                scan_file(p, &mut findings)?;
                files_scanned += 1;
            }
        }
    } else {
        warn!(path = %path.display(), "path does not exist");
        anyhow::bail!("path does not exist: {}", path.display());
    }

    findings.retain(|f| !ignore.ignores_rule(&f.rule_id));
    dedup(&mut findings);
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.rule_id.cmp(&b.rule_id)));

    let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high = findings.iter().filter(|f| f.severity == Severity::High).count();
    let medium = findings.iter().filter(|f| f.severity == Severity::Medium).count();
    let low = findings.iter().filter(|f| f.severity == Severity::Low).count();

    info!(
        files_scanned = files_scanned,
        findings_total = findings.len(),
        findings_critical = critical,
        findings_high = high,
        findings_medium = medium,
        findings_low = low,
        "scan metrics"
    );

    Ok(findings)
}

fn is_skipped_dir(path: &Path) -> bool {
    path.components().any(|c| {
        matches!(
            c.as_os_str().to_str().unwrap_or(""),
            ".git" | "target" | "node_modules" | "vendor" | ".venv" | "dist"
        )
    })
}

fn is_pipeline_file(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();

    name.ends_with(".yml")
        || name.ends_with(".yaml")
        || name.ends_with(".toml")
        || name == "jenkinsfile"
        || name.starts_with("jenkinsfile.")
        || name == "dockerfile"
        || name.starts_with("dockerfile.")
        || name.ends_with(".dockerfile")
        || name == ".env"
        || name.ends_with(".env")
        || name == "azure-pipelines.yml"
        || name == "bitbucket-pipelines.yml"
        || name == "cloudbuild.yaml"
        || name == "cloudbuild.yml"
}

fn dedup(findings: &mut Vec<Finding>) {
    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| {
        seen.insert((f.file.clone(), f.rule_id.clone(), f.line.unwrap_or(0)))
    });
}

#[tracing::instrument(skip(findings), fields(file = %path.display()))]
fn scan_file(path: &Path, findings: &mut Vec<Finding>) -> Result<()> {
    debug!("parsing file");

    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "failed to read file");
            return Err(e.into());
        }
    };
    if content.len() > 2_000_000 {
        warn!(path = %path.display(), "skipping oversized file");
        return Ok(());
    }
    let lines: Vec<&str> = content.lines().collect();

    {
        let _span = info_span!("entropy.analyze", file = %path.display()).entered();
        let secrets = secrets::scan_secrets(path, &content, &lines);
        for f in &secrets {
            tracing::info!(
                target: "pipeguard.finding",
                rule_id = %f.rule_id,
                severity = ?f.severity,
                line = ?f.line,
                title = %f.title,
                "finding.detected"
            );
        }
        findings.extend(secrets);
    }

    {
        let _span = info_span!("rule.evaluate", file = %path.display()).entered();
        let rules_findings = rules::scan_rules(path, &content, &lines);
        for f in &rules_findings {
            tracing::info!(
                target: "pipeguard.finding",
                rule_id = %f.rule_id,
                severity = ?f.severity,
                line = ?f.line,
                title = %f.title,
                "finding.detected"
            );
        }
        findings.extend(rules_findings);
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
