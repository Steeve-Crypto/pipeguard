use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;

use crate::scanner::Finding;
use crate::Severity;

#[derive(Debug)]
pub struct RuleFinding {
    pub file: std::path::PathBuf,
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub line: Option<usize>,
    pub snippet: Option<String>,
}

static UNPINNED_ACTION: Lazy<Regex> = Lazy::new(|| {
    // matches: uses: owner/action@v1  or @main  or @master  (no full SHA)
    Regex::new(r#"(?i)uses:\s*['\"]?[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@(v?\d|main|master|latest)"#).unwrap()
});

static WRITE_ALL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)permissions:\s*write-all"#).unwrap()
});

static PULL_REQUEST_TARGET: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)pull_request_target"#).unwrap()
});

static SELF_HOSTED: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)runs-on:\s*.*self-hosted"#).unwrap()
});

static ECHO_SECRET: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(echo|print|printf|puts).*(\$\{\{\s*secrets\.|SECRET|PASSWORD|TOKEN|API_KEY)"#).unwrap()
});

static BROAD_PERMISSIONS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)permissions:\s*\n(\s+\w+:\s*write\s*\n)+"#).unwrap()
});

pub fn scan_rules(path: &Path, content: &str, lines: &[&str]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }

        // Unpinned actions
        if UNPINNED_ACTION.is_match(line) {
            findings.push(Finding {
                file: path.to_path_buf(),
                rule_id: "unpinned-action".into(),
                title: "Unpinned GitHub Action".into(),
                description: "Action is referenced by a mutable tag (v1, main, etc.) instead of a full commit SHA. This allows supply-chain attacks if the tag is moved.".into(),
                severity: Severity::High,
                line: Some(idx + 1),
                snippet: Some(trimmed.chars().take(100).collect()),
            });
        }

        // permissions: write-all
        if WRITE_ALL.is_match(line) {
            findings.push(Finding {
                file: path.to_path_buf(),
                rule_id: "permissions-write-all".into(),
                title: "Overly broad permissions (write-all)".into(),
                description: "`permissions: write-all` grants the GITHUB_TOKEN maximum privileges. Prefer least-privilege explicit permissions.".into(),
                severity: Severity::High,
                line: Some(idx + 1),
                snippet: Some(trimmed.to_string()),
            });
        }

        // pull_request_target
        if PULL_REQUEST_TARGET.is_match(line) {
            findings.push(Finding {
                file: path.to_path_buf(),
                rule_id: "pull-request-target".into(),
                title: "Dangerous trigger: pull_request_target".into(),
                description: "`pull_request_target` runs in the context of the base repository and can be exploited by malicious PRs to steal secrets or modify the repo.".into(),
                severity: Severity::Critical,
                line: Some(idx + 1),
                snippet: Some(trimmed.to_string()),
            });
        }

        // self-hosted runners
        if SELF_HOSTED.is_match(line) {
            findings.push(Finding {
                file: path.to_path_buf(),
                rule_id: "self-hosted-runner".into(),
                title: "Self-hosted runner detected".into(),
                description: "Self-hosted runners can be dangerous if not properly isolated, especially when running untrusted code (e.g. from forks).".into(),
                severity: Severity::Medium,
                line: Some(idx + 1),
                snippet: Some(trimmed.to_string()),
            });
        }

        // Echoing secrets
        if ECHO_SECRET.is_match(line) {
            findings.push(Finding {
                file: path.to_path_buf(),
                rule_id: "secret-in-logs".into(),
                title: "Possible secret echoed to logs".into(),
                description: "Secrets should never be printed. Even if masked, this is a bad practice and can leak in some runners.".into(),
                severity: Severity::High,
                line: Some(idx + 1),
                snippet: Some(trimmed.chars().take(100).collect()),
            });
        }
    }

    // Multi-line style checks can be added later (e.g. many write permissions)
    let _ = (content, BROAD_PERMISSIONS); // silence unused for now

    findings
}
