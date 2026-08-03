use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;

use crate::scanner::Finding;
use crate::Severity;

static PATTERNS: Lazy<Vec<(&str, &str, Severity, Regex)>> = Lazy::new(|| {
    vec![
        (
            "aws-access-key",
            "AWS Access Key ID",
            Severity::Critical,
            Regex::new(r"(?i)(AKIA[0-9A-Z]{16})").unwrap(),
        ),
        (
            "aws-secret-key",
            "Possible AWS Secret Access Key",
            Severity::Critical,
            Regex::new(r"(?i)aws.{0,20}?(?:secret|access).{0,20}?['\"]([A-Za-z0-9/+=]{40})['\"]").unwrap(),
        ),
        (
            "github-pat",
            "GitHub Personal Access Token",
            Severity::Critical,
            Regex::new(r"gh[pousr]_[A-Za-z0-9_]{36,}").unwrap(),
        ),
        (
            "github-fine-grained",
            "GitHub Fine-grained PAT",
            Severity::Critical,
            Regex::new(r"github_pat_[A-Za-z0-9_]{20,}").unwrap(),
        ),
        (
            "slack-token",
            "Slack Token",
            Severity::High,
            Regex::new(r"xox[baprs]-[0-9A-Za-z-]{10,}").unwrap(),
        ),
        (
            "private-key",
            "Private Key block",
            Severity::Critical,
            Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----").unwrap(),
        ),
        (
            "generic-secret",
            "Possible hardcoded secret / password",
            Severity::High,
            Regex::new(r#"(?i)(password|secret|token|api[_-]?key|access[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}['\"]"#).unwrap(),
        ),
        (
            "jwt",
            "Possible JWT",
            Severity::Medium,
            Regex::new(r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*").unwrap(),
        ),
    ]
});

pub fn scan_secrets(path: &Path, _content: &str, lines: &[&str]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (idx, line) in lines.iter().enumerate() {
        // Skip comments that look like examples
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }

        for (id, title, severity, re) in PATTERNS.iter() {
            if re.is_match(line) {
                findings.push(Finding {
                    file: path.to_path_buf(),
                    rule_id: id.to_string(),
                    title: title.to_string(),
                    description: format!("Potential secret detected by pattern `{}`", id),
                    severity: severity.clone(),
                    line: Some(idx + 1),
                    snippet: Some(trimmed.chars().take(120).collect()),
                });
            }
        }
    }

    findings
}
