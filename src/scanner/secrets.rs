use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;
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
            Regex::new(r#"(?i)aws.{0,20}?(?:secret|access).{0,20}?['\"]([A-Za-z0-9/+=]{40})['\"]"#)
                .unwrap(),
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
            Regex::new(
                r#"(?i)(password|secret|token|api[_-]?key|access[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}['\"]"#,
            )
            .unwrap(),
        ),
        (
            "jwt",
            "Possible JWT",
            Severity::Medium,
            Regex::new(r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*").unwrap(),
        ),
    ]
});

// Candidate strings that look like secrets (quoted or assigned values)
static CANDIDATE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:['\"]([A-Za-z0-9+/=_\-.]{20,})['\"]|(?:=|:)\s*([A-Za-z0-9+/=_\-.]{24,}))"#)
        .unwrap()
});

/// Shannon entropy of a string
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }
    let len = s.len() as f64;
    freq.values()
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn looks_like_secret(s: &str) -> bool {
    // Skip obvious non-secrets
    if s.chars().all(|c| c.is_ascii_digit()) {
        return false; // pure numbers
    }
    if s.contains("example") || s.contains("placeholder") || s.contains("changeme") {
        return false;
    }
    // High entropy + reasonable length
    let entropy = shannon_entropy(s);
    entropy >= 4.2 && s.len() >= 20
}

pub fn scan_secrets(path: &Path, _content: &str, lines: &[&str]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }

        // 1. Known pattern matches
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

        // 2. Entropy-based detection for unknown high-entropy strings
        for caps in CANDIDATE_RE.captures_iter(line) {
            let candidate = caps
                .get(1)
                .or_else(|| caps.get(2))
                .map(|m| m.as_str())
                .unwrap_or("");

            if looks_like_secret(candidate) {
                // Avoid double-reporting if already matched a known pattern
                let already_matched = PATTERNS.iter().any(|(_, _, _, re)| re.is_match(line));
                if !already_matched {
                    findings.push(Finding {
                        file: path.to_path_buf(),
                        rule_id: "high-entropy-secret".into(),
                        title: "High-entropy string (possible secret)".into(),
                        description: format!(
                            "String has high Shannon entropy ({:.2}) and looks like a potential secret or key.",
                            shannon_entropy(candidate)
                        ),
                        severity: Severity::Medium,
                        line: Some(idx + 1),
                        snippet: Some(trimmed.chars().take(120).collect()),
                    });
                }
            }
        }
    }

    findings
}
