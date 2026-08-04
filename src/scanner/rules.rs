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

// Detects uses: owner/repo@tag where tag is not a full 40-char SHA
static UNPINNED_ACTION: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)uses:\s*['\"]?([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([A-Za-z0-9._/-]+)"#)
        .unwrap()
});

static WRITE_ALL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)permissions:\s*write-all"#).unwrap());

static PULL_REQUEST_TARGET: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)pull_request_target"#).unwrap());

static SELF_HOSTED: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)runs-on:\s*.*self-hosted"#).unwrap());

static ECHO_SECRET: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(echo|print|printf|puts).*(\$\{\{\s*secrets\.|SECRET|PASSWORD|TOKEN|API_KEY)"#,
    )
    .unwrap()
});

static SCRIPT_INJECTION: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)run:.*\$\{\{\s*github\.event\.(pull_request|issue|comment|head_ref)"#,
    )
    .unwrap()
});

// Individual dangerous write permissions
static PERM_WRITE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)^\s*(contents|actions|packages|deployments|security-events|id-token|attestations):\s*write"#,
    )
    .unwrap()
});

static PERM_CONTENTS_WRITE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)^\s*contents:\s*write"#).unwrap());

static PERM_ID_TOKEN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)^\s*id-token:\s*write"#).unwrap());

pub fn scan_rules(path: &Path, content: &str, lines: &[&str]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut write_perm_count = 0;
    let mut has_contents_write = false;
    let mut has_id_token_write = false;
    let mut first_write_line = None;

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }

        // Unpinned actions — only flag if the ref is not a full SHA
        if let Some(caps) = UNPINNED_ACTION.captures(line) {
            let ref_name = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let is_sha = ref_name.len() == 40 && ref_name.chars().all(|c| c.is_ascii_hexdigit());
            if !is_sha {
                findings.push(Finding {
                    file: path.to_path_buf(),
                    rule_id: "unpinned-action".into(),
                    title: "Unpinned GitHub Action".into(),
                    description: format!(
                        "Action is referenced by mutable ref `{}` instead of a full commit SHA. This enables supply-chain attacks if the tag/branch is moved.",
                        ref_name
                    ),
                    severity: Severity::High,
                    line: Some(idx + 1),
                    snippet: Some(trimmed.chars().take(100).collect()),
                });
            }
        }

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

        // Track individual write permissions for better analysis
        if PERM_WRITE.is_match(line) {
            write_perm_count += 1;
            if first_write_line.is_none() {
                first_write_line = Some(idx + 1);
            }
        }
        if PERM_CONTENTS_WRITE.is_match(line) {
            has_contents_write = true;
        }
        if PERM_ID_TOKEN.is_match(line) {
            has_id_token_write = true;
        }

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

        if SCRIPT_INJECTION.is_match(line) {
            findings.push(Finding {
                file: path.to_path_buf(),
                rule_id: "script-injection".into(),
                title: "Potential script injection via github.event".into(),
                description: "Using untrusted github.event data (PR title, body, head_ref, etc.) directly in a run: step can lead to script injection.".into(),
                severity: Severity::High,
                line: Some(idx + 1),
                snippet: Some(trimmed.chars().take(120).collect()),
            });
        }
    }

    // Post-scan permission analysis
    if write_perm_count >= 3 {
        findings.push(Finding {
            file: path.to_path_buf(),
            rule_id: "excessive-write-permissions".into(),
            title: "Excessive write permissions".into(),
            description: format!(
                "Workflow grants write access to {} different scopes. Consider reducing to least privilege.",
                write_perm_count
            ),
            severity: Severity::Medium,
            line: first_write_line,
            snippet: None,
        });
    }

    // contents: write + id-token: write is a common dangerous combo for token abuse
    if has_contents_write && has_id_token_write {
        findings.push(Finding {
            file: path.to_path_buf(),
            rule_id: "dangerous-permission-combo".into(),
            title: "Dangerous permission combination".into(),
            description: "`contents: write` combined with `id-token: write` can enable privilege escalation or artifact poisoning attacks.".into(),
            severity: Severity::High,
            line: first_write_line,
            snippet: None,
        });
    }

    let _ = content; // reserved for future multi-line block parsing

    findings
}
