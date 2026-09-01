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
        r#"(?i)run:.*\$\{\{\s*github\.event\.(pull_request|issue|comment|head_ref|discussion|inputs)"#,
    )
    .unwrap()
});

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

static CHECKOUT_ACTION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)uses:\s*['\"]?actions/checkout@"#).unwrap());

static PERSIST_CREDS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)persist-credentials:\s*true"#).unwrap());

static PR_HEAD_REF: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)ref:\s*.*\$\{\{\s*github\.event\.pull_request\.(head\.(sha|ref)|head_sha)"#,
    )
    .unwrap()
});

static ENV_LITERAL_SECRET: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)^\s*(password|secret|token|api[_-]?key|access[_-]?key|aws_secret_access_key|gh_token)\s*:\s*['\"][^'\"]{8,}['\"]"#,
    )
    .unwrap()
});

static CURL_PIPE_SHELL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(curl|wget).+\|\s*(sudo\s+)?(bash|sh|zsh)"#).unwrap()
});

static IMAGE_LATEST: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)^\s*(image|container|from):\s*.+:latest\b"#).unwrap());

static PRIVILEGED: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)privileged:\s*true|--privileged\b"#).unwrap());

static INSECURE_SSL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(GIT_SSL_NO_VERIFY|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0|--insecure\b|insecure:\s*true)"#)
        .unwrap()
});

static WORLD_WRITABLE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)chmod\s+(-R\s+)?0?777\b"#).unwrap());

pub fn catalog() -> &'static [(&'static str, &'static str, &'static str)] {
    &[
        ("unpinned-action", "high", "Actions pinned to tags/branches"),
        ("permissions-write-all", "high", "permissions: write-all"),
        ("excessive-write-permissions", "medium", "Too many write scopes"),
        ("dangerous-permission-combo", "high", "contents write + id-token write"),
        ("pull-request-target", "critical", "pull_request_target trigger"),
        ("pr-target-untrusted-checkout", "critical", "PR target + untrusted checkout"),
        ("persist-credentials", "medium", "Checkout persists GITHUB_TOKEN"),
        ("env-hardcoded-secret", "high", "Literal secret in env"),
        ("self-hosted-runner", "medium", "Self-hosted runner"),
        ("secret-in-logs", "high", "Secret echoed to logs"),
        ("script-injection", "high", "Untrusted github.event in run"),
        ("curl-pipe-shell", "high", "curl|wget piped to a shell"),
        ("image-latest", "medium", "Image or FROM tagged :latest"),
        ("privileged-container", "high", "Privileged container or --privileged"),
        ("insecure-ssl", "high", "TLS/SSL verification disabled"),
        ("world-writable", "medium", "chmod 777 in a pipeline"),
    ]
}

pub fn scan_rules(path: &Path, content: &str, lines: &[&str]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut write_perm_count = 0;
    let mut has_contents_write = false;
    let mut has_id_token_write = false;
    let mut first_write_line = None;
    let mut has_pr_target = false;
    let mut pr_target_line = None;
    let mut has_untrusted_checkout = false;
    let mut untrusted_checkout_line = None;
    let mut has_checkout = false;
    let mut persist_creds_line = None;

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }

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
            has_pr_target = true;
            pr_target_line = Some(idx + 1);
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
                description: "Using untrusted github.event data (PR title, body, head_ref, inputs, etc.) directly in a run: step can lead to script injection.".into(),
                severity: Severity::High,
                line: Some(idx + 1),
                snippet: Some(trimmed.chars().take(120).collect()),
            });
        }

        if CHECKOUT_ACTION.is_match(line) {
            has_checkout = true;
        }
        if PERSIST_CREDS.is_match(line) {
            persist_creds_line = Some(idx + 1);
            findings.push(Finding {
                file: path.to_path_buf(),
                rule_id: "persist-credentials".into(),
                title: "Checkout persists credentials".into(),
                description: "`persist-credentials: true` leaves the GITHUB_TOKEN in the workspace. Prefer `false` unless a later step must push with that token.".into(),
                severity: Severity::Medium,
                line: Some(idx + 1),
                snippet: Some(trimmed.to_string()),
            });
        }
        if PR_HEAD_REF.is_match(line) {
            has_untrusted_checkout = true;
            untrusted_checkout_line = Some(idx + 1);
        }

        if ENV_LITERAL_SECRET.is_match(line) {
            findings.push(Finding {
                file: path.to_path_buf(),
                rule_id: "env-hardcoded-secret".into(),
                title: "Hardcoded secret in env block".into(),
                description: "A secret-looking value is assigned directly in `env:`. Use GitHub Secrets (`${{ secrets.* }}`) instead of literals.".into(),
                severity: Severity::High,
                line: Some(idx + 1),
                snippet: Some(trimmed.chars().take(120).collect()),
            });
        }

        if CURL_PIPE_SHELL.is_match(line) {
            findings.push(Finding {
                file: path.to_path_buf(),
                rule_id: "curl-pipe-shell".into(),
                title: "Remote script piped to a shell".into(),
                description: "`curl | bash` (or wget) downloads and executes unpinned remote code. Pin a checksum or vendor the script.".into(),
                severity: Severity::High,
                line: Some(idx + 1),
                snippet: Some(trimmed.chars().take(120).collect()),
            });
        }

        if IMAGE_LATEST.is_match(line) {
            findings.push(Finding {
                file: path.to_path_buf(),
                rule_id: "image-latest".into(),
                title: "Container image tagged :latest".into(),
                description: "`:latest` is a moving tag. Pin the image digest or a version tag so builds stay reproducible and supply-chain safer.".into(),
                severity: Severity::Medium,
                line: Some(idx + 1),
                snippet: Some(trimmed.to_string()),
            });
        }

        if PRIVILEGED.is_match(line) {
            findings.push(Finding {
                file: path.to_path_buf(),
                rule_id: "privileged-container".into(),
                title: "Privileged container".into(),
                description: "Privileged mode disables container isolation. Avoid `--privileged` / `privileged: true` unless there is no alternative.".into(),
                severity: Severity::High,
                line: Some(idx + 1),
                snippet: Some(trimmed.chars().take(120).collect()),
            });
        }

        if INSECURE_SSL.is_match(line) {
            findings.push(Finding {
                file: path.to_path_buf(),
                rule_id: "insecure-ssl".into(),
                title: "TLS verification disabled".into(),
                description: "Disabling SSL/TLS verification (`--insecure`, GIT_SSL_NO_VERIFY, NODE_TLS_REJECT_UNAUTHORIZED=0) invites MITM on CI traffic.".into(),
                severity: Severity::High,
                line: Some(idx + 1),
                snippet: Some(trimmed.chars().take(120).collect()),
            });
        }

        if WORLD_WRITABLE.is_match(line) {
            findings.push(Finding {
                file: path.to_path_buf(),
                rule_id: "world-writable".into(),
                title: "World-writable permissions".into(),
                description: "`chmod 777` in CI widens the blast radius if a later step is compromised. Use tighter modes.".into(),
                severity: Severity::Medium,
                line: Some(idx + 1),
                snippet: Some(trimmed.to_string()),
            });
        }
    }

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

    if has_pr_target && (has_untrusted_checkout || (has_checkout && content.contains("github.event.pull_request"))) {
        findings.push(Finding {
            file: path.to_path_buf(),
            rule_id: "pr-target-untrusted-checkout".into(),
            title: "pull_request_target checks out untrusted code".into(),
            description: "`pull_request_target` plus checkout of the PR head runs attacker-controlled code with base-repo privileges and secrets.".into(),
            severity: Severity::Critical,
            line: untrusted_checkout_line.or(pr_target_line),
            snippet: None,
        });
    }

    let _ = persist_creds_line;
    let _ = content;

    findings
}
