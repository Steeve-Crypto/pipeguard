# pipeguard

**CI/CD Pipeline Security Scanner + Multi-format Config Converter**

`pipeguard` is a fast Rust CLI that helps security engineers and ethical hackers:

1. **Scan** GitHub Actions, GitLab CI, and other pipeline YAML files for common security issues
2. **Convert** between YAML ↔ JSON ↔ TOML

Built for practical use during recon, code review, and securing your own pipelines.

## Features

### Scanner
Detects:

| Rule ID                | Severity   | Description                                      |
|------------------------|------------|--------------------------------------------------|
| `unpinned-action`      | High       | Actions pinned to tags (`@v1`, `@main`) instead of SHAs |
| `permissions-write-all`| High       | `permissions: write-all`                         |
| `pull-request-target`  | Critical   | Dangerous `pull_request_target` trigger          |
| `self-hosted-runner`   | Medium     | Use of self-hosted runners                       |
| `secret-in-logs`       | High       | Secrets being echoed                             |
| `aws-access-key`       | Critical   | Hardcoded AWS Access Key                         |
| `github-pat`           | Critical   | GitHub Personal Access Tokens                    |
| `private-key`          | Critical   | Private key blocks                               |
| `generic-secret`       | High       | Hardcoded passwords / API keys                   |

### Converter
Cleanly convert configuration files between:
- YAML
- JSON
- TOML

## Installation

```bash
# From source
git clone https://github.com/Steeve-Crypto/pipeguard.git
cd pipeguard
cargo install --path .

# Or just build
cargo build --release
```

## Usage

### Scan a workflow or directory

```bash
# Scan a single file
pipeguard scan examples/bad-workflow.yml

# Scan all workflows in a repo
pipeguard scan .github/workflows/

# Only show High and Critical
pipeguard scan .github/workflows --min-severity high

# Machine-readable output
pipeguard scan .github/workflows --json
```

### Convert formats

```bash
# YAML → JSON
pipeguard convert config.yaml --to json

# JSON → TOML
pipeguard convert data.json --to toml -o data.toml

# TOML → YAML
pipeguard convert Cargo.toml --to yaml
```

## Example Output

```
⚠ 8 finding(s) found

CRITICAL [pull-request-target] Dangerous trigger: pull_request_target
   File : examples/bad-workflow.yml
   Line : 4
   Code : pull_request_target:
   `pull_request_target` runs in the context of the base repository...

HIGH [unpinned-action] Unpinned GitHub Action
   File : examples/bad-workflow.yml
   Line : 18
   Code : - uses: actions/checkout@v4
   ...
```

## Why this exists

Modern software delivery heavily relies on CI/CD. Misconfigured pipelines are one of the highest-ROI targets for attackers (and a frequent source of real breaches). 

`pipeguard` gives you a fast, offline, dependency-light way to audit pipeline configurations during security assessments or while hardening your own projects.

## Roadmap

- [ ] More precise GitHub Actions permission analysis
- [ ] GitLab CI specific rules
- [ ] SARIF output for GitHub Code Scanning integration
- [ ] Custom rule support
- [ ] Secrets entropy analysis

## License

MIT
