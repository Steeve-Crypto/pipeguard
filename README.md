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
| `unpinned-action`      | High       | Actions pinned to tags/branches instead of SHAs  |
| `permissions-write-all`| High       | `permissions: write-all`                         |
| `pull-request-target`  | Critical   | Dangerous `pull_request_target` trigger          |
| `self-hosted-runner`   | Medium     | Use of self-hosted runners                       |
| `secret-in-logs`       | High       | Secrets being echoed                             |
| `script-injection`     | High       | Untrusted `github.event` data used in `run:`     |
| `aws-access-key`       | Critical   | Hardcoded AWS Access Key                         |
| `github-pat`           | Critical   | GitHub Personal Access Tokens                    |
| `private-key`          | Critical   | Private key blocks                               |
| `generic-secret`       | High       | Hardcoded passwords / API keys                   |

### Converter
Cleanly convert configuration files between YAML, JSON, and TOML.

### Output formats
- Human-readable (colored)
- JSON
- SARIF (for GitHub Code Scanning)

## Installation

```bash
git clone https://github.com/Steeve-Crypto/pipeguard.git
cd pipeguard
cargo install --path .
```

## Usage

### Scan

```bash
# Scan a single file
pipeguard scan examples/bad-workflow.yml

# Scan all workflows
pipeguard scan .github/workflows/

# Only High + Critical
pipeguard scan .github/workflows --min-severity high

# JSON output
pipeguard scan .github/workflows --json

# SARIF output (GitHub Code Scanning)
pipeguard scan .github/workflows --sarif > results.sarif
```

### Convert

```bash
pipeguard convert config.yaml --to json
pipeguard convert data.json --to toml -o data.toml
pipeguard convert Cargo.toml --to yaml
```

## Example

```bash
$ pipeguard scan examples/bad-workflow.yml
```

## Why this exists

Misconfigured CI/CD pipelines are a high-ROI target. `pipeguard` gives you a fast, offline way to audit them during assessments or while hardening your own projects.

## License

MIT
