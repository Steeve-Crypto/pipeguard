<p align="center">
  <img src="assets/logo.svg" alt="pipeguard" width="360"/>
</p>

<p align="center">
  <strong>CI/CD Pipeline Security Scanner + Multi-format Config Converter</strong>
</p>

<p align="center">
  <a href="https://scorecard.dev/viewer/?uri=github.com/Steeve-Crypto/pipeguard"><img src="https://api.scorecard.dev/projects/github.com/Steeve-Crypto/pipeguard/badge" alt="OpenSSF Scorecard"/></a>
</p>

`pipeguard` is a fast Rust CLI that helps security engineers and ethical hackers:

1. **Scan** GitHub Actions, GitLab CI, and other pipeline YAML files for common security issues
2. **Convert** between YAML ↔ JSON ↔ TOML

Built for practical use during recon, code review, and securing your own pipelines.

## Features

### Scanner
Detects:

| Rule ID                      | Severity   | Description                                           |
|------------------------------|------------|-------------------------------------------------------|
| `unpinned-action`            | High       | Actions pinned to tags/branches instead of SHAs       |
| `permissions-write-all`      | High       | `permissions: write-all`                              |
| `excessive-write-permissions`| Medium     | Too many individual write scopes                      |
| `dangerous-permission-combo` | High       | `contents: write` + `id-token: write`                 |
| `pull-request-target`        | Critical   | Dangerous `pull_request_target` trigger               |
| `self-hosted-runner`         | Medium     | Use of self-hosted runners                            |
| `secret-in-logs`             | High       | Secrets being echoed                                  |
| `script-injection`           | High       | Untrusted `github.event` data used in `run:`          |
| `aws-access-key`             | Critical   | Hardcoded AWS Access Key                              |
| `github-pat`                 | Critical   | GitHub Personal Access Tokens                         |
| `private-key`                | Critical   | Private key blocks                                    |
| `generic-secret`             | High       | Hardcoded passwords / API keys                        |
| `high-entropy-secret`        | Medium     | High Shannon entropy string (possible unknown secret) |

### Converter
Cleanly convert configuration files between YAML, JSON, and TOML.

### Output formats
- Human-readable (colored)
- JSON
- SARIF (for GitHub Code Scanning)

### GitHub Action

```yaml
- uses: actions/checkout@v4
- uses: Steeve-Crypto/pipeguard@main
  with:
    path: .github/workflows
    min_severity: medium
    sarif: pipeguard.sarif
    fail_on_findings: "true"
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: pipeguard.sarif
```

Full docs: [`docs/github-action.md`](docs/github-action.md)

### Observability (Tracing / Logs / Metrics)
pipeguard is instrumented with the `tracing` ecosystem:

**Spans**
- `scan.start` → `scan_file` → `entropy.analyze` → `rule.evaluate` → `report.generate`
- `convert`

**Structured events**
- `finding.detected` (rule_id, severity, line, title)
- `scan metrics` (files_scanned, findings_total, findings_critical/high/medium/low)

**Control**
```bash
# Default compact human logs
pipeguard scan examples/bad-workflow.yml

# More verbose
RUST_LOG=pipeguard=debug pipeguard scan examples/bad-workflow.yml

# JSON logs (ready for collectors / Loki / ELK)
PIPEGUARD_LOG_FORMAT=json RUST_LOG=pipeguard=info pipeguard scan examples/bad-workflow.yml
```

### OSSF Scorecard
This repository runs [OpenSSF Scorecard](https://github.com/ossf/scorecard) on a schedule and on pushes to `main` (see `.github/workflows/scorecard.yml`).

- Results go to **GitHub Code Scanning** (SARIF)
- Results are published for the **Scorecard badge** above
- Details: [`docs/scorecard.md`](docs/scorecard.md)

**Scorecard** = repo-level security posture. **pipeguard** = CI/CD pipeline content risks. Use both.

## Brand assets

See [`assets/`](assets/) for logo variants:

- `logo.svg` — primary logo (icon + wordmark)
- `logo-icon.svg` — icon only (avatar / favicon)

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

## Security

See [SECURITY.md](SECURITY.md) for how to report vulnerabilities.

## Why this exists

Misconfigured CI/CD pipelines are a high-ROI target. `pipeguard` gives you a fast, offline way to audit them during assessments or while hardening your own projects.

## License

MIT
