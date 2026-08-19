<p align="center">
  <img src="assets/logo.svg" alt="pipeguard" width="360"/>
</p>

<p align="center">
  <strong>CI/CD Pipeline Security Scanner + Multi-format Config Converter</strong>
</p>

<p align="center">
  <a href="https://crates.io/crates/pipeguard"><img src="https://img.shields.io/crates/v/pipeguard.svg" alt="crates.io"/></a>
  <a href="https://github.com/Steeve-Crypto/pipeguard/releases"><img src="https://img.shields.io/github/v/release/Steeve-Crypto/pipeguard" alt="GitHub release"/></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/Steeve-Crypto/pipeguard"><img src="https://api.scorecard.dev/projects/github.com/Steeve-Crypto/pipeguard/badge" alt="OpenSSF Scorecard"/></a>
  <a href="https://github.com/Steeve-Crypto/pipeguard/actions/workflows/pipeguard-self.yml"><img src="https://github.com/Steeve-Crypto/pipeguard/actions/workflows/pipeguard-self.yml/badge.svg" alt="self-scan"/></a>
</p>

**pipeguard** is a fast Rust CLI for security engineers and builders who care about their pipelines.

It does two things extremely well:

1. **Scans** GitHub Actions, GitLab CI, and other pipeline YAML for real security issues
2. **Converts** cleanly between YAML ↔ JSON ↔ TOML

Built for practical use during code review, recon, and hardening your own CI.

## Why it matters

Misconfigured CI/CD is one of the highest-ROI attack surfaces. Most teams still pin actions to tags, over-permission jobs, and leak secrets into logs. pipeguard finds these problems offline, fast, and with SARIF output ready for GitHub Code Scanning.

## Scanner detections

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

## Output formats

- Human-readable (colored)
- JSON
- SARIF (GitHub Code Scanning ready)

## GitHub Action

```yaml
- uses: actions/checkout@v4
- uses: Steeve-Crypto/pipeguard@v0.1.0
  with:
    path: .github/workflows
    min_severity: medium
    sarif: pipeguard.sarif
    fail_on_findings: "true"
- uses: github/codeql-action/upload-sarif@v4
  if: always()
  with:
    sarif_file: pipeguard.sarif
```

## Installation

```bash
# From crates.io
cargo install pipeguard

# From source
git clone https://github.com/Steeve-Crypto/pipeguard.git
cd pipeguard
cargo install --path .
```

## Usage

```bash
# Scan
pipeguard scan .github/workflows/
pipeguard scan .github/workflows --min-severity high
pipeguard scan .github/workflows --json
pipeguard scan .github/workflows --sarif > results.sarif

# Convert
pipeguard convert config.yaml --to json
pipeguard convert data.json --to toml -o data.toml
```

## Observability

Fully instrumented with the `tracing` ecosystem. Structured events for every finding, scan metrics, and JSON log support for collectors.

## OpenSSF Scorecard

This repo runs Scorecard on a schedule. Scorecard covers repository posture; pipeguard covers the actual pipeline content risks. Use both.

## License

MIT
