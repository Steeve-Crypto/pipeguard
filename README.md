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

1. **Scans** GitHub Actions, GitLab CI, Dockerfiles, `.env`, and other pipeline files for real security issues
2. **Converts** cleanly between YAML ↔ JSON ↔ TOML

Built for practical use during code review, recon, and hardening your own CI.

## Why it matters

Misconfigured CI/CD is one of the highest-ROI attack surfaces. Most teams still pin actions to tags, over-permission jobs, and leak secrets into logs. pipeguard finds these problems offline, fast, and with SARIF output ready for GitHub Code Scanning.

## Scanner detections

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `unpinned-action` | High | Actions pinned to tags/branches instead of SHAs |
| `permissions-write-all` | High | `permissions: write-all` |
| `excessive-write-permissions` | Medium | Too many individual write scopes |
| `dangerous-permission-combo` | High | `contents: write` + `id-token: write` |
| `pull-request-target` | Critical | Dangerous `pull_request_target` trigger |
| `pr-target-untrusted-checkout` | Critical | `pull_request_target` + checkout of PR head |
| `persist-credentials` | Medium | Checkout leaves GITHUB_TOKEN in workspace |
| `env-hardcoded-secret` | High | Literal secrets assigned in `env:` |
| `self-hosted-runner` | Medium | Use of self-hosted runners |
| `secret-in-logs` | High | Secrets being echoed |
| `script-injection` | High | Untrusted `github.event` data used in `run:` |
| `curl-pipe-shell` | High | `curl \| bash` / `wget \| sh` |
| `image-latest` | Medium | Image or `FROM` tagged `:latest` |
| `privileged-container` | High | Privileged container |
| `insecure-ssl` | High | TLS verification disabled |
| `world-writable` | Medium | `chmod 777` |
| `aws-access-key` / `github-pat` / `stripe-key` / `openai-key` | Critical | Known secret patterns |
| `high-entropy-secret` | Medium | High Shannon entropy string |

## Output formats

- Human-readable (colored)
- JSON
- SARIF (GitHub Code Scanning ready)

## Ignore noise

Create a `.pipeguardignore` next to the scan root:

```
# rule IDs
self-hosted-runner

# path fragments
examples/
```

Or suppress one line with `# pipeguard-ignore`.

## GitHub Action

```yaml
- uses: actions/checkout@v4
- uses: Steeve-Crypto/pipeguard@v0.1.0
  with:
    path: .github/workflows
    min_severity: medium
    exclude: self-hosted-runner
    sarif: pipeguard.sarif
    fail_on_findings: "true"
    comment_pr: "true"
- uses: github/codeql-action/upload-sarif@v4
  if: always()
  with:
    sarif_file: pipeguard.sarif
```

The Action builds from the tag you pin, so `@v0.1.0` and later checkouts stay consistent.

## Installation

```bash
cargo install pipeguard
```

## Usage

```bash
pipeguard scan .github/workflows/
pipeguard scan . --min-severity high --fail-on high
pipeguard scan . --exclude self-hosted-runner,image-latest
pipeguard scan . --json
pipeguard scan . --sarif > results.sarif
pipeguard rules

pipeguard convert config.yaml --to json
```

## Observability

Instrumented with `tracing`. Structured events for every finding, scan metrics, and JSON logs for collectors.

## License

MIT
