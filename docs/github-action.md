# Using the pipeguard GitHub Action

Scan your workflows on every PR and push.

## Minimal example

```yaml
name: Pipeline security

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write
  pull-requests: write   # only needed if comment_pr: true

jobs:
  pipeguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5

      - name: Scan CI/CD configs
        uses: Steeve-Crypto/pipeguard@v0.1.6
        with:
          path: .github/workflows
          min_severity: medium
          exclude: self-hosted-runner
          sarif: pipeguard.sarif
          fail_on_findings: "true"
          comment_pr: "true"

      - name: Upload to Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: pipeguard.sarif
```

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.github/workflows` | File or directory to scan |
| `min_severity` | `low` | `low` \| `medium` \| `high` \| `critical` |
| `fail_on` | empty | Exit 1 if any finding meets this severity |
| `exclude` | empty | Comma-separated rule IDs to ignore |
| `sarif` | `pipeguard.sarif` | SARIF output path (empty to skip) |
| `fail_on_findings` | `true` | Fail the job when findings exist |
| `comment_pr` | `false` | Post a summary comment on the PR |
| `token` | `${{ github.token }}` | Token used for PR comments |

## Outputs

| Output | Description |
|--------|-------------|
| `sarif_path` | Path to the generated SARIF file |
| `findings_count` | Number of findings reported |

## Notes

- The Action installs Rust if missing, then builds from the tag you pin.
- Pin to a release tag in production: `Steeve-Crypto/pipeguard@v0.1.6`.
- A `pipeguard.toml` in the scanned tree is honored; Action inputs override it.
- Pair with [OSSF Scorecard](scorecard.md) for repo-level posture + pipeline content checks.
