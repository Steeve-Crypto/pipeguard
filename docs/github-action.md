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

jobs:
  pipeguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Scan CI/CD configs
        uses: Steeve-Crypto/pipeguard@main
        with:
          path: .github/workflows
          min_severity: medium
          sarif: pipeguard.sarif
          fail_on_findings: "true"

      - name: Upload to Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: pipeguard.sarif
```

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.github/workflows` | File or directory to scan |
| `min_severity` | `low` | `low` \| `medium` \| `high` \| `critical` |
| `sarif` | `pipeguard.sarif` | SARIF output path (empty to skip) |
| `fail_on_findings` | `true` | Fail the job when findings exist |

## Notes

- First run compiles pipeguard from source (Rust + cache). Later runs are faster via `Swatinem/rust-cache`.
- Pin to a tag or commit SHA in production once you cut releases, e.g. `Steeve-Crypto/pipeguard@v0.1.0`.
- Pair with [OSSF Scorecard](scorecard.md) for repo-level posture + pipeline content checks.
