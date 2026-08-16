# OSSF Scorecard integration

[OpenSSF Scorecard](https://github.com/ossf/scorecard) measures repository security posture (branch protection, pinned dependencies, security policy, etc.).

## What we added

| File | Purpose |
|------|---------|
| `.github/workflows/scorecard.yml` | Runs Scorecard on schedule + pushes to `main` |
| `SECURITY.md` | Improves the **Security-Policy** check |

Results are:

1. Uploaded as SARIF to **GitHub Code Scanning** (Security tab)
2. Published to the OpenSSF API (`publish_results: true`) so a **Scorecard badge** can be shown

## Badge

After the first successful run with `publish_results: true`:

```markdown
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Steeve-Crypto/pipeguard/badge)](https://scorecard.dev/viewer/?uri=github.com/Steeve-Crypto/pipeguard)
```

## How this relates to pipeguard

| Tool | Focus |
|------|--------|
| **OSSF Scorecard** | Repo-level posture (process, config, supply chain hygiene) |
| **pipeguard** | Content of CI/CD pipelines (secrets, unpinned actions, dangerous permissions, injection) |

Together they cover both *how the project is run* and *what the pipelines contain*.

## Optional: PAT for Branch-Protection

For a higher Branch-Protection score on public repos, create a fine-grained PAT with appropriate admin/read permissions and add it as `SCORECARD_TOKEN`, then uncomment `repo_token` in the workflow.

See: https://github.com/ossf/scorecard-action#authentication-with-fine-grained-pat-optional
