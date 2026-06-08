# Demo 01 — Auditing a risky GitHub Actions release workflow

A team's `release.yml` looks fine to the naked eye, but it carries several
classic CI/CD supply-chain risks. PIPEWATCH-PRO finds them and (by default)
fails the build so the issues get fixed before they ship.

## Input

`.github/workflows/release.yml` — a release pipeline that:

- triggers on `pull_request_target` (runs with repo secrets in fork-PR context)
- pins `actions/checkout@v4` and `actions/setup-node` (one mutable tag, one SHA)
- pipes a remote installer straight into `sudo bash`
- hard-codes an AWS secret access key in an `env:` value
- interpolates `secrets.NPM_TOKEN` directly into a `run:` script
- declares no `permissions:` block (GITHUB_TOKEN defaults to broad scope)

## Run it

```bash
# human-readable
python -m pipewatch_pro audit demos/01-basic

# machine-readable for CI gating
python -m pipewatch_pro audit demos/01-basic --format json
```

## Expected outcome

Findings across multiple OWASP CI/CD Top 10 categories:

| Rule        | OWASP                              | What it caught                          |
|-------------|------------------------------------|-----------------------------------------|
| CICD-SEC-06 | Insufficient Credential Hygiene    | hard-coded AWS key; secret in run script|
| CICD-SEC-01 | Insufficient Flow Control          | `pull_request_target` trigger           |
| CICD-SEC-07 | Insecure System Configuration      | `curl ... | sudo bash`                  |
| CICD-SEC-04 | Poisoned Pipeline Execution        | `actions/checkout@v4` not SHA-pinned    |
| CICD-SEC-05 | Insufficient PBAC                  | no `permissions:` block                 |

Note: `actions/setup-node` is correctly pinned to a 40-char SHA and is
NOT flagged — that is the fix the other `uses:` lines should adopt.

Exit code is non-zero (default `--fail-on high`), so this workflow would
break the CI gate until remediated.
