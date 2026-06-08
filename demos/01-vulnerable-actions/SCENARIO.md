# Scenario: Workflow with multiple OWASP CI/CD Top 10 issues

Unpinned actions, secret in env block, no permissions block.

## Expected findings

- PW-ACT-001 × 2
- PW-SECRET-001
- PW-PERM-001

## Why this matters

This workflow can be hijacked by malicious/action versions or leak the secret. Fix all four before merge.
