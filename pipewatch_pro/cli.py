"""PIPEWATCH-PRO command-line interface."""
from cognis_core import build_cli
from pipewatch_pro.core import scan, TOOL_NAME, TOOL_VERSION

main = build_cli(
    tool_name=TOOL_NAME,
    tool_version=TOOL_VERSION,
    description="CI/CD supply-chain auditor — GH Actions / GitLab CI / OWASP CI/CD Top 10",
    scan_fn=scan,
)

if __name__ == "__main__":
    import sys
    sys.exit(main())
