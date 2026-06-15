"""PIPEWATCH-PRO MCP server — exposes scan as an MCP tool for Cognis.Studio."""
from cognis_core.mcp import build_mcp_server
from pipewatch_pro.core import scan, TOOL_NAME

_DESCRIPTION = (
    "CI/CD supply-chain auditor — GH Actions / GitLab CI / OWASP CI/CD Top 10"
)

run_mcp_server = build_mcp_server(
    tool_name=TOOL_NAME,
    description=_DESCRIPTION,
    scan_fn=scan,
)

if __name__ == "__main__":
    run_mcp_server()
