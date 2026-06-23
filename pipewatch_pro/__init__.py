"""pipewatch-pro — part of the Cognis Neural Suite.

CI/CD supply-chain auditor (GitHub Actions / GitLab CI) mapped to the OWASP
CI/CD Top 10, with offline OSV vulnerability enrichment. Stdlib-only core.
"""
from pipewatch_pro.core import (  # noqa: F401
    TOOL_NAME,
    TOOL_VERSION,
    Finding,
    Component,
    audit_text,
    audit_file,
    audit_paths,
    discover_pipeline_files,
    extract_components,
    summarize,
    scan,
    to_sarif,
    SEVERITY_ORDER,
)

__version__ = TOOL_VERSION
__all__ = [
    "TOOL_NAME", "TOOL_VERSION", "Finding", "Component",
    "audit_text", "audit_file", "audit_paths", "discover_pipeline_files",
    "extract_components", "summarize", "scan", "to_sarif", "SEVERITY_ORDER",
]
