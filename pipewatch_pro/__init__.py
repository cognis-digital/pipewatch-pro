"""PIPEWATCH-PRO — CI/CD supply-chain auditor.

Audits GitHub Actions and GitLab CI pipeline definitions against the
OWASP Top 10 CI/CD Security Risks. Standard library only, zero install.
"""
from .core import (
    Finding,
    audit_text,
    audit_file,
    audit_paths,
    discover_pipeline_files,
    summarize,
    SEVERITY_ORDER,
)

TOOL_NAME = "PIPEWATCH-PRO"
TOOL_VERSION = "1.0.0"

__all__ = [
    "Finding",
    "audit_text",
    "audit_file",
    "audit_paths",
    "discover_pipeline_files",
    "summarize",
    "SEVERITY_ORDER",
    "TOOL_NAME",
    "TOOL_VERSION",
]
