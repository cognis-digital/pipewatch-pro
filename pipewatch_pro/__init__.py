"""
PIPEWATCH-PRO — CI/CD supply-chain auditor — GH Actions / GitLab CI / OWASP CI/CD Top 10
Part of the Cognis Neural Suite by Cognis Digital.
https://cognis.digital · MIT License
"""
from pipewatch_pro.core import scan, TOOL_NAME, TOOL_VERSION

__version__ = TOOL_VERSION
__author__ = "Cognis Digital"
__license__ = "MIT"
__all__ = ["scan", "TOOL_NAME", "TOOL_VERSION", "__version__"]
