"""Command-line interface for PIPEWATCH-PRO.

Subcommands
  audit    Scan CI/CD pipeline files against the OWASP CI/CD Top 10.
  enrich   Match the components a pipeline pulls (actions / container images /
           pinned pip & npm installs / CVE references) against the bundled,
           fully-offline OSV vulnerability database (262k real records).
  feeds    Thin passthrough to the edge/air-gap data-feed manager (datafeeds).

All processing is passive and offline: PIPEWATCH-PRO reads files, it never
performs network scanning or active probing.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    audit_paths,
    summarize,
    to_sarif,
    discover_pipeline_files,
    extract_components,
    SEVERITY_ORDER,
)


_SEV_GLYPH = {
    "critical": "CRIT", "high": "HIGH", "medium": "MED ",
    "low": "LOW ", "info": "INFO",
}


def _render_table(findings, summary) -> str:
    lines: list[str] = []
    lines.append(f"{TOOL_NAME} {TOOL_VERSION} - CI/CD supply-chain audit")
    lines.append("=" * 64)
    if not findings:
        lines.append("No findings. Pipelines pass the OWASP CI/CD checks.")
        return "\n".join(lines)
    for f in findings:
        loc = f"{f.file}:{f.line}" if f.line else f.file
        lines.append(f"[{_SEV_GLYPH.get(f.severity, f.severity)}] {f.rule_id}  {f.title}")
        lines.append(f"        at {loc}")
        lines.append(f"        evidence: {f.evidence}")
        lines.append(f"        fix: {f.remediation}")
        lines.append("")
    lines.append("-" * 64)
    sev = summary["by_severity"]
    parts = [f"{k}={sev[k]}" for k in sorted(sev, key=lambda s: SEVERITY_ORDER.get(s, 9))]
    lines.append(f"Total: {summary['total']}  ({', '.join(parts)})")
    lines.append(f"Gating (critical+high): {summary['failed']}")
    return "\n".join(lines)


def _cmd_audit(args) -> int:
    try:
        findings = audit_paths(args.paths)
    except FileNotFoundError as exc:
        print(f"error: path not found: {exc}", file=sys.stderr)
        return 2
    summary = summarize(findings)

    if args.format == "json":
        payload = {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "summary": summary,
            "findings": [f.to_dict() for f in findings],
        }
        print(json.dumps(payload, indent=2))
    elif args.format == "sarif":
        print(json.dumps(to_sarif(findings), indent=2))
    else:
        print(_render_table(findings, summary))

    # Fail the build when findings at/above the threshold exist.
    if args.fail_on == "never":
        return 0
    threshold = SEVERITY_ORDER[args.fail_on]
    worst_hit = any(SEVERITY_ORDER.get(f.severity, 9) <= threshold for f in findings)
    return 1 if worst_hit else 0


# --------------------------------------------------------------------------- #
# enrich — offline OSV vulnerability matching
# --------------------------------------------------------------------------- #
def _collect_components(paths):
    targets: list[str] = []
    for p in paths:
        if os.path.isdir(p):
            targets.extend(discover_pipeline_files(p))
        elif os.path.isfile(p):
            targets.append(p)
        else:
            raise FileNotFoundError(p)
    comps = []
    for t in targets:
        with open(t, "r", encoding="utf-8", errors="replace") as fh:
            comps.extend(extract_components(fh.read(), t))
    return comps


def enrich_components(comps, *, limit_per_component: int = 25) -> list[dict]:
    """Match each extracted component against the bundled OSV database.

    Returns one match record per (component, vulnerability) pair, fully offline.
    """
    from .vulndb_local import VulnDB, severity_band

    db = VulnDB()
    results: list[dict] = []
    for c in comps:
        if c.kind == "cve-ref":
            recs = db.by_cve(c.name)
        else:
            recs = db.package_match(c.name)
        for r in recs[:limit_per_component]:
            results.append({
                "component": c.name,
                "version": c.version,
                "kind": c.kind,
                "file": c.file,
                "line": c.line,
                "vuln_id": r.get("id"),
                "aliases": r.get("aliases", []),
                "ecosystem": r.get("ecosystem"),
                "summary": (r.get("summary") or "")[:240],
                "cvss": r.get("severity") or "",
                "severity": severity_band(r.get("severity") or ""),
                "published": r.get("published"),
            })
    return results


def _cmd_enrich(args) -> int:
    try:
        comps = _collect_components(args.paths)
    except FileNotFoundError as exc:
        print(f"error: path not found: {exc}", file=sys.stderr)
        return 2
    matches = enrich_components(comps)

    if args.format == "json":
        print(json.dumps({
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "components_scanned": len(comps),
            "matches": len(matches),
            "results": matches,
        }, indent=2))
    else:
        print(f"{TOOL_NAME} {TOOL_VERSION} - offline OSV enrichment")
        print("=" * 64)
        print(f"components extracted: {len(comps)}   vulnerability matches: {len(matches)}")
        print("-" * 64)
        if not matches:
            print("No components matched the bundled OSV corpus.")
        for m in matches:
            cve = next((a for a in m["aliases"] if str(a).upper().startswith("CVE")),
                       m["vuln_id"])
            print(f"[{m['severity'].upper():8}] {cve}  ({m['ecosystem']})")
            print(f"        component: {m['component']}@{m['version'] or '*'}  "
                  f"[{m['kind']}]  at {m['file']}:{m['line']}")
            if m["summary"]:
                print(f"        {m['summary']}")
            print()
    if args.fail_on_match and matches:
        return 1
    return 0


# --------------------------------------------------------------------------- #
# feeds — passthrough to the edge/air-gap data-feed manager
# --------------------------------------------------------------------------- #
def _cmd_feeds(args) -> int:
    from . import datafeeds
    return datafeeds.main(args.feeds_args)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pipewatch-pro",
        description="Audit CI/CD pipelines against the OWASP CI/CD Top 10 "
                    "(passive, offline).",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("audit", help="Audit pipeline files / directories.")
    a.add_argument("paths", nargs="+",
                   help="Files or directories (repos) to scan.")
    a.add_argument("--format", choices=("table", "json", "sarif"), default="table")
    a.add_argument("--fail-on",
                   choices=("critical", "high", "medium", "low", "info", "never"),
                   default="high", metavar="SEVERITY",
                   help="Exit non-zero if a finding at/above this severity "
                        "exists, or 'never' to always exit 0. Default: high.")
    a.set_defaults(func=_cmd_audit)

    e = sub.add_parser("enrich",
                       help="Match pipeline components against the bundled "
                            "offline OSV vulnerability database.")
    e.add_argument("paths", nargs="+",
                   help="Files or directories (repos) to scan for components.")
    e.add_argument("--format", choices=("table", "json"), default="table")
    e.add_argument("--fail-on-match", action="store_true",
                   help="Exit non-zero if any component matches a known vuln.")
    e.set_defaults(func=_cmd_enrich)

    fp = sub.add_parser("feeds",
                        help="Edge/air-gap data-feed manager (offline cache + "
                             "snapshot import/export). See `feeds -h`.")
    fp.add_argument("feeds_args", nargs=argparse.REMAINDER,
                    help="Arguments forwarded to the datafeeds CLI "
                         "(list / update / get / snapshot-export / ...).")
    fp.set_defaults(func=_cmd_feeds)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
