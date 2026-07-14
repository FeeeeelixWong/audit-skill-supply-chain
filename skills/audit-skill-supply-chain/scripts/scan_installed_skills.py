#!/usr/bin/env python3
"""Scan already-installed agent skills for high-risk behavior.

This script is intended for the first baseline pass after installing
audit-skill-supply-chain. It treats missing provenance as informational because
older installed skills often lack source metadata.
"""

from __future__ import annotations

import argparse
import json
import sys
from argparse import Namespace
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import scan_skill  # noqa: E402


SEVERITY_ORDER = scan_skill.SEVERITY_ORDER
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache"}


def default_roots() -> list[Path]:
    home = Path.home()
    roots = [
        home / ".codex" / "skills",
        home / ".claude" / "skills",
        Path.cwd() / "skills",
    ]
    return [root for root in roots if root.exists()]


def discover_skill_dirs(roots: list[Path], max_depth: int) -> list[Path]:
    found: set[Path] = set()

    def walk(path: Path, depth: int) -> None:
        if depth > max_depth:
            return
        if path.name in SKIP_DIRS:
            return
        if (path / "SKILL.md").exists():
            found.add(path.resolve())
            return
        try:
            children = sorted(path.iterdir(), key=lambda item: item.name)
        except OSError:
            return
        for child in children:
            if child.name in SKIP_DIRS:
                continue
            if child.is_symlink():
                # Never let a baseline inventory escape a configured skill root.
                continue
            if child.is_dir():
                walk(child, depth + 1)

    for root in roots:
        walk(root.expanduser().resolve(), 0)
    return sorted(found)


def run_scan(skill_dir: Path, max_bytes: int) -> dict:
    findings: list[scan_skill.Finding] = []
    args = Namespace(
        source_url=None,
        expected_commit=None,
        artifact=None,
        expected_sha256=None,
        installed_baseline=True,
    )
    try:
        scan_skill.scan_provenance(skill_dir, args, findings)
        if skill_dir.resolve() == SCRIPT_DIR.parent.resolve():
            findings.append(
                scan_skill.Finding(
                    "INFO",
                    "scanner-self",
                    ".",
                    None,
                    "Skipped recursive scan of the active audit skill",
                    "The active scanner's own rules and examples are not third-party skill content.",
                    "Use repository CI and release verification to review changes to the audit skill itself.",
                )
            )
        else:
            scan_skill.scan_structure(skill_dir, findings)
            scan_skill.scan_files(skill_dir, max_bytes, findings)
    except Exception as exc:
        return {
            "target": str(skill_dir),
            "gate": "BLOCK",
            "summary": {"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 1, "CRITICAL": 0},
            "findings": [
                {
                    "severity": "HIGH",
                    "category": "scanner-error",
                    "path": ".",
                    "line": None,
                    "title": "Scanner failed",
                    "evidence": str(exc),
                    "recommendation": "Review this skill manually before trusting it.",
                }
            ],
        }
    return {
        "target": str(skill_dir),
        "gate": scan_skill.gate_for_findings(findings),
        "summary": scan_skill.summarize(findings),
        "findings": [asdict(finding) for finding in findings],
    }


def overall_gate(results: list[dict]) -> str:
    highest = 0
    for result in results:
        for severity, count in result.get("summary", {}).items():
            if count:
                highest = max(highest, SEVERITY_ORDER[severity])
    if highest >= SEVERITY_ORDER["HIGH"]:
        return "BLOCK"
    if highest == SEVERITY_ORDER["MEDIUM"]:
        return "QUARANTINE"
    if highest == SEVERITY_ORDER["LOW"]:
        return "ALLOW WITH CONDITIONS"
    return "ALLOW"


def markdown_literal(value: object) -> str:
    """Render untrusted data as one escaped JSON string, never Markdown syntax."""
    escaped = json.dumps(str(value), ensure_ascii=False)
    for character, replacement in {
        "&": "\\u0026",
        "<": "\\u003c",
        ">": "\\u003e",
        "[": "\\u005b",
        "]": "\\u005d",
        "`": "\\u0060",
        "|": "\\u007c",
    }.items():
        escaped = escaped.replace(character, replacement)
    return escaped


def write_markdown_report(path: Path, roots: list[Path], results: list[dict]) -> None:
    lines = [
        "# Installed Skill Baseline Audit",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Roots",
        "",
    ]
    lines.extend(f"- {markdown_literal(root)}" for root in roots)
    lines.extend(["", "## Summary", ""])
    lines.append(f"- Overall gate: `{overall_gate(results)}`")
    lines.append(f"- Skills scanned: {len(results)}")
    lines.append("")
    lines.append("| Gate | Skill | Critical | High | Medium | Low | Info |")
    lines.append("| --- | --- | ---: | ---: | ---: | ---: | ---: |")
    for result in results:
        summary = result.get("summary", {})
        lines.append(
            "| {gate} | `{target}` | {critical} | {high} | {medium} | {low} | {info} |".format(
                gate=result.get("gate", "UNKNOWN"),
                target=markdown_literal(result.get("target", "")),
                critical=summary.get("CRITICAL", 0),
                high=summary.get("HIGH", 0),
                medium=summary.get("MEDIUM", 0),
                low=summary.get("LOW", 0),
                info=summary.get("INFO", 0),
            )
        )

    lines.extend(["", "## Actionable Findings", ""])
    for index, result in enumerate(results, 1):
        actionable = [
            finding
            for finding in result.get("findings", [])
            if SEVERITY_ORDER.get(finding.get("severity", "INFO"), 0) >= SEVERITY_ORDER["MEDIUM"]
        ]
        if not actionable:
            continue
        lines.append(f"### Skill {index}")
        lines.append("")
        lines.append(f"- Target (untrusted): {markdown_literal(result.get('target', ''))}")
        for finding in actionable:
            loc = finding.get("path") or "."
            if finding.get("line"):
                loc = f"{loc}:{finding['line']}"
            lines.append(
                f"- **{markdown_literal(finding.get('severity', 'UNKNOWN'))}** "
                f"{markdown_literal(finding.get('title', ''))} ({markdown_literal(loc)})"
            )
            lines.append(f"  Evidence (untrusted): {markdown_literal(finding.get('evidence', ''))}")
            lines.append(f"  Recommendation: {markdown_literal(finding.get('recommendation', ''))}")
        lines.append("")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan installed agent skill directories.")
    parser.add_argument("--path", action="append", help="Skill root or individual skill directory to scan")
    parser.add_argument("--max-depth", type=int, default=3, help="Maximum depth for discovering SKILL.md files")
    parser.add_argument("--max-bytes", type=int, default=512_000, help="Maximum bytes read per text file")
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    parser.add_argument("--report", help="Write a Markdown report to this path")
    parser.add_argument(
        "--fail-on",
        choices=["info", "low", "medium", "high", "critical"],
        default="high",
        help="Exit with status 2 when this severity or higher is present",
    )
    args = parser.parse_args()

    roots = [Path(item).expanduser().resolve() for item in args.path] if args.path else default_roots()
    skills = discover_skill_dirs(roots, args.max_depth)
    results = [run_scan(skill, args.max_bytes) for skill in skills]

    if args.report:
        write_markdown_report(Path(args.report).expanduser(), roots, results)

    if args.json:
        print(json.dumps({"roots": [str(root) for root in roots], "results": results}, indent=2, sort_keys=True))
    else:
        print(f"Installed skill baseline: {overall_gate(results)}")
        print(f"Roots: {', '.join(str(root) for root in roots)}")
        print(f"Skills scanned: {len(results)}")
        for result in results:
            summary = result.get("summary", {})
            actionable = summary.get("CRITICAL", 0) + summary.get("HIGH", 0) + summary.get("MEDIUM", 0)
            print(
                f"- {result.get('gate')}: {result.get('target')} "
                f"(C={summary.get('CRITICAL', 0)}, H={summary.get('HIGH', 0)}, "
                f"M={summary.get('MEDIUM', 0)}, L={summary.get('LOW', 0)}, actionable={actionable})"
            )
        if args.report:
            print(f"Report: {Path(args.report).expanduser()}")

    threshold = SEVERITY_ORDER[args.fail_on.upper()]
    for result in results:
        for severity, count in result.get("summary", {}).items():
            if count and SEVERITY_ORDER[severity] >= threshold:
                return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
