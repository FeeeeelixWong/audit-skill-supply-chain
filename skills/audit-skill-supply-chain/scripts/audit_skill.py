#!/usr/bin/env python3
"""Unified entry point for baseline scans, candidate reviews, installs, and drift checks."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import install_manifest


SCRIPT_DIR = Path(__file__).resolve().parent
FORWARDED_COMMANDS = {
    "baseline": "scan_installed_skills.py",
    "scan": "scan_skill.py",
    "install": "safe_install_skill.py",
}


def print_usage() -> None:
    print(
        "Usage: audit_skill.py <baseline|scan|install|verify|recover> [options]\n\n"
        "  baseline  Scan already-installed skills.\n"
        "  scan      Review one quarantined candidate.\n"
        "  install   Scan and install the exact reviewed staging copy.\n"
        "  verify    Compare installed skills with their recorded reviewed hashes.\n"
        "  recover   Restore or finalize an interrupted install transaction."
    )


def verify_command(arguments: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Verify installed skills against the audit integrity manifest.")
    parser.add_argument("--manifest", default=str(install_manifest.default_manifest_path()))
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    args = parser.parse_args(arguments)

    try:
        result = install_manifest.verify_manifest(args.manifest)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"Manifest: {result['manifest']}")
        print(f"Gate: {result['gate']}")
        for record in result["records"]:
            print(f"[{record['status']}] {record['path']}")
            print(f"  {record['reason']}")
    return 0 if result["gate"] == "ALLOW" else 2


def recover_command(arguments: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Recover an interrupted audited skill install.")
    parser.add_argument("--manifest", default=str(install_manifest.default_manifest_path()))
    args = parser.parse_args(arguments)
    try:
        result = install_manifest.recover_pending_transaction(args.manifest)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print("No pending install transaction." if result is None else f"Recovered: {result}")
    return 0


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments or arguments[0] in {"-h", "--help"}:
        print_usage()
        return 0 if arguments else 1

    command = arguments.pop(0)
    if command == "verify":
        return verify_command(arguments)
    if command == "recover":
        return recover_command(arguments)
    script_name = FORWARDED_COMMANDS.get(command)
    if not script_name:
        print(f"error: unknown command: {command}", file=sys.stderr)
        print_usage()
        return 1
    result = subprocess.run([sys.executable, str(SCRIPT_DIR / script_name), *arguments], check=False)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
