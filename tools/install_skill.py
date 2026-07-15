#!/usr/bin/env python3
"""Compatibility wrapper for the attested-release bootstrap installer."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP_INSTALLER = ROOT / "skills" / "audit-skill-supply-chain" / "scripts" / "bootstrap_install.py"


def main() -> int:
    if not BOOTSTRAP_INSTALLER.is_file():
        raise SystemExit(f"missing bootstrap installer: {BOOTSTRAP_INSTALLER}")
    return subprocess.run([sys.executable, str(BOOTSTRAP_INSTALLER), *sys.argv[1:]], check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
