#!/usr/bin/env python3
"""Create a release zip and SHA256 checksum for the installable skill."""

from __future__ import annotations

import argparse
import hashlib
import shutil
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILL_NAME = "audit-skill-supply-chain"
SKILL_DIR = ROOT / "skills" / SKILL_NAME
DIST_DIR = ROOT / "dist"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Package the audit-skill-supply-chain skill.")
    parser.add_argument("--version", default="0.1.0", help="Release version without leading v")
    args = parser.parse_args()

    if not SKILL_DIR.exists():
        raise SystemExit(f"missing skill directory: {SKILL_DIR}")

    DIST_DIR.mkdir(exist_ok=True)
    archive = DIST_DIR / f"{SKILL_NAME}-v{args.version}.zip"
    if archive.exists():
        archive.unlink()

    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(SKILL_DIR.rglob("*")):
            if path.is_dir() or "__pycache__" in path.parts:
                continue
            arcname = Path(SKILL_NAME) / path.relative_to(SKILL_DIR)
            zf.write(path, arcname.as_posix())

    checksum = sha256_file(archive)
    sums_path = DIST_DIR / "SHA256SUMS.txt"
    sums_path.write_text(f"{checksum}  {archive.name}\n", encoding="utf-8")
    print(f"wrote {archive}")
    print(f"sha256 {checksum}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
