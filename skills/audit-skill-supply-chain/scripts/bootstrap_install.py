#!/usr/bin/env python3
"""Bootstrap this auditor only from its official GitHub-attested release."""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

import install_manifest
import safe_install_skill
import scan_skill


OFFICIAL_REPOSITORY = "FeeeeelixWong/audit-skill-supply-chain"
OFFICIAL_SOURCE_URL = f"https://github.com/{OFFICIAL_REPOSITORY}"
OFFICIAL_SIGNER_WORKFLOW = f"{OFFICIAL_REPOSITORY}/.github/workflows/release.yml"
SKILL_NAME = "audit-skill-supply-chain"
ATTESTED_BOOTSTRAP_GATE = "ALLOW (ATTESTED BOOTSTRAP)"


def verify_official_attestation(artifact: Path) -> None:
    command = [
        "gh",
        "attestation",
        "verify",
        str(artifact),
        "--repo",
        OFFICIAL_REPOSITORY,
        "--signer-workflow",
        OFFICIAL_SIGNER_WORKFLOW,
    ]
    try:
        result = subprocess.run(command, check=False)
    except FileNotFoundError as exc:
        raise ValueError("GitHub CLI is required to verify the official release attestation") from exc
    if result.returncode != 0:
        raise ValueError("official release attestation verification failed")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Install audit-skill-supply-chain from an official GitHub-attested release ZIP."
    )
    parser.add_argument("--artifact", required=True, help="Official release ZIP to verify and install")
    parser.add_argument("--expected-sha256", required=True, help="Full SHA256 from the release SHA256SUMS.txt")
    parser.add_argument(
        "--cli",
        choices=["codex", "claude", "both"],
        default="codex",
        help="Live agent CLI skill root to install into when --dest-root is not set",
    )
    parser.add_argument("--dest-root", help="Custom live skill root")
    parser.add_argument("--replace", action="store_true", help="Replace an existing installed auditor")
    parser.add_argument("--dry-run", action="store_true", help="Verify and stage the release without installing it")
    parser.add_argument(
        "--manifest",
        default=str(install_manifest.default_manifest_path()),
        help="Integrity manifest written after a successful install",
    )
    parser.add_argument(
        "--accept-attested-bootstrap",
        action="store_true",
        help="Explicitly accept this narrow bootstrap path after personally verifying the official release",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    if not args.accept_attested_bootstrap:
        print(
            "Bootstrap blocked. Pass --accept-attested-bootstrap only after reviewing the official release "
            "and its attestation.",
            file=sys.stderr,
        )
        return 2

    try:
        recovery = install_manifest.recover_pending_transaction(args.manifest)
        if recovery:
            print(f"Recovered: {recovery}")
        artifact = safe_install_skill.verify_artifact(Path(args.artifact), args.expected_sha256)
        verify_official_attestation(artifact)

        with tempfile.TemporaryDirectory(prefix="audit-skill-bootstrap-") as temporary_dir:
            candidate = safe_install_skill.extract_verified_zip(artifact, Path(temporary_dir))
            skill_name = safe_install_skill.parse_skill_name(candidate / "SKILL.md")
            if skill_name != SKILL_NAME:
                raise ValueError(f"official release must contain only {SKILL_NAME}")
            destinations = [
                safe_install_skill.safe_destination(root, skill_name)
                for root in safe_install_skill.destination_roots(args.cli, args.dest_root)
            ]
            safe_install_skill.preflight_destinations(destinations, args.replace)
            reviewed_tree_sha256 = scan_skill.sha256_tree(candidate)
            if args.dry_run:
                for destination in destinations:
                    print(f"Dry run: would install attested staging copy -> {destination}")
                print(f"Dry run: would record integrity manifest -> {Path(args.manifest).expanduser()}")
                return 0

            manifest_path, manifest_existed, manifest_before, manifest_after = (
                install_manifest.prepare_installation_manifest(
                    args.manifest,
                    destinations,
                    skill_name=skill_name,
                    tree_sha256=reviewed_tree_sha256,
                    source_url=OFFICIAL_SOURCE_URL,
                    expected_commit=None,
                    artifact_sha256=args.expected_sha256,
                    gate=ATTESTED_BOOTSTRAP_GATE,
                )
            )
            journal_path, transaction = safe_install_skill.install_staged_skill(
                candidate,
                destinations,
                args.replace,
                reviewed_tree_sha256,
                manifest_path,
                manifest_existed,
                manifest_before,
                manifest_after,
            )
            try:
                install_manifest.write_manifest(manifest_path, manifest_after)
                install_manifest.update_transaction_state(journal_path, transaction, "manifest-written")
                install_manifest.recover_pending_transaction(manifest_path)
            except Exception as exc:
                try:
                    install_manifest.recover_pending_transaction(manifest_path)
                except Exception as recovery_exc:
                    exc = RuntimeError(f"{exc}; recovery also failed: {recovery_exc}")
                print(
                    "error: bootstrap transaction was rolled back because the integrity record could not be written: "
                    f"{exc}",
                    file=sys.stderr,
                )
                return 1
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    for destination in destinations:
        print(f"Installed: {destination}")
    print(f"Integrity manifest: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
