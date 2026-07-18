#!/usr/bin/env python3
"""Install a skill only after auditing an immutable private staging copy."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import stat
import sys
import tempfile
import uuid
import zipfile
from argparse import Namespace
from dataclasses import asdict
from pathlib import Path, PurePosixPath


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import scan_skill  # noqa: E402
import install_manifest  # noqa: E402


BLOCKING_GATES = {"BLOCK", "QUARANTINE"}
SKILL_NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
STAGING_SKIP_DIRS = {"__pycache__", ".pytest_cache"}
INSTALL_SKIP_DIRS = {".git", "__pycache__", ".pytest_cache"}
MAX_ARCHIVE_ENTRIES = 10_000
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 50 * 1024 * 1024
CLI_DEST_ROOTS = {
    "codex": Path.home() / ".codex" / "skills",
    "claude": Path.home() / ".claude" / "skills",
}


def parse_skill_name(skill_md: Path) -> str:
    text = skill_md.read_text(encoding="utf-8", errors="replace")
    if not text.startswith("---\n"):
        raise ValueError("SKILL.md is missing frontmatter")
    end = text.find("\n---", 4)
    if end == -1:
        raise ValueError("SKILL.md frontmatter is not closed")
    for raw in text[4:end].splitlines():
        if raw.startswith("name:"):
            name = raw.split(":", 1)[1].strip().strip("\"'")
            if not SKILL_NAME_RE.fullmatch(name):
                raise ValueError("SKILL.md name must be a lowercase hyphen-case identifier")
            return name
    raise ValueError("SKILL.md is missing name")


def ignore_staging_entries(_dir: str, names: list[str]) -> set[str]:
    return {name for name in names if name in STAGING_SKIP_DIRS}


def ignore_install_entries(_dir: str, names: list[str]) -> set[str]:
    return {name for name in names if name in INSTALL_SKIP_DIRS}


def safe_destination(root: Path, skill_name: str) -> Path:
    root = root.expanduser().resolve()
    destination = (root / skill_name).resolve(strict=False)
    try:
        destination.relative_to(root)
    except ValueError as exc:
        raise ValueError("skill destination escapes the configured install root") from exc
    return destination


def destination_roots(cli: str, dest_root: str | None) -> list[Path]:
    if dest_root:
        return [Path(dest_root).expanduser().resolve()]
    if cli == "both":
        return [CLI_DEST_ROOTS["codex"].resolve(), CLI_DEST_ROOTS["claude"].resolve()]
    return [CLI_DEST_ROOTS[cli].resolve()]


def preflight_destinations(destinations: list[Path], replace: bool) -> None:
    if len(set(destinations)) != len(destinations):
        raise ValueError("duplicate install destinations are not allowed")
    for destination in destinations:
        if destination.is_symlink():
            raise ValueError(f"destination must not be a symlink: {destination}")
        if destination.exists():
            if not destination.is_dir():
                raise ValueError(f"destination is not a directory: {destination}")
            if not replace:
                raise FileExistsError(f"destination exists: {destination}; pass --replace to overwrite")


def verify_artifact(artifact: Path, expected_sha256: str | None) -> Path:
    if not expected_sha256 or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256.strip()):
        raise ValueError("--artifact requires a full 64-character --expected-sha256")
    artifact = artifact.expanduser().resolve()
    if not artifact.is_file():
        raise ValueError(f"artifact is not a file: {artifact}")
    actual_sha256 = scan_skill.sha256_file(artifact)
    if actual_sha256 != expected_sha256.strip().lower():
        raise ValueError("release artifact checksum mismatch")
    return artifact


def zip_member_path(member: zipfile.ZipInfo) -> tuple[str, ...]:
    if "\\" in member.filename or "\0" in member.filename:
        raise ValueError(f"unsafe archive member: {member.filename!r}")
    path = PurePosixPath(member.filename)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise ValueError(f"unsafe archive member: {member.filename!r}")
    return tuple(part for part in path.parts if part not in {"", "."})


def zip_member_is_symlink(member: zipfile.ZipInfo) -> bool:
    return stat.S_ISLNK((member.external_attr >> 16) & 0xFFFF)


def extract_verified_zip(artifact: Path, workspace: Path) -> Path:
    extract_root = (workspace / "artifact").resolve()
    extract_root.mkdir(parents=True)
    try:
        archive = zipfile.ZipFile(artifact)
    except zipfile.BadZipFile as exc:
        raise ValueError("artifact must be a valid ZIP archive") from exc

    with archive:
        members = archive.infolist()
        if len(members) > MAX_ARCHIVE_ENTRIES:
            raise ValueError("archive has too many entries for safe review")
        if sum(member.file_size for member in members) > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
            raise ValueError("archive exceeds the safe uncompressed review limit")

        for member in members:
            parts = zip_member_path(member)
            if zip_member_is_symlink(member):
                raise ValueError("archive contains a symlink; reject it before installation")
            destination = extract_root.joinpath(*parts)
            try:
                destination.resolve(strict=False).relative_to(extract_root)
            except ValueError as exc:
                raise ValueError(f"archive member escapes extraction root: {member.filename!r}") from exc
            if member.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists():
                raise ValueError(f"archive contains duplicate member: {member.filename!r}")
            with archive.open(member) as source, destination.open("xb") as target:
                shutil.copyfileobj(source, target, length=1024 * 1024)

    skill_roots = sorted(path.parent for path in extract_root.rglob("SKILL.md") if path.is_file())
    if len(skill_roots) != 1:
        raise ValueError("verified archive must contain exactly one skill root with SKILL.md")
    return skill_roots[0]


def stage_directory_candidate(candidate: Path, workspace: Path) -> Path:
    candidate = candidate.expanduser().resolve()
    if not candidate.is_dir():
        raise ValueError(f"candidate is not a directory: {candidate}")
    staged = workspace / "candidate"
    shutil.copytree(candidate, staged, symlinks=True, ignore=ignore_staging_entries)
    return staged


def prepare_staged_candidate(args: argparse.Namespace, workspace: Path) -> tuple[Path, bool]:
    if args.artifact:
        artifact = verify_artifact(Path(args.artifact), args.expected_sha256)
        return extract_verified_zip(artifact, workspace), True
    if not args.candidate:
        raise ValueError("provide a quarantined candidate directory or a verified --artifact")
    return stage_directory_candidate(Path(args.candidate), workspace), False


def run_scan(candidate: Path, args: argparse.Namespace, artifact_bound: bool) -> dict:
    findings: list[scan_skill.Finding] = []
    scan_args = Namespace(
        source_url=args.source_url,
        expected_commit=args.expected_commit,
        artifact=args.artifact,
        expected_sha256=args.expected_sha256,
        installed_baseline=False,
        artifact_bound=artifact_bound,
    )
    scan_skill.scan_provenance(candidate, scan_args, findings)
    scan_skill.scan_structure(candidate, findings)
    scan_skill.scan_files(candidate, 512_000, findings)
    return {
        "target": str(candidate),
        "gate": scan_skill.gate_for_findings(findings),
        "summary": scan_skill.summarize(findings),
        "decision": scan_skill.decision_for_findings(findings),
        "findings": [asdict(finding) for finding in findings],
    }


def remove_directory(path: Path) -> None:
    if path.is_symlink():
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)


def install_staged_skill(
    candidate: Path,
    destinations: list[Path],
    replace: bool,
    expected_tree_sha256: str,
    manifest_path: Path,
    manifest_existed: bool,
    manifest_before: dict,
    manifest_after: dict,
) -> tuple[Path, dict]:
    preflight_destinations(destinations, replace)
    token = uuid.uuid4().hex
    entries = [
        {
            "destination": str(destination),
            "temporary": str(destination.parent / f".{destination.name}.audit-stage-{token}"),
            "backup": str(destination.parent / f".{destination.name}.audit-backup-{token}"),
            "had_existing": destination.exists(),
        }
        for destination in destinations
    ]
    journal_path = install_manifest.begin_transaction(
        manifest_path,
        manifest_existed=manifest_existed,
        manifest_before=manifest_before,
        manifest_after=manifest_after,
        entries=entries,
        expected_tree_sha256=expected_tree_sha256,
    )
    transaction = install_manifest.load_transaction(manifest_path)
    if transaction is None:
        raise RuntimeError("install transaction disappeared before promotion")
    _transaction_path, transaction_data = transaction

    try:
        for entry in entries:
            destination = Path(entry["destination"])
            temporary = Path(entry["temporary"])
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(candidate, temporary, symlinks=True, ignore=ignore_install_entries)
            if scan_skill.sha256_tree(temporary) != expected_tree_sha256:
                raise ValueError("prepared install copy did not match the reviewed staging hash")

        for entry in entries:
            destination = Path(entry["destination"])
            temporary = Path(entry["temporary"])
            backup = Path(entry["backup"])
            if destination.exists():
                os.replace(destination, backup)
            os.replace(temporary, destination)
        install_manifest.update_transaction_state(journal_path, transaction_data, "promoted")
    except Exception:
        install_manifest.recover_pending_transaction(manifest_path)
        raise
    return journal_path, transaction_data


def main() -> int:
    parser = argparse.ArgumentParser(description="Safely install a skill after pre-install audit.")
    parser.add_argument("candidate", nargs="?", help="Quarantined skill directory; omit when installing from --artifact")
    parser.add_argument(
        "--cli",
        choices=["codex", "claude", "both"],
        default="codex",
        help="Live agent CLI skill root to install into when --dest-root is not set",
    )
    parser.add_argument("--dest-root", help="Custom live skill root")
    parser.add_argument("--source-url", help="Approved GitHub repository URL")
    parser.add_argument("--expected-commit", help="Approved full 40-character Git commit SHA")
    parser.add_argument("--artifact", help="Verified ZIP release archive; it is extracted privately and becomes the candidate")
    parser.add_argument("--expected-sha256", help="Expected SHA256 for --artifact, or tree digest when installing a directory")
    parser.add_argument("--allow-conditions", action="store_true", help="Allow ALLOW WITH CONDITIONS installs")
    parser.add_argument("--replace", action="store_true", help="Replace existing destination skill directory")
    parser.add_argument("--dry-run", action="store_true", help="Stage, scan, and report without copying to a live destination")
    parser.add_argument(
        "--manifest",
        default=str(install_manifest.default_manifest_path()),
        help="Integrity manifest written after a successful install",
    )
    args = parser.parse_args()

    if args.candidate and args.artifact:
        print("error: provide either a candidate directory or --artifact, not both", file=sys.stderr)
        return 1

    try:
        recovery = install_manifest.recover_pending_transaction(args.manifest)
        if recovery:
            print(f"Recovered: {recovery}")
        with tempfile.TemporaryDirectory(prefix="audit-skill-stage-") as temporary_dir:
            candidate, artifact_bound = prepare_staged_candidate(args, Path(temporary_dir))
            skill_md = candidate / "SKILL.md"
            if not skill_md.is_file():
                raise ValueError("candidate does not contain SKILL.md at the selected skill root")
            skill_name = parse_skill_name(skill_md)
            destinations = [safe_destination(root, skill_name) for root in destination_roots(args.cli, args.dest_root)]
            result = run_scan(candidate, args, artifact_bound)

            gate = result.get("gate", "BLOCK")
            print(f"Gate: {gate}")
            print("Findings: " + ", ".join(f"{key}={value}" for key, value in result.get("summary", {}).items()))
            decision = result.get("decision", {})
            if decision:
                print(f"Decision: {decision.get('reason')}")
                print(f"Next action: {decision.get('recommended_action')}")

            if gate in BLOCKING_GATES:
                print("Install blocked. Keep the candidate in quarantine and review findings.")
                return 2
            if gate == "ALLOW WITH CONDITIONS" and not args.allow_conditions:
                print("Install requires --allow-conditions after manual review.")
                return 2
            preflight_destinations(destinations, args.replace)
            reviewed_tree_sha256 = scan_skill.sha256_tree(candidate)
            if args.dry_run:
                for destination in destinations:
                    print(f"Dry run: would install verified staging copy -> {destination}")
                print(f"Dry run: would record integrity manifest -> {Path(args.manifest).expanduser()}")
                return 0
            manifest_path, manifest_existed, manifest_before, manifest_after = install_manifest.prepare_installation_manifest(
                args.manifest,
                destinations,
                skill_name=skill_name,
                tree_sha256=reviewed_tree_sha256,
                source_url=args.source_url,
                expected_commit=args.expected_commit,
                artifact_sha256=args.expected_sha256 if artifact_bound else None,
                gate=gate,
            )
            journal_path, transaction = install_staged_skill(
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
                    "error: install transaction was rolled back because the integrity record could not be written: "
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
