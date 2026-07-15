#!/usr/bin/env python3
"""Persist and verify integrity records for skills installed through the audit gate."""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import scan_skill


SCHEMA_VERSION = 1
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


def default_manifest_path() -> Path:
    return Path.home() / ".agent-skill-audit" / "installed-skills.json"


def normalize_manifest_path(value: str | Path) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    # Resolve the parent for a stable absolute path, but preserve the final
    # component so callers can reject a manifest file that is itself a symlink.
    return path.parent.resolve(strict=False) / path.name


def empty_manifest() -> dict[str, Any]:
    return {"schema_version": SCHEMA_VERSION, "installations": {}}


def load_manifest(value: str | Path, *, require_exists: bool = False) -> tuple[Path, dict[str, Any]]:
    path = normalize_manifest_path(value)
    if path.is_symlink():
        raise ValueError(f"integrity manifest must be a regular file: {path}")
    if not path.exists():
        if require_exists:
            raise FileNotFoundError(f"integrity manifest does not exist: {path}")
        return path, empty_manifest()
    if not path.is_file():
        raise ValueError(f"integrity manifest must be a regular file: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"integrity manifest is not valid JSON: {path}") from exc
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("integrity manifest has an unsupported schema")
    if not isinstance(data.get("installations"), dict):
        raise ValueError("integrity manifest installations must be an object")
    return path, data


def write_manifest(value: str | Path, manifest: dict[str, Any]) -> Path:
    path = normalize_manifest_path(value)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError(f"integrity manifest must be a regular file: {path}")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return path


def transaction_path(value: str | Path) -> Path:
    manifest = normalize_manifest_path(value)
    return manifest.parent / f".{manifest.name}.install-transaction.json"


def write_transaction(path: Path, transaction: dict[str, Any]) -> Path:
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError(f"install transaction must be a regular file: {path}")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = json.dumps(transaction, indent=2, sort_keys=True) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return path


def prepare_installation_manifest(
    value: str | Path,
    destinations: list[Path],
    *,
    skill_name: str,
    tree_sha256: str,
    source_url: str | None,
    expected_commit: str | None,
    artifact_sha256: str | None,
    gate: str,
) -> tuple[Path, bool, dict[str, Any], dict[str, Any]]:
    if not SHA256_RE.fullmatch(tree_sha256):
        raise ValueError("installed skill tree hash must be a SHA256 digest")
    path = normalize_manifest_path(value)
    manifest_existed = path.exists()
    _path, before = load_manifest(path)
    after = json.loads(json.dumps(before))
    installed_at = datetime.now(timezone.utc).isoformat()
    for destination in destinations:
        target = destination.expanduser().resolve(strict=False)
        after["installations"][str(target)] = {
            "artifact_sha256": artifact_sha256.lower() if artifact_sha256 else None,
            "expected_commit": expected_commit.lower() if expected_commit else None,
            "gate": gate,
            "installed_at": installed_at,
            "name": skill_name,
            "source_url": source_url,
            "tree_sha256": tree_sha256,
        }
    return path, manifest_existed, before, after


def begin_transaction(
    manifest_path: Path,
    *,
    manifest_existed: bool,
    manifest_before: dict[str, Any],
    manifest_after: dict[str, Any],
    entries: list[dict[str, Any]],
    expected_tree_sha256: str,
) -> Path:
    if not SHA256_RE.fullmatch(expected_tree_sha256):
        raise ValueError("install transaction requires a SHA256 tree hash")
    path = transaction_path(manifest_path)
    if path.exists() or path.is_symlink():
        raise ValueError(f"pending install transaction requires recovery: {path}")
    transaction = {
        "entries": entries,
        "expected_tree_sha256": expected_tree_sha256,
        "manifest_after": manifest_after,
        "manifest_before": manifest_before,
        "manifest_existed": manifest_existed,
        "manifest_path": str(normalize_manifest_path(manifest_path)),
        "schema_version": SCHEMA_VERSION,
        "state": "prepared",
    }
    return write_transaction(path, transaction)


def load_transaction(value: str | Path) -> tuple[Path, dict[str, Any]] | None:
    path = transaction_path(value)
    if not path.exists() and not path.is_symlink():
        return None
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"install transaction must be a regular file: {path}")
    try:
        transaction = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"install transaction is not valid JSON: {path}") from exc
    if not isinstance(transaction, dict) or transaction.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("install transaction has an unsupported schema")
    return path, transaction


def update_transaction_state(transaction_path_value: Path, transaction: dict[str, Any], state: str) -> None:
    transaction["state"] = state
    write_transaction(transaction_path_value, transaction)


def remove_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    elif path.exists():
        shutil.rmtree(path)


def transaction_entries(transaction: dict[str, Any]) -> list[dict[str, Any]]:
    entries = transaction.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ValueError("install transaction has no destination entries")
    expected_hash = transaction.get("expected_tree_sha256")
    if not isinstance(expected_hash, str) or not SHA256_RE.fullmatch(expected_hash):
        raise ValueError("install transaction has no valid expected tree hash")
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("install transaction entry is malformed")
        destination = Path(str(entry.get("destination", "")))
        temporary = Path(str(entry.get("temporary", "")))
        backup = Path(str(entry.get("backup", "")))
        if not destination.is_absolute() or temporary.parent != destination.parent or backup.parent != destination.parent:
            raise ValueError("install transaction entry escapes its destination parent")
        if not temporary.name.startswith(f".{destination.name}.audit-stage-"):
            raise ValueError("install transaction has an unsafe temporary path")
        if not backup.name.startswith(f".{destination.name}.audit-backup-"):
            raise ValueError("install transaction has an unsafe backup path")
        if not isinstance(entry.get("had_existing"), bool):
            raise ValueError("install transaction entry is missing prior-state metadata")
    return entries


def recover_pending_transaction(value: str | Path) -> str | None:
    loaded = load_transaction(value)
    if loaded is None:
        return None
    journal_path, transaction = loaded
    entries = transaction_entries(transaction)
    manifest_path = normalize_manifest_path(transaction.get("manifest_path", ""))
    if manifest_path != normalize_manifest_path(value):
        raise ValueError("install transaction targets a different manifest")
    state = transaction.get("state")
    if state == "manifest-written":
        for entry in entries:
            remove_path(Path(entry["backup"]))
            remove_path(Path(entry["temporary"]))
        journal_path.unlink(missing_ok=True)
        return "finalized interrupted install transaction"
    if state not in {"prepared", "promoted"}:
        raise ValueError("install transaction has an unknown state")

    expected_hash = transaction["expected_tree_sha256"]
    for entry in reversed(entries):
        destination = Path(entry["destination"])
        backup = Path(entry["backup"])
        temporary = Path(entry["temporary"])
        if entry["had_existing"]:
            if backup.exists():
                if destination.exists() or destination.is_symlink():
                    if destination.is_dir() and not destination.is_symlink() and scan_skill.sha256_tree(destination) != expected_hash:
                        raise ValueError(f"cannot safely recover changed destination: {destination}")
                    remove_path(destination)
                os.replace(backup, destination)
        elif destination.exists() or destination.is_symlink():
            if destination.is_dir() and not destination.is_symlink() and scan_skill.sha256_tree(destination) != expected_hash:
                raise ValueError(f"cannot safely recover changed destination: {destination}")
            remove_path(destination)
        remove_path(temporary)

    if transaction.get("manifest_existed"):
        before = transaction.get("manifest_before")
        if not isinstance(before, dict):
            raise ValueError("install transaction is missing the previous manifest")
        write_manifest(manifest_path, before)
    else:
        manifest_path.unlink(missing_ok=True)
    journal_path.unlink(missing_ok=True)
    return "rolled back interrupted install transaction"


def record_installations(
    value: str | Path,
    destinations: list[Path],
    *,
    skill_name: str,
    tree_sha256: str,
    source_url: str | None,
    expected_commit: str | None,
    artifact_sha256: str | None,
    gate: str,
) -> Path:
    path, _manifest_existed, _before, manifest = prepare_installation_manifest(
        value,
        destinations,
        skill_name=skill_name,
        tree_sha256=tree_sha256,
        source_url=source_url,
        expected_commit=expected_commit,
        artifact_sha256=artifact_sha256,
        gate=gate,
    )
    for destination in destinations:
        target = destination.expanduser()
        if target.is_symlink() or not target.is_dir():
            raise ValueError(f"installed destination is not a regular directory: {target}")
        target = target.resolve()
        actual_hash = scan_skill.sha256_tree(target)
        if actual_hash != tree_sha256:
            raise ValueError(f"installed destination did not match the reviewed staging copy: {target}")
    return write_manifest(path, manifest)


def verify_manifest(value: str | Path) -> dict[str, Any]:
    path = normalize_manifest_path(value)
    pending = load_transaction(path)
    if pending is not None:
        journal_path, transaction = pending
        return {
            "manifest": str(path),
            "gate": "QUARANTINE",
            "records": [
                {
                    "path": str(journal_path),
                    "status": "PENDING_TRANSACTION",
                    "reason": f"Interrupted install transaction ({transaction.get('state', 'unknown')}); run audit_skill.py recover before trusting installed skills.",
                }
            ],
        }
    if path.is_symlink():
        raise ValueError(f"integrity manifest must be a regular file: {path}")
    if not path.exists():
        return {
            "manifest": str(path),
            "gate": "QUARANTINE",
            "records": [
                {
                    "path": str(path),
                    "status": "MISSING_MANIFEST",
                    "reason": "No integrity manifest exists; run installs through the audit gate before trusting installed skills.",
                }
            ],
        }

    path, manifest = load_manifest(path, require_exists=True)
    records: list[dict[str, str]] = []
    for raw_path, record in sorted(manifest["installations"].items()):
        if not isinstance(raw_path, str) or not isinstance(record, dict):
            records.append(
                {
                    "path": str(raw_path),
                    "status": "INVALID_RECORD",
                    "reason": "Manifest record is malformed and cannot be trusted.",
                }
            )
            continue
        target = Path(raw_path).expanduser()
        expected_hash = record.get("tree_sha256")
        if not target.is_absolute() or not isinstance(expected_hash, str) or not SHA256_RE.fullmatch(expected_hash):
            records.append(
                {
                    "path": raw_path,
                    "status": "INVALID_RECORD",
                    "reason": "Manifest record is missing an absolute path or valid tree hash.",
                }
            )
        elif target.is_symlink():
            records.append(
                {
                    "path": raw_path,
                    "status": "CHANGED",
                    "reason": "Installed skill path is now a symlink; re-audit before trusting it.",
                }
            )
        elif not target.is_dir():
            records.append(
                {
                    "path": raw_path,
                    "status": "MISSING",
                    "reason": "Installed skill directory is missing or no longer a directory.",
                }
            )
        elif scan_skill.sha256_tree(target) != expected_hash:
            records.append(
                {
                    "path": raw_path,
                    "status": "CHANGED",
                    "reason": "Installed content no longer matches the reviewed tree hash; re-audit before use.",
                }
            )
        else:
            records.append({"path": raw_path, "status": "MATCH", "reason": "Matches the reviewed tree hash."})

    return {
        "manifest": str(path),
        "gate": "ALLOW" if records and all(record["status"] == "MATCH" for record in records) else "QUARANTINE",
        "records": records,
    }
