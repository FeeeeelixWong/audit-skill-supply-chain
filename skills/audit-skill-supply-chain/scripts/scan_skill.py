#!/usr/bin/env python3
"""Static scanner for untrusted agent skill directories.

The scanner is intentionally conservative: it reports leads for manual review
and never executes files from the target skill.
"""

from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse


SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

TEXT_SUFFIXES = {
    ".bash",
    ".cjs",
    ".css",
    ".fish",
    ".js",
    ".json",
    ".jsx",
    ".md",
    ".mjs",
    ".py",
    ".sh",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
    ".zsh",
}

SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build"}


@dataclass
class Finding:
    severity: str
    category: str
    path: str
    line: int | None
    title: str
    evidence: str
    recommendation: str


PATTERNS: list[tuple[str, str, str, re.Pattern[str], str]] = [
    (
        "CRITICAL",
        "remote-code-execution",
        "Downloads and immediately executes remote content",
        re.compile(r"(curl|wget)[^|;&\n]*(\|\s*(sh|bash|zsh|python|python3)|;\s*(sh|bash|zsh|python|python3))", re.I),
        "Remove remote execution. Vendor the code or require a pinned checksum and explicit user approval.",
    ),
    (
        "CRITICAL",
        "credential-access",
        "Reads common credential or agent configuration locations",
        re.compile(
            r"((cat|less|open|read\w*|fs\.readFile|copy|cp|upload|zip|tar|grep|rg)[^\n]{0,100}(\.env|~/\.ssh|/\.ssh/|id_rsa|id_ed25519|aws/credentials|gcloud|keychain|login\.keychain|browser profile|~/.codex|~/.claude)|process\.env|os\.environ|std::env|printenv|env\s*\|)",
            re.I,
        ),
        "Remove credential access or make it an explicit, user-scoped operation outside install time.",
    ),
    (
        "CRITICAL",
        "destructive-command",
        "Contains destructive filesystem or repository command",
        re.compile(r"\b(rm\s+-rf\s+(/|~|\$HOME|\.{1,2})|git\s+reset\s+--hard|git\s+clean\s+-fdx|chmod\s+-R\s+777|chown\s+-R)\b", re.I),
        "Remove destructive commands or put them behind explicit, narrow user confirmation.",
    ),
    (
        "HIGH",
        "code-execution",
        "Uses dynamic code execution",
        re.compile(r"\b(eval|exec|Function\s*\(|child_process|subprocess\.(run|Popen|call)|os\.system|os\.popen|spawn\s*\(|execSync|execFileSync)\b", re.I),
        "Verify the input source and replace dynamic execution with structured APIs where possible.",
    ),
    (
        "HIGH",
        "persistence",
        "Attempts persistence through startup files, hooks, or scheduled tasks",
        re.compile(r"(\.bashrc|\.zshrc|\.profile|crontab|LaunchAgents|launchctl|\.git/hooks|post-checkout|pre-commit|postinstall|preinstall|prepare)", re.I),
        "Remove persistence behavior from the skill or document and isolate it as a separate explicit setup step.",
    ),
    (
        "HIGH",
        "exfiltration",
        "Potential network exfiltration or webhook behavior",
        re.compile(r"(webhook|requestbin|pastebin|ngrok|discord(app)?\.com/api/webhooks|slack\.com/api|fetch\s*\(|axios\.|requests\.(post|put)|curl\s+-X\s+POST)", re.I),
        "Explain and constrain outbound traffic. Do not transmit local files, prompts, logs, or secrets.",
    ),
    (
        "HIGH",
        "private-data-access",
        "Mentions high-value private data or private-data connectors",
        re.compile(
            r"\b(gmail|outlook|email|google drive|sharepoint|box|slack|teams|calendar|browser history|cookies|private repos?|customer data|screenshots?|local files|cloud credentials)\b",
            re.I,
        ),
        "Require narrow, user-approved connector scope and verify no private data is transmitted or summarized unexpectedly.",
    ),
    (
        "CRITICAL",
        "wallet-secret-access",
        "Potential access to wallet secrets or signing material",
        re.compile(
            r"((read|copy|upload|send|export|backup|paste|print)[^\n]{0,100}(seed phrase|mnemonic|private key|wallet file|wallet\.json|keypair\.json)|(seed phrase|mnemonic|wallet private key|exchange api secret))",
            re.I,
        ),
        "Block installation unless the secret-handling path is removed. Skills should never request wallet seeds or private keys.",
    ),
    (
        "HIGH",
        "asset-loss-path",
        "Potential money, wallet, exchange, or payment action",
        re.compile(
            r"\b(sign transaction|send transaction|transfer funds|token transfer|withdraw|swap tokens?|approve spend|setApprovalForAll|change payout|refund payment|create charge|stripe|bank account|exchange api|trading api|payment link|recipient address)\b",
            re.I,
        ),
        "Require explicit user confirmation boundaries, dry-run behavior, and no secret reads before allowing installation.",
    ),
    (
        "HIGH",
        "prompt-injection",
        "Contains instruction override or prompt extraction language",
        re.compile(r"(ignore (all )?(previous|prior|above) instructions|disregard .*instructions|reveal .*system prompt|developer message|you are now|bypass (safety|approval|policy))", re.I),
        "Remove prompt-injection language unless it is clearly quoted as a test fixture.",
    ),
    (
        "MEDIUM",
        "obfuscation",
        "Contains encoded or obfuscated payload indicators",
        re.compile(r"(base64\s+-d|atob\s*\(|fromCharCode|\\x[0-9a-fA-F]{2}|[A-Za-z0-9+/]{120,}={0,2})"),
        "Inspect the decoded content and replace obfuscation with readable source.",
    ),
    (
        "MEDIUM",
        "external-url",
        "References external URL",
        re.compile(r"https?://[^\s)>'\"]+", re.I),
        "Verify the domain, maintainer context, and whether the URL is documentation, download, or exfiltration.",
    ),
    (
        "LOW",
        "secret-pattern",
        "Contains secret-like keyword",
        re.compile(
            r"\b(OPENAI_API_KEY|ANTHROPIC_API_KEY|API[_-]?KEY|SECRET[_-]?KEY|SECRET|PASSWORD|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|SEED[_-]?PHRASE|AUTH[_-]?TOKEN|BEARER[_-]?TOKEN)\b",
            re.I,
        ),
        "Confirm whether this is a placeholder, documentation, or a real credential.",
    ),
]


def rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def is_probably_binary(path: Path, sample_size: int = 4096) -> bool:
    try:
        data = path.read_bytes()[:sample_size]
    except OSError:
        return False
    return b"\0" in data


def iter_files(root: Path) -> Iterable[Path]:
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        base = Path(current)
        for name in files:
            yield base / name


def read_text(path: Path, max_bytes: int) -> str | None:
    if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in {"SKILL.md", "openai.yaml"}:
        if is_probably_binary(path):
            return None
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if len(data) > max_bytes:
        data = data[:max_bytes]
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace")


def is_guidance_line(path: Path, line: str) -> bool:
    stripped = line.strip()
    lower = stripped.lower()
    if path.suffix.lower() not in {".md", ".txt"}:
        return False
    if path.name in {"risk-model.md", "report-template.md", "provenance-and-isolation.md"} and stripped.startswith(
        ("- ", "* ", "|", "##", "###")
    ):
        return True
    if stripped.startswith("--source-url "):
        return True
    if stripped.startswith(("- ", "* ", "|")) and any(
        marker in lower
        for marker in (
            "check ",
            "confirm ",
            "do not ",
            "example",
            "avoid ",
            "lifecycle hooks",
            "patterns",
            "private-data",
            "require ",
            "remove ",
            "review ",
            "risk",
            "such as",
            "state whether",
            "verify ",
            "whether ",
            "without explicit",
        )
    ):
        return True
    if re.match(
        r"^-\s+(tool abuse|code execution|credential access|exfiltration|private-data exfiltration|asset-loss paths|persistence|destructive behavior|prompt injection|provenance)\b",
        stripped,
        re.I,
    ):
        return True
    return False


def is_detector_source(path: Path, line: str) -> bool:
    stripped = line.strip()
    if "re.compile(" in stripped or "PATTERNS" in stripped or "category" in stripped and "severity" in stripped:
        return True
    if path.suffix.lower() == ".py" and (
        stripped.startswith(("r\"", "r'", "\"", "'"))
        or stripped.endswith("\",")
        or stripped.endswith("',")
    ):
        return True
    return False


def contextualize_match(path: Path, line: str, severity: str, category: str, title: str) -> tuple[str, str, str]:
    if is_detector_source(path, line):
        return "INFO", f"{category}-detector", f"Detector source mentions: {title}"
    if is_guidance_line(path, line):
        return "INFO", f"{category}-guidance", f"Guidance mentions: {title}"
    return severity, category, title


def add_findings_for_text(path: Path, root: Path, text: str, findings: list[Finding]) -> None:
    for line_no, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped:
            continue
        for severity, category, title, pattern, recommendation in PATTERNS:
            if pattern.search(stripped):
                effective_severity, effective_category, effective_title = contextualize_match(
                    path, stripped, severity, category, title
                )
                findings.append(
                    Finding(
                        severity=effective_severity,
                        category=effective_category,
                        path=rel(path, root),
                        line=line_no,
                        title=effective_title,
                        evidence=stripped[:240],
                        recommendation=recommendation,
                    )
                )


def parse_frontmatter(text: str) -> dict[str, str]:
    if not text.startswith("---\n"):
        return {}
    end = text.find("\n---", 4)
    if end == -1:
        return {}
    result: dict[str, str] = {}
    for raw in text[4:end].splitlines():
        if ":" not in raw:
            continue
        key, value = raw.split(":", 1)
        result[key.strip()] = value.strip().strip("\"'")
    return result


def is_full_sha(value: str | None) -> bool:
    return bool(value and re.fullmatch(r"[0-9a-fA-F]{40}", value.strip()))


def parse_github_ref(value: str | None) -> tuple[str | None, str | None]:
    if not value:
        return None, None
    raw = value.strip()

    scp_match = re.match(r"git@github\.com:([^/\s]+)/([^/\s]+?)(?:\.git)?$", raw, re.I)
    if scp_match:
        return f"{scp_match.group(1)}/{scp_match.group(2)}".lower(), None

    if raw.startswith("github.com/"):
        raw = "https://" + raw

    parsed = urlparse(raw)
    if parsed.netloc.lower() != "github.com":
        return None, None

    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        return None, None

    owner = parts[0]
    repo = re.sub(r"\.git$", "", parts[1])
    ref = None
    if len(parts) >= 4 and parts[2] in {"tree", "commit", "releases"}:
        ref = parts[3]
    return f"{owner}/{repo}".lower(), ref


def find_git_dir(root: Path) -> Path | None:
    dot_git = root / ".git"
    if dot_git.is_dir():
        return dot_git
    if dot_git.is_file():
        try:
            content = dot_git.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            return None
        if content.startswith("gitdir:"):
            git_dir = content.split(":", 1)[1].strip()
            candidate = Path(git_dir)
            if not candidate.is_absolute():
                candidate = (root / candidate).resolve()
            return candidate if candidate.exists() else None
    return None


def read_origin_url(git_dir: Path) -> str | None:
    config_path = git_dir / "config"
    if not config_path.exists():
        return None
    parser = configparser.ConfigParser()
    try:
        parser.read(config_path)
    except configparser.Error:
        return None
    for section in parser.sections():
        if section == 'remote "origin"':
            return parser.get(section, "url", fallback=None)
    return None


def read_packed_ref(git_dir: Path, ref_name: str) -> str | None:
    packed_refs = git_dir / "packed-refs"
    if not packed_refs.exists():
        return None
    try:
        lines = packed_refs.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    for line in lines:
        if line.startswith("#") or not line.strip():
            continue
        parts = line.split()
        if len(parts) == 2 and parts[1] == ref_name and is_full_sha(parts[0]):
            return parts[0]
    return None


def read_head_commit(git_dir: Path) -> str | None:
    head_path = git_dir / "HEAD"
    if not head_path.exists():
        return None
    try:
        head = head_path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None
    if is_full_sha(head):
        return head.lower()
    if head.startswith("ref:"):
        ref_name = head.split(":", 1)[1].strip()
        ref_path = git_dir / ref_name
        if ref_path.exists():
            try:
                ref_value = ref_path.read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                ref_value = ""
            if is_full_sha(ref_value):
                return ref_value.lower()
        packed = read_packed_ref(git_dir, ref_name)
        if packed:
            return packed.lower()
    return None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_tree(root: Path) -> str:
    digest = hashlib.sha256()
    digest.update(b"skill-tree-v1\0")
    for path in sorted(iter_files(root), key=lambda item: rel(item, root)):
        relative = rel(path, root).replace(os.sep, "/")
        try:
            st = path.lstat()
        except OSError:
            continue
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(stat.S_IMODE(st.st_mode)).encode("ascii"))
        digest.update(b"\0")
        if stat.S_ISLNK(st.st_mode):
            digest.update(b"symlink\0")
            digest.update(os.readlink(path).encode("utf-8", errors="replace"))
        elif path.is_file():
            digest.update(b"file\0")
            digest.update(sha256_file(path).encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest()


def add_provenance_finding(
    findings: list[Finding],
    severity: str,
    title: str,
    evidence: str,
    recommendation: str,
) -> None:
    findings.append(Finding(severity, "provenance", ".", None, title, evidence, recommendation))


def scan_provenance(root: Path, args: argparse.Namespace, findings: list[Finding]) -> None:
    source_slug, source_ref = parse_github_ref(args.source_url)
    expected_commit = args.expected_commit.strip().lower() if args.expected_commit else None
    expected_sha = args.expected_sha256.strip().lower() if args.expected_sha256 else None
    integrity_verified = False
    installed_baseline = bool(getattr(args, "installed_baseline", False))

    if args.source_url and not source_slug:
        add_provenance_finding(
            findings,
            "MEDIUM",
            "Source URL is not a parseable GitHub repository",
            args.source_url,
            "Manually verify the source identity, owner, and immutable version before installation.",
        )

    if source_ref and not is_full_sha(source_ref):
        add_provenance_finding(
            findings,
            "MEDIUM",
            "GitHub source URL is pinned to a mutable or short ref",
            source_ref,
            "Use a full 40-character commit SHA or verified release checksum.",
        )

    if expected_commit and not is_full_sha(expected_commit):
        add_provenance_finding(
            findings,
            "MEDIUM",
            "Expected commit is not a full 40-character SHA",
            expected_commit,
            "Require a full commit SHA so a different revision cannot be substituted.",
        )

    if args.artifact:
        artifact = Path(args.artifact).expanduser().resolve()
        if not artifact.exists() or not artifact.is_file():
            add_provenance_finding(
                findings,
                "HIGH",
                "Release artifact cannot be found for checksum verification",
                str(artifact),
                "Re-download the release artifact into quarantine and verify its SHA256 before extraction.",
            )
        elif expected_sha:
            actual_sha = sha256_file(artifact)
            if actual_sha.lower() != expected_sha:
                add_provenance_finding(
                    findings,
                    "CRITICAL",
                    "Release artifact checksum mismatch",
                    f"expected {expected_sha}, got {actual_sha}",
                    "Reject the artifact. Do not install or inspect it as trusted source material.",
                )
            else:
                integrity_verified = True
        else:
            add_provenance_finding(
                findings,
                "MEDIUM",
                "Release artifact provided without expected SHA256",
                str(artifact),
                "Obtain a trusted checksum or keep the skill quarantined.",
            )
    elif expected_sha:
        actual_tree_sha = sha256_tree(root)
        if actual_tree_sha.lower() != expected_sha:
            add_provenance_finding(
                findings,
                "CRITICAL",
                "Directory tree checksum mismatch",
                f"expected {expected_sha}, got {actual_tree_sha}",
                "Reject the directory or re-acquire the exact reviewed artifact.",
            )
        else:
            integrity_verified = True

    git_dir = find_git_dir(root)
    if git_dir:
        origin_url = read_origin_url(git_dir)
        origin_slug, _ = parse_github_ref(origin_url)
        head_commit = read_head_commit(git_dir)

        if args.source_url and source_slug and origin_slug and origin_slug != source_slug:
            add_provenance_finding(
                findings,
                "CRITICAL",
                "GitHub remote does not match approved source",
                f"expected {source_slug}, got {origin_slug}",
                "Reject the checkout. Re-clone from the approved repository in quarantine.",
            )
        elif args.source_url and source_slug and not origin_slug:
            add_provenance_finding(
                findings,
                "HIGH",
                "Cannot verify GitHub remote against approved source",
                origin_url or "missing origin remote",
                "Require a matching GitHub origin URL or verified release checksum.",
            )

        approved_commit = expected_commit or (source_ref.lower() if is_full_sha(source_ref) else None)
        if approved_commit and is_full_sha(approved_commit):
            if head_commit and head_commit != approved_commit:
                add_provenance_finding(
                    findings,
                    "CRITICAL",
                    "Checked-out commit does not match approved commit",
                    f"expected {approved_commit}, got {head_commit}",
                    "Reject the checkout and review only the approved commit.",
                )
            elif not head_commit:
                add_provenance_finding(
                    findings,
                    "HIGH",
                    "Cannot determine checked-out commit",
                    str(git_dir),
                    "Use a normal Git checkout or verified release checksum before installation.",
                )
            else:
                integrity_verified = True
        elif origin_slug:
            add_provenance_finding(
                findings,
                "MEDIUM",
                "GitHub checkout is not pinned to a full commit SHA",
                origin_url or origin_slug,
                "Pin to a full 40-character commit SHA before promoting from quarantine.",
            )
    else:
        if expected_commit:
            add_provenance_finding(
                findings,
                "HIGH",
                "Expected commit cannot be verified because target is not a Git checkout",
                expected_commit,
                "Provide a Git checkout, verified release archive, or tree checksum.",
            )
        elif args.source_url and not integrity_verified:
            add_provenance_finding(
                findings,
                "MEDIUM",
                "Source URL supplied but local artifact has no verifiable commit or checksum",
                args.source_url,
                "Verify the release checksum or scan a checkout pinned to a full commit SHA.",
            )
        elif not integrity_verified:
            if installed_baseline:
                add_provenance_finding(
                    findings,
                    "INFO",
                    "No provenance evidence supplied for installed baseline scan",
                    "no .git directory, source URL, approved commit, or verified checksum",
                    "Record source metadata during the next update or reinstall through the safe installer.",
                )
                return
            add_provenance_finding(
                findings,
                "MEDIUM",
                "No provenance evidence supplied",
                "no .git directory, source URL, approved commit, or verified checksum",
                "Keep the skill quarantined until source identity and immutable version are documented.",
            )

    license_names = {"LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING", "NOTICE"}
    if not any((root / name).exists() for name in license_names):
        add_provenance_finding(
            findings,
            "LOW",
            "No license file found at skill root",
            ", ".join(sorted(license_names)),
            "Verify license and redistribution rights before installing third-party code.",
        )


def scan_structure(root: Path, findings: list[Finding]) -> None:
    skill_md = root / "SKILL.md"
    if not skill_md.exists():
        findings.append(
            Finding(
                "CRITICAL",
                "manifest",
                ".",
                None,
                "Missing SKILL.md",
                "No SKILL.md found at skill root",
                "Reject the package or move the real skill root into scope.",
            )
        )
        return

    text = read_text(skill_md, 256_000) or ""
    frontmatter = parse_frontmatter(text)
    if not frontmatter:
        findings.append(
            Finding(
                "HIGH",
                "manifest",
                "SKILL.md",
                None,
                "Missing or invalid frontmatter",
                "SKILL.md does not start with valid YAML frontmatter",
                "Require valid name and description fields before installation.",
            )
        )
    else:
        for required in ("name", "description"):
            if not frontmatter.get(required):
                findings.append(
                    Finding(
                        "HIGH",
                        "manifest",
                        "SKILL.md",
                        None,
                        f"Missing `{required}` in frontmatter",
                        str(frontmatter),
                        "Require minimal Codex skill metadata before installation.",
                    )
                )
        unexpected = sorted(set(frontmatter) - {"name", "description"})
        if unexpected:
            findings.append(
                Finding(
                    "MEDIUM",
                    "manifest",
                    "SKILL.md",
                    None,
                    "Unexpected frontmatter keys",
                    ", ".join(unexpected),
                    "Review nonstandard keys, especially tool grants or policy-affecting metadata.",
                )
            )
        description = frontmatter.get("description", "")
        if re.search(r"\b(always|every|all tasks|any request|must use)\b", description, re.I):
            findings.append(
                Finding(
                    "MEDIUM",
                    "trigger-scope",
                    "SKILL.md",
                    None,
                    "Potentially overbroad trigger description",
                    description[:240],
                    "Narrow the description to the skill's real use cases.",
                )
            )


def scan_files(root: Path, max_bytes: int, findings: list[Finding]) -> None:
    for path in iter_files(root):
        rel_path = rel(path, root)
        try:
            st = path.lstat()
        except OSError:
            continue

        if stat.S_ISLNK(st.st_mode):
            target = os.readlink(path)
            findings.append(
                Finding(
                    "MEDIUM",
                    "symlink",
                    rel_path,
                    None,
                    "Symlink inside skill",
                    target,
                    "Verify the symlink does not escape the skill directory or hide mutable content.",
                )
            )
            continue

        if st.st_size > 1_000_000:
            findings.append(
                Finding(
                    "MEDIUM",
                    "large-file",
                    rel_path,
                    None,
                    "Large file in skill",
                    f"{st.st_size} bytes",
                    "Inspect why a skill needs this file; quarantine binary or generated artifacts.",
                )
            )

        if stat.S_IMODE(st.st_mode) & 0o111:
            findings.append(
                Finding(
                    "LOW",
                    "executable-file",
                    rel_path,
                    None,
                    "Executable file in skill",
                    oct(stat.S_IMODE(st.st_mode)),
                    "Review executable content before allowing installation.",
                )
            )

        if path.name.startswith(".") and path.name not in {".gitignore"}:
            findings.append(
                Finding(
                    "LOW",
                    "hidden-file",
                    rel_path,
                    None,
                    "Hidden file in skill",
                    path.name,
                    "Review hidden files for payloads, config changes, or persistence hooks.",
                )
            )

        text = read_text(path, max_bytes)
        if text is not None:
            add_findings_for_text(path, root, text, findings)
        elif is_probably_binary(path):
            findings.append(
                Finding(
                    "MEDIUM",
                    "binary-file",
                    rel_path,
                    None,
                    "Binary file in skill",
                    f"{st.st_size} bytes",
                    "Confirm the binary is necessary, trusted, and not executed during install.",
                )
            )


def summarize(findings: list[Finding]) -> dict[str, int]:
    counts = {name: 0 for name in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] += 1
    return counts


def gate_for_findings(findings: list[Finding]) -> str:
    highest = max((SEVERITY_ORDER[f.severity] for f in findings), default=0)
    if highest >= SEVERITY_ORDER["HIGH"]:
        return "BLOCK"
    if highest == SEVERITY_ORDER["MEDIUM"]:
        return "QUARANTINE"
    if highest == SEVERITY_ORDER["LOW"]:
        return "ALLOW WITH CONDITIONS"
    return "ALLOW"


def print_text_report(root: Path, findings: list[Finding]) -> None:
    counts = summarize(findings)
    gate = gate_for_findings(findings)

    print(f"Target: {root}")
    print(f"Gate: {gate}")
    print("Findings: " + ", ".join(f"{k}={v}" for k, v in counts.items()))
    print()

    if not findings:
        print("No static findings. Continue with manual provenance and intent review.")
        return

    for finding in sorted(findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.path, f.line or 0)):
        loc = finding.path if finding.line is None else f"{finding.path}:{finding.line}"
        print(f"[{finding.severity}] {finding.title}")
        print(f"  Category: {finding.category}")
        print(f"  Location: {loc}")
        print(f"  Evidence: {finding.evidence}")
        print(f"  Recommendation: {finding.recommendation}")
        print()


def main() -> int:
    parser = argparse.ArgumentParser(description="Static scanner for untrusted agent skill directories.")
    parser.add_argument("target", help="Path to the skill directory to scan")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    parser.add_argument("--max-bytes", type=int, default=512_000, help="Maximum bytes read from each text file")
    parser.add_argument("--source-url", help="Approved GitHub repository URL for provenance comparison")
    parser.add_argument("--expected-commit", help="Approved full 40-character Git commit SHA")
    parser.add_argument("--artifact", help="Downloaded release archive or asset to hash before extraction/install")
    parser.add_argument("--expected-sha256", help="Expected SHA256 for --artifact, or tree digest when no artifact is provided")
    parser.add_argument(
        "--installed-baseline",
        action="store_true",
        help="Downgrade missing provenance to INFO for already-installed skill inventory scans",
    )
    parser.add_argument(
        "--fail-on",
        choices=["info", "low", "medium", "high", "critical"],
        help="Exit with status 2 when this severity or higher is present",
    )
    args = parser.parse_args()

    root = Path(args.target).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        print(f"error: target is not a directory: {root}", file=sys.stderr)
        return 1

    findings: list[Finding] = []
    scan_provenance(root, args, findings)
    scan_structure(root, findings)
    scan_files(root, args.max_bytes, findings)

    if args.json:
        print(
            json.dumps(
                {
                    "target": str(root),
                    "gate": gate_for_findings(findings),
                    "summary": summarize(findings),
                    "findings": [asdict(finding) for finding in findings],
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print_text_report(root, findings)

    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on.upper()]
        if any(SEVERITY_ORDER[f.severity] >= threshold for f in findings):
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
