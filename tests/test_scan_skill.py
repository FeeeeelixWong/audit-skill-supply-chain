"""Regression tests for provenance URL parsing."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "audit-skill-supply-chain" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import scan_skill  # noqa: E402


class ParseGitHubRefTests(unittest.TestCase):
    def test_accepts_canonical_github_references(self) -> None:
        self.assertEqual(scan_skill.parse_github_ref("github.com/Owner/Repo"), ("owner/repo", None))
        self.assertEqual(
            scan_skill.parse_github_ref("https://github.com/Owner/Repo/tree/0123456789abcdef"),
            ("owner/repo", "0123456789abcdef"),
        )
        self.assertEqual(scan_skill.parse_github_ref("git@github.com:Owner/Repo.git"), ("owner/repo", None))

    def test_rejects_ambiguous_or_non_github_urls(self) -> None:
        for value in (
            "https://github.com@evil.example/Owner/Repo",
            "https://evil.example/github.com/Owner/Repo",
            "https://github.com:443/Owner/Repo",
            "https://github.com:not-a-port/Owner/Repo",
            "https://user@github.com/Owner/Repo",
            "https://github.com/Owner/Repo?ref=main",
            "https://github.com/Owner/Repo#readme",
        ):
            with self.subTest(value=value):
                self.assertEqual(scan_skill.parse_github_ref(value), (None, None))


if __name__ == "__main__":
    unittest.main()
