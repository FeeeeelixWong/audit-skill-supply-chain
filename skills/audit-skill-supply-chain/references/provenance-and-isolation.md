# Provenance and Isolation

Use this reference for GitHub-hosted or release-archive skills.

## Quarantine First

Review candidate skills outside live install paths:

- Use `~/.codex/skill-quarantine/<repo>@<commit-or-version>/` or another throwaway directory.
- Do not clone, unzip, or copy directly into `~/.codex/skills`, `~/.claude/skills`, project `skills/`, or plugin cache directories.
- Do not run target scripts, package installers, lifecycle hooks, or setup commands during acquisition.
- Do not expose `.env`, SSH keys, wallet files, browser profiles, cloud credentials, API keys, or connector tokens to the target.
- After approval, copy only the exact reviewed directory into the live install path.

## GitHub Repository Checks

Prefer a full 40-character commit SHA. Treat branches, mutable tags, short SHAs, and "latest" URLs as unpinned.

Verify:

- Repository owner/name exactly matches the user-approved source.
- Local `HEAD` equals the approved full commit SHA.
- Remote URL has not changed between clone and review.
- The skill root is the reviewed subdirectory, not a sibling path with different content.
- The repository license allows use and redistribution.
- Security posture is appropriate: clear maintainer identity, normal issue/PR history, security policy or contact, signed releases or commits when available, and no sudden unexplained ownership transfer.

Do not let stars, forks, or "open source" status substitute for code review.

## Release Archive Checksums

When reviewing a release asset:

- Obtain the SHA256 checksum from a trusted release channel, signed checksum file, Sigstore/GPG artifact, or maintainer-controlled documentation.
- Verify the downloaded archive before extracting it.
- Reject checksum mismatches immediately.
- Treat archives without checksums as `QUARANTINE`; if the skill requests private-data, shell, write, wallet, payment, or production access, treat them as `BLOCK`.

## Maintainer Trust

Score maintainer trust against requested permissions:

- Low-risk text-only skill: license, visible source, narrow purpose, and no high-value permissions may be enough.
- Private-data skill: require strong repository history, clear owner, reviewed code, no hidden telemetry, and narrow connector access.
- Wallet/payment/production skill: require pinned commit or verified release checksum, explicit transaction/payment confirmation boundaries, no secret reads, no remote code execution, and strong maintainer provenance.

Red flags:

- New or renamed repository with no review history.
- Maintainer account recently created, transferred, or inconsistent with prior releases.
- Release asset differs from repository source.
- Minified or generated code without source.
- Binary blobs, hidden files, symlinks, or archives inside the skill.
- Instructions that normalize broad data collection, telemetry, signing, withdrawals, refunds, or cloud billing operations.

## Promotion to Install

Only promote after the final gate is `ALLOW` or `ALLOW WITH CONDITIONS`:

1. Record source URL, commit or checksum, scanner command, and gate decision.
2. Remove `.git`, hidden build artifacts, caches, and unneeded archives unless they are part of the approved skill.
3. Preserve only expected skill files: `SKILL.md`, `agents/`, `scripts/`, `references/`, and `assets/`.
4. Copy the reviewed artifact into the live skill directory.
5. Keep a note of the reviewed commit/checksum so future updates can be diffed.
