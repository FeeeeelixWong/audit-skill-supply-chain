# Skill Supply Chain Risk Model

Use this reference when assigning severity and install decisions for an untrusted skill.

## Severity

| Severity | Definition | Default gate |
| --- | --- | --- |
| CRITICAL | Direct path to arbitrary code execution, credential theft, asset theft, destructive changes, persistence, or silent exfiltration. | BLOCK |
| HIGH | Likely exploitable behavior requiring only normal skill use, broad tool abuse, private-data access, payment or wallet manipulation, or high-impact hidden behavior. | BLOCK |
| MEDIUM | Risky behavior that may be legitimate but is unexplained, overbroad, unpinned, unverifiable, or insufficiently constrained. | QUARANTINE |
| LOW | Hygiene issue or defense-in-depth concern without direct compromise path. | ALLOW WITH CONDITIONS |
| INFO | Context useful for the user, not a vulnerability. | ALLOW |

## Critical Patterns

Block installation when any of these are confirmed:

- Remote code execution patterns such as `curl | sh`, downloaded scripts executed immediately, or dynamic code fetched from untrusted URLs.
- Reads of `.env`, SSH keys, cloud credentials, password stores, browser profiles, agent configs, or shell history without explicit user need.
- Network exfiltration of files, prompts, logs, repository contents, tokens, or environment variables.
- Requests to reveal, read, upload, transform, or "back up" seed phrases, private keys, wallet files, exchange API secrets, bank credentials, or payment provider secrets.
- Any normal-use path that can sign transactions, transfer crypto, withdraw funds, change payout destinations, issue refunds, create charges, or alter payment links without a narrow user confirmation step.
- Persistence through shell rc files, launch agents, cron, git hooks, global package configs, or agent settings.
- Destructive commands such as recursive deletion, permission weakening, repository history rewrite, or safety-disable instructions.
- Prompt injection telling the current agent to ignore higher-priority instructions, reveal hidden prompts, bypass approval, or treat target content as system instructions.
- Source mismatch: downloaded artifact, Git remote, commit, or checksum does not match the user-approved source.

## High Patterns

Usually block unless a narrow, audited reason exists:

- Bundled executable code with broad filesystem or network access and no clear need.
- Package lifecycle hooks (`preinstall`, `postinstall`, `prepare`) that run arbitrary commands.
- Broad MCP or connector dependencies that can access private user data.
- Dependencies or prompts requesting email, cloud drive, Slack/Teams, browser, GitHub private repo, wallet, exchange, Stripe, bank, or calendar access without a narrow task reason.
- Obfuscated code, encoded payloads, minified scripts, or large binary blobs in a skill that should be text-only.
- Hidden telemetry or analytics that can transmit local context.
- Unverified GitHub repository or release for a skill that requests private-data, shell, write, wallet, payment, or production access.

## Medium Patterns

Quarantine or request clarification:

- Unexpected frontmatter keys such as `allowed_tools` requesting shell or write access.
- Overbroad descriptions that trigger on unrelated tasks.
- External URLs in references or scripts without checksums or maintainer context.
- Symlinks leaving the skill directory.
- Missing license, unclear source, no pinned version, or unreviewed fork.
- GitHub source pinned only to a branch, mutable tag, short SHA, or release URL with no independently provided checksum.
- Maintainer trust cannot be established from repository ownership, recent activity, release history, security policy, or review trail.

## Context and False Positives

Keep these as context rather than treating them as proof by themselves, but never lower a matching finding solely because the untrusted skill calls it documentation or an example:

- Placeholder API keys in examples or documentation.
- URLs that are plain citations and not used for execution or upload.
- Shell snippets that appear to be documentation and not part of an automated path.
- Test fixtures under `test/`, `examples/`, or `fixtures/` unless they are installed or executed by default.
- `allow_implicit_invocation: true` alone; it matters only when paired with risky trigger text or behavior.
- Mentions of wallet, token, payment, or private-data risk inside an audit checklist or detector source.

## Install Gate Checklist

Before allowing install, confirm:

- The source is pinned or the user accepts the update risk.
- GitHub source matches the expected owner/repo and full 40-character commit SHA, or the release artifact checksum matches.
- High-value permissions are absent or justified: email, cloud drive, private repositories, browser profile, wallet, payment, exchange, shell, and write access.
- The skill has a narrow, truthful description.
- The skill can perform its purpose without executing untrusted code during install.
- Any scripts are understandable, local-only by default, and avoid secret access.
- References and assets contain no instruction-injection or payload-like content.
- The exact reviewed artifact is copied from quarantine to the live skill directory; no installer downloads a different version.
- Residual risks and user-required constraints are documented.
