# Skill Security Audit Report Template

Use this structure for the final answer.

## Gate

Decision: `BLOCK | QUARANTINE | ALLOW WITH CONDITIONS | ALLOW`

Target: path, repository, archive, version, or commit.

Scope: files reviewed, scanner command, and whether network/provenance review was performed.

Provenance: GitHub owner/repo, commit SHA, release artifact checksum, maintainer trust summary, and any mismatch or unverifiable claim.

Isolation: quarantine path used, live install path, and whether the final artifact is exactly the reviewed artifact.

## Findings

### [SEVERITY] Title

- Location: `path:line`
- Confidence: `1-10`
- Evidence: short excerpt or scanner finding
- Impact: what could happen if installed
- Remediation: exact change or constraint

## Privacy and Asset-Loss Risk

State whether the skill can access or influence:

- Secrets, environment variables, SSH keys, cloud credentials, browser profile data, or agent configs
- Email, calendar, Slack/Teams, cloud drive, private repositories, customer data, or local files
- Wallet keys, seed phrases, signing flows, transfers, swaps, exchange APIs, payment providers, payouts, refunds, or bank details

## Install Conditions

List required constraints for `ALLOW WITH CONDITIONS`, such as pinning a commit, removing a script, disabling a dependency, or installing only in a sandbox.

## Residual Risk

List uncertain issues, unavailable provenance checks, unreviewed generated files, binary assets, or network-dependent assumptions.

## Recommendation

State the next action plainly: install, patch then install, sandbox and test, or reject.
