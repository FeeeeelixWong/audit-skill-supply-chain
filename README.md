# Audit Skill Supply Chain

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Agent Skill](https://img.shields.io/badge/Agent-Skill-blue.svg)](skills/audit-skill-supply-chain/SKILL.md)
[![Focus: Supply Chain Security](https://img.shields.io/badge/focus-supply--chain_security-red.svg)](skills/audit-skill-supply-chain/references/risk-model.md)

![Audit Skill Supply Chain security gate protecting private data and assets](docs/assets/audit-skill-supply-chain-cover.png)

**English** | [中文](#中文)

A pre-install security gate for open-source agent skills across Codex, Claude Code, and compatible CLI skill directories.

Agent skills are not just documentation. They can become operating instructions for an agent with filesystem, shell, network, connector, wallet, payment, or repository access. This project helps review a third-party skill before it is installed, with a strong focus on preventing privacy leakage, credential theft, supply-chain substitution, and asset loss.

It ships as a standard `SKILL.md` directory. The same installable skill works in Codex (`~/.codex/skills`) and Claude Code-style skill directories (`~/.claude/skills`). Codex-specific UI metadata lives in `agents/openai.yaml` and can be ignored by other CLIs.

The static scanner can block or quarantine detected matching patterns and invalid provenance. It cannot prove that every malicious behavior is absent, so an `ALLOW` is evidence for the reviewed artifact, not a blanket safety guarantee.

## Security Gate at a Glance / 安全闸门一览 🛡️

![A quarantined skill is scanned before risky data and money paths are blocked or a verified copy is installed](docs/assets/audit-skill-supply-chain-quarantine-flow.png)

An untrusted skill stays isolated while its provenance, content, privacy behavior, and asset-risk signals are reviewed. Candidates with detected blocking signals are stopped; only the exact reviewed copy can be promoted.
未信任 skill 会先隔离，再审查来源、内容、隐私行为和财产风险信号。检测到阻断信号的候选会被停止，只有已审查的同一份内容才能安装。

## Highlights ✨

- **Pre-install by default**: review skills in quarantine before copying them into a live skill directory.
- **First-run baseline**: scan the skills already installed on the machine after this auditor is installed.
- **Safe install wrapper**: make future skill installs go through scan-before-copy instead of direct installation.
- **Integrity ledger**: record the reviewed tree hash and provenance at install time, then detect changed or replaced skills before later use.
- **Provenance-aware**: check GitHub owner/repo, full commit pinning, release artifacts, and SHA256 checksums.
- **Privacy-first**: flag access to local files, secrets, browser data, email, cloud drives, private repositories, and connector data.
- **Asset-loss focused**: block wallet seed/private-key handling, signing flows, transfers, withdrawals, payout changes, refunds, and payment-provider abuse.
- **Agent-injection aware**: detect prompt-injection language that tries to override user, system, or safety instructions.
- **No target execution**: the scanner treats the target skill as data and never runs its bundled scripts.
- **Staged promotion**: safe install scans a private staging copy, rejects symlinks and oversized files, then promotes only that reviewed copy.

## Quick Start 🚀

Baseline-scan already installed skills:

```bash
python3 skills/audit-skill-supply-chain/scripts/audit_skill.py baseline \
  --report ~/.agent-skill-audit/installed-skills-baseline.md
```

Scan a local untrusted skill:

```bash
python3 skills/audit-skill-supply-chain/scripts/audit_skill.py scan /path/to/untrusted-skill
```

Scan a GitHub-sourced skill with provenance checks:

```bash
python3 skills/audit-skill-supply-chain/scripts/audit_skill.py scan /path/to/untrusted-skill \
  --source-url https://github.com/owner/repo \
  --expected-commit <40-character-commit-sha>
```

Inspect a release archive checksum without promoting an extracted directory:

```bash
python3 skills/audit-skill-supply-chain/scripts/audit_skill.py scan /path/to/extracted-skill \
  --artifact /path/to/release.zip \
  --expected-sha256 <sha256>
```

This produces `QUARANTINE` unless the archive is bound to the candidate by the safe installer. Install a verified ZIP directly; the installer privately extracts, scans, and promotes the exact archive content:

```bash
python3 skills/audit-skill-supply-chain/scripts/audit_skill.py install \
  --artifact /path/to/release.zip \
  --expected-sha256 <sha256> \
  --cli both
```

Safely install a quarantined skill only after it passes the gate:

```bash
python3 skills/audit-skill-supply-chain/scripts/audit_skill.py install /path/to/quarantined-skill \
  --cli both \
  --source-url https://github.com/owner/repo \
  --expected-commit <40-character-commit-sha>
```

Every successful install records the reviewed tree hash and provenance in `~/.agent-skill-audit/installed-skills.json`. Recheck it after an update or whenever an installed skill might have been modified:

```bash
python3 skills/audit-skill-supply-chain/scripts/audit_skill.py verify
```

`verify` returns `QUARANTINE` and a nonzero exit code when a tracked directory is missing, becomes a symlink, or no longer matches its reviewed content. Reinstall it through the gate rather than accepting the changed directory.

## Install This Skill 📦

### Verify and Bootstrap an Official Release

For a release produced after the attested release workflow is enabled, verify the ZIP with GitHub CLI **before extracting or running any file from it**:

```bash
gh attestation verify /path/to/audit-skill-supply-chain-vX.Y.Z.zip \
  --repo FeeeeelixWong/audit-skill-supply-chain \
  --signer-workflow FeeeeelixWong/audit-skill-supply-chain/.github/workflows/release.yml
```

Then compare the ZIP with the accompanying `SHA256SUMS.txt`. The attestation is signed through GitHub's OIDC/Sigstore path and binds the artifact to this repository, the release workflow, and its build commit. This bootstrap check deliberately uses GitHub CLI, not code inside the untrusted archive.

```bash
shasum -a 256 /path/to/audit-skill-supply-chain-vX.Y.Z.zip
```

The output must exactly match the ZIP entry in the release's `SHA256SUMS.txt`.

Only after both checks pass, extract the verified ZIP into a private quarantine directory and use its attested bootstrap installer. It repeats the attestation and checksum checks, safely extracts the exact ZIP into private staging, installs that staging copy atomically, and records its tree hash in the integrity manifest:

```bash
umask 077
quarantine="$(mktemp -d)"
unzip /path/to/audit-skill-supply-chain-vX.Y.Z.zip -d "$quarantine"
python3 "$quarantine/audit-skill-supply-chain/scripts/audit_skill.py" bootstrap \
  --artifact /path/to/audit-skill-supply-chain-vX.Y.Z.zip \
  --expected-sha256 <64-character-sha256-from-SHA256SUMS.txt> \
  --cli both \
  --accept-attested-bootstrap
```

The `--accept-attested-bootstrap` flag is explicit consent to trust this narrow, official-release bootstrap path. It does not authorize access to private data, wallets, or payment systems. Do not use this bootstrap command for any third-party skill; use the normal `audit_skill.py install` gate instead. Add `--replace` only when you explicitly approve replacing an existing auditor installation.

Use the skill by asking your agent CLI:

```text
Use $audit-skill-supply-chain to review this open-source skill before installing it.
```

After installation, run the first baseline scan:

```bash
python3 ~/.codex/skills/audit-skill-supply-chain/scripts/audit_skill.py baseline \
  --report ~/.agent-skill-audit/installed-skills-baseline.md
```

## Review Workflow 🔎

1. **Acquire in quarantine**: clone or extract into a temporary review directory, not a live skill path.
2. **Verify provenance**: require a full commit SHA or a verified release checksum.
3. **Run static scanning**: inspect manifests, scripts, references, assets, symlinks, hidden files, URLs, and high-risk phrases.
4. **Review privacy and money flows**: check whether the skill can access private data, credentials, wallets, payment systems, or production systems.
5. **Decide the install gate**: return `BLOCK`, `QUARANTINE`, `ALLOW WITH CONDITIONS`, or `ALLOW`. An `ALLOW WITH CONDITIONS` install requires `--allow-conditions` only after the user explicitly approves every privacy- or money-sensitive condition.
6. **Promote exact artifact only**: if allowed, promote the same private staging copy into the live install path and record its tree hash.
7. **Recheck before later trust**: run `audit_skill.py verify` after an update or suspected local modification; changed content returns `QUARANTINE`.

The skill cannot magically intercept every external installer at the operating-system level. To enforce pre-install scanning, use `audit_skill.py install` as the install path for new skills and ask Codex, Claude Code, or another compatible CLI to use `$audit-skill-supply-chain` whenever a new skill is being installed or updated.

## CLI Support 🖥️

| Tool | Support level | Install / adapter |
| --- | --- | --- |
| Codex | Native `SKILL.md` directory | `~/.codex/skills/audit-skill-supply-chain` |
| Claude Code | Native `SKILL.md` directory | `~/.claude/skills/audit-skill-supply-chain` |
| Gemini CLI | Instruction adapter | Use `audit_skill.py` and add the policy to `GEMINI.md` |
| Qwen Code | Instruction adapter | Use the Gemini-style `GEMINI.md` adapter where supported |
| GitHub Copilot coding agent | Instruction adapter | Use `AGENTS.md` or `.github/copilot-instructions.md` |
| Cursor | Instruction adapter | Use `AGENTS.md` or `.cursor/rules/*.mdc` |
| Aider, opencode, Amazon Q Developer, Windsurf, Kilo CLI | Script-first support | Run `audit_skill.py`; add equivalent project instructions when the tool supports them |
| Any other CLI | Generic | Use `audit_skill.py` with a custom `--dest-root` on its `install` command |

Generate project-level adapters for CLIs that use instruction files instead of native skill directories:

```bash
python3 tools/create_cli_adapter.py --project /path/to/project --target all
```

This can create or update `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.github/copilot-instructions.md`, and `.cursor/rules/audit-skill-supply-chain.mdc`.

## Repository Layout 🗂️

```text
.
├── skills/audit-skill-supply-chain/     # Installable agent skill
│   ├── SKILL.md                         # Agent workflow
│   ├── agents/openai.yaml               # UI metadata
│   ├── references/                      # Risk model and report templates
│   └── scripts/audit_skill.py           # Unified scan, install, and verify entry point
├── tools/                               # Install, adapter, release, and validation helpers
├── SECURITY.md                          # Vulnerability reporting policy
├── CONTRIBUTING.md                      # Contribution guide
└── LICENSE                              # MIT license
```

## What It Blocks 🚫

The gate blocks or quarantines detected matching patterns and failed integrity checks. It does not claim to detect every possible malicious behavior.

- Detected remote-code-execution patterns such as downloaded scripts executed immediately.
- Detected reads or uploads of `.env`, SSH keys, cloud credentials, browser profiles, agent configs, or shell history.
- Detected silent exfiltration of prompts, logs, local files, source code, email, cloud-drive data, private repositories, or connector data.
- Detected wallet seed phrases, private keys, exchange API secrets, transaction signing, token transfers, withdrawals, payout changes, refunds, or payment abuse.
- Detected prompt-injection language that tells the agent to ignore higher-priority instructions or hide behavior from the user.
- GitHub source mismatch, unpinned branch/tag installs, or checksum mismatch.
- Post-install changes, missing directories, or symlink replacement of a tracked skill.

## Security Model 🔐

This project is a defensive review tool. It does not prove a skill is safe. It raises evidence for manual review and encourages a strict install gate:

- `BLOCK`: confirmed high-impact risk.
- `QUARANTINE`: provenance or behavior cannot be verified.
- `ALLOW WITH CONDITIONS`: low-risk issues remain and must be constrained.
- `ALLOW`: no material issue was detected in the reviewed artifact; it is not proof of complete safety.

An `ALLOW` applies to the reviewed tree, not to future untracked changes. Run `audit_skill.py verify` to detect integrity drift before later trust or use.

## Automated Repository Review 🤖

This repository layers several independent checks around pull requests and ongoing repository security checks:

- **CodeRabbit** reviews each non-draft pull request after a repository owner has reviewed the requested GitHub App permissions and explicitly authorized it. Its repository configuration gives extra scrutiny to scanners, installers, CI workflows, and privacy- or asset-sensitive guidance.
- **CodeQL** scans Python and GitHub Actions code on pull requests, pushes to `main`, and weekly.
- **Dependency Review** fails a pull request that introduces a moderate-or-higher vulnerable dependency, and reports license or OpenSSF Scorecard information for new dependencies.
- **Dependabot** opens weekly pull requests for GitHub Actions updates.
- **OpenSSF Scorecard** evaluates repository-level supply-chain practices weekly and uploads findings to GitHub code scanning.
- **zizmor** reviews GitHub Actions definitions with a security-focused static analysis and uploads high-confidence findings to GitHub code scanning.

These services provide review evidence, not a safety guarantee and not an automatic merge decision. CodeRabbit requires third-party GitHub App permissions for code, commit statuses, issues, and pull requests; a repository owner must review those permissions and explicitly approve the installation. Then choose **Only select repositories** and select this repository only. See the [CodeRabbit GitHub integration guide](https://docs.coderabbit.ai/platforms/github-com).

## 中文

一个用于 Codex、Claude Code 及兼容 CLI skill 目录的开源 agent skill 安装前安全审查闸门。

Agent skill 不只是普通文档。它可能会成为 agent 的操作说明，而 agent 可能拥有文件系统、Shell、网络、连接器、钱包、支付或代码仓库权限。本项目用于在安装第三方 skill 之前进行审查，重点防止隐私泄漏、凭据盗取、供应链替换和财产损失。

它以标准 `SKILL.md` 目录形式发布。同一份可安装 skill 可用于 Codex（`~/.codex/skills`）和 Claude Code 风格 skill 目录（`~/.claude/skills`）。`agents/openai.yaml` 是 Codex UI 元数据，其他 CLI 可以忽略。

静态扫描器会阻断或隔离已检测到的匹配风险信号和无效来源，但不能证明所有恶意行为都不存在。因此，`ALLOW` 只是已审查产物的证据，不是无条件的安全保证。

## 项目亮点 ✨

- **默认安装前审查**：先在隔离目录中审查，再决定是否复制到真实 skill 目录。
- **首次基线扫描**：安装本审查 skill 后，先扫描本机已安装的 skill。
- **安全安装入口**：后续安装新 skill 时先扫描再复制，避免直接安装。
- **完整性台账**：安装时记录已审查内容的哈希和来源证据，之后可检测目录被替换或修改。
- **来源可信度检查**：检查 GitHub owner/repo、完整 commit pin、release artifact 和 SHA256 checksum。
- **隐私优先**：标记本地文件、密钥、浏览器数据、邮箱、云盘、私有仓库和连接器数据访问风险。
- **防财产损失**：阻断钱包助记词/私钥处理、签名流程、转账、提现、收款地址变更、退款和支付服务滥用。
- **识别 prompt injection**：检测试图覆盖用户、系统或安全指令的恶意提示词。
- **不执行目标代码**：扫描器把目标 skill 当成数据处理，不运行目标 skill 自带脚本。
- **私有暂存提升**：安全安装器先审计私有暂存副本，拒绝符号链接和超出审查上限的文件，只提升已审查副本。

## 快速开始 🚀

扫描本机已安装 skill：

```bash
python3 skills/audit-skill-supply-chain/scripts/audit_skill.py baseline \
  --report ~/.agent-skill-audit/installed-skills-baseline.md
```

扫描本地未信任 skill：

```bash
python3 skills/audit-skill-supply-chain/scripts/audit_skill.py scan /path/to/untrusted-skill
```

扫描来自 GitHub 的 skill，并检查来源：

```bash
python3 skills/audit-skill-supply-chain/scripts/audit_skill.py scan /path/to/untrusted-skill \
  --source-url https://github.com/owner/repo \
  --expected-commit <40-character-commit-sha>
```

只检查 release 压缩包的 checksum，不把它与已解压目录混为一谈：

```bash
python3 skills/audit-skill-supply-chain/scripts/audit_skill.py scan /path/to/extracted-skill \
  --artifact /path/to/release.zip \
  --expected-sha256 <sha256>
```

在安全安装器把压缩包和候选目录绑定前，该命令会返回 `QUARANTINE`。安装已校验 ZIP 时请直接传入压缩包；安装器会私有解压、扫描并提升同一份内容：

```bash
python3 skills/audit-skill-supply-chain/scripts/audit_skill.py install \
  --artifact /path/to/release.zip \
  --expected-sha256 <sha256> \
  --cli both
```

只在候选 skill 通过闸门后安全安装：

```bash
python3 skills/audit-skill-supply-chain/scripts/audit_skill.py install /path/to/quarantined-skill \
  --cli both \
  --source-url https://github.com/owner/repo \
  --expected-commit <40-character-commit-sha>
```

每次成功安装都会把已审查树的哈希和来源信息记录到 `~/.agent-skill-audit/installed-skills.json`。在更新后或怀疑本地内容被修改时运行：

```bash
python3 skills/audit-skill-supply-chain/scripts/audit_skill.py verify
```

当已记录目录缺失、变成符号链接或内容不再匹配时，`verify` 会返回 `QUARANTINE` 和非零退出码。不要直接接受变化后的目录，应重新通过安装闸门安装。

## 安装这个 Skill 📦

### 验证并自举安装官方 Release

对于启用带 attestation 发布工作流之后创建的 release，在解压或运行其中任何文件**之前**，先用 GitHub CLI 验证 ZIP：

```bash
gh attestation verify /path/to/audit-skill-supply-chain-vX.Y.Z.zip \
  --repo FeeeeelixWong/audit-skill-supply-chain \
  --signer-workflow FeeeeelixWong/audit-skill-supply-chain/.github/workflows/release.yml
```

随后将 ZIP 与同一 Release 附带的 `SHA256SUMS.txt` 比对。该 attestation 经 GitHub OIDC/Sigstore 路径签名，会把产物绑定到本仓库、发布工作流和构建 commit。这个启动信任检查刻意使用 GitHub CLI，而不执行未验证压缩包中的代码。

```bash
shasum -a 256 /path/to/audit-skill-supply-chain-vX.Y.Z.zip
```

输出必须与同一 Release 的 `SHA256SUMS.txt` 中 ZIP 条目完全一致。

两项验证都通过后，才可以把 ZIP 解压到私有隔离目录，并使用其中的已证明自举安装器。它会再次验证 attestation 和 checksum，把同一 ZIP 安全解压到私有暂存区，原子安装该暂存副本，并把树哈希记录到完整性台账：

```bash
umask 077
quarantine="$(mktemp -d)"
unzip /path/to/audit-skill-supply-chain-vX.Y.Z.zip -d "$quarantine"
python3 "$quarantine/audit-skill-supply-chain/scripts/audit_skill.py" bootstrap \
  --artifact /path/to/audit-skill-supply-chain-vX.Y.Z.zip \
  --expected-sha256 <SHA256SUMS.txt 中的 64 位 SHA256> \
  --cli both \
  --accept-attested-bootstrap
```

`--accept-attested-bootstrap` 表示用户明确同意信任这条狭窄的官方 Release 自举路径；它不授权访问私有数据、钱包或支付系统。不要对任何第三方 skill 使用该自举命令，第三方 skill 必须走普通 `audit_skill.py install` 安装闸门。只有明确同意替换已安装审计器时，才添加 `--replace`。

在你的 agent CLI 中这样调用：

```text
Use $audit-skill-supply-chain to review this open-source skill before installing it.
```

安装后先跑一次本机基线扫描：

```bash
python3 ~/.codex/skills/audit-skill-supply-chain/scripts/audit_skill.py baseline \
  --report ~/.agent-skill-audit/installed-skills-baseline.md
```

## 审查流程 🔎

1. **隔离获取**：克隆或解压到临时审查目录，不直接放入真实 skill 路径。
2. **验证来源**：要求完整 commit SHA 或已验证 release checksum。
3. **运行静态扫描**：检查 manifest、脚本、参考文件、资产、符号链接、隐藏文件、URL 和高风险语句。
4. **审查隐私和资金路径**：确认 skill 是否能访问私有数据、凭据、钱包、支付系统或生产系统。
5. **给出安装闸门结论**：返回 `BLOCK`、`QUARANTINE`、`ALLOW WITH CONDITIONS` 或 `ALLOW`。对于 `ALLOW WITH CONDITIONS`，必须在用户明确同意每一项隐私或资金敏感条件后，才可使用 `--allow-conditions` 安装。
6. **只提升已审查产物**：如果允许安装，只提升私有暂存中的同一份已审查 skill，并记录它的树哈希。
7. **后续信任前复核**：更新后或怀疑本地内容被改动时运行 `audit_skill.py verify`；发生漂移即返回 `QUARANTINE`。

这个 skill 不能在操作系统层面神奇拦截所有外部安装器。要强制安装前审查，请把 `audit_skill.py install` 作为新 skill 的安装入口，并在安装或更新 skill 时要求 Codex、Claude Code 或其他兼容 CLI 使用 `$audit-skill-supply-chain`。

## CLI 支持 🖥️

| 工具 | 支持级别 | 安装 / 适配方式 |
| --- | --- | --- |
| Codex | 原生 `SKILL.md` 目录 | `~/.codex/skills/audit-skill-supply-chain` |
| Claude Code | 原生 `SKILL.md` 目录 | `~/.claude/skills/audit-skill-supply-chain` |
| Gemini CLI | 指令适配 | 使用 `audit_skill.py`，并把策略加入 `GEMINI.md` |
| Qwen Code | 指令适配 | 在支持 Gemini 风格上下文时使用 `GEMINI.md` 适配 |
| GitHub Copilot coding agent | 指令适配 | 使用 `AGENTS.md` 或 `.github/copilot-instructions.md` |
| Cursor | 指令适配 | 使用 `AGENTS.md` 或 `.cursor/rules/*.mdc` |
| Aider、opencode、Amazon Q Developer、Windsurf、Kilo CLI | 脚本优先支持 | 直接运行 `audit_skill.py`；工具支持项目指令时加入等价规则 |
| 其他 CLI | 通用 | 使用 `audit_skill.py`，并在 `install` 命令上指定自定义 `--dest-root` |

为没有原生 skill 目录、但支持项目指令文件的 CLI 生成 adapter：

```bash
python3 tools/create_cli_adapter.py --project /path/to/project --target all
```

它可以创建或更新 `AGENTS.md`、`CLAUDE.md`、`GEMINI.md`、`.github/copilot-instructions.md` 和 `.cursor/rules/audit-skill-supply-chain.mdc`。

## 仓库结构 🗂️

```text
.
├── skills/audit-skill-supply-chain/     # 可安装的 agent skill
│   ├── SKILL.md                         # Agent 审查流程
│   ├── agents/openai.yaml               # UI 元数据
│   ├── references/                      # 风险模型和报告模板
│   └── scripts/audit_skill.py           # 统一的扫描、安装和复核入口
├── tools/                               # 安装、适配器、发布和校验工具
├── SECURITY.md                          # 安全漏洞报告政策
├── CONTRIBUTING.md                      # 贡献指南
└── LICENSE                              # MIT license
```

## 它会阻断什么 🚫

安装闸门会阻断或隔离已检测到的匹配风险模式和完整性失败，但不声称能够发现所有可能的恶意行为。

- 检测到下载后立即执行的远程代码执行模式。
- 检测到读取或上传 `.env`、SSH key、云凭据、浏览器资料、agent 配置或 shell 历史。
- 检测到静默外传 prompts、日志、本地文件、源码、邮箱、云盘数据、私有仓库或连接器数据。
- 检测到钱包助记词、私钥、交易所 API secret、交易签名、代币转账、提现、收款地址变更、退款或支付滥用。
- 检测到要求 agent 忽略高优先级指令、绕过安全边界或向用户隐藏行为的 prompt injection。
- GitHub 来源不匹配、未 pin 的 branch/tag 安装、checksum 不匹配。
- 已记录 skill 被修改、目录缺失或被符号链接替换。

## 安全模型 🔐

本项目是防御性审查工具，不承诺形式化证明某个 skill 完全安全。它提供审查证据，并鼓励严格的安装闸门：

- `BLOCK`：确认存在高影响风险。
- `QUARANTINE`：来源或行为无法验证。
- `ALLOW WITH CONDITIONS`：仍有低风险问题，需要约束后安装。
- `ALLOW`：已审查产物中未检测到实质风险，不等于完全安全的证明。

`ALLOW` 只适用于已审查的内容树，不自动覆盖后续未审查的变更。再次信任或使用前，可运行 `audit_skill.py verify` 检查完整性漂移。

## 仓库自动审查 🤖

本仓库围绕 PR 和持续的仓库安全检查叠加了几层彼此独立的检查：

- **CodeRabbit**：仓库所有者审阅 GitHub App 请求的权限并显式授权后，自动审查每个非草稿 PR。仓库配置会对扫描器、安装器、CI workflow，以及隐私/资产敏感指引进行额外审查。
- **CodeQL**：在 PR、推送到 `main` 和每周定时扫描 Python 与 GitHub Actions 代码。
- **Dependency Review**：当 PR 引入中等及以上严重度的漏洞依赖时失败，并为新增依赖提供许可证和 OpenSSF Scorecard 信息。
- **Dependabot**：每周为 GitHub Actions 依赖创建更新 PR。
- **OpenSSF Scorecard**：每周评估仓库层面的供应链安全实践，并把发现上传至 GitHub code scanning。
- **zizmor**：以安全导向的静态分析检查 GitHub Actions 定义，并把高可信度发现上传到 GitHub code scanning。

这些服务提供审查证据，不是安全保证，也不会自动合并。CodeRabbit 需要第三方 GitHub App 对代码、提交状态、Issue 和 PR 的权限；仓库所有者必须先审阅这些权限并显式批准安装。随后请选择 **Only select repositories**，并且只授权当前仓库。接入步骤见 [CodeRabbit GitHub 集成指南](https://docs.coderabbit.ai/platforms/github-com)。

## License

MIT.
