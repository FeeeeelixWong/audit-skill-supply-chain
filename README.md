# Audit Skill Supply Chain

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Agent Skill](https://img.shields.io/badge/Agent-Skill-blue.svg)](skills/audit-skill-supply-chain/SKILL.md)
[![Focus: Supply Chain Security](https://img.shields.io/badge/focus-supply--chain_security-red.svg)](skills/audit-skill-supply-chain/references/risk-model.md)

**English** | [中文](#中文)

A pre-install security gate for open-source agent skills across Codex, Claude Code, and compatible CLI skill directories.

Agent skills are not just documentation. They can become operating instructions for an agent with filesystem, shell, network, connector, wallet, payment, or repository access. This project helps review a third-party skill before it is installed, with a strong focus on preventing privacy leakage, credential theft, supply-chain substitution, and asset loss.

It ships as a standard `SKILL.md` directory. The same installable skill works in Codex (`~/.codex/skills`) and Claude Code-style skill directories (`~/.claude/skills`). Codex-specific UI metadata lives in `agents/openai.yaml` and can be ignored by other CLIs.

## Highlights

- **Pre-install by default**: review skills in quarantine before copying them into a live skill directory.
- **First-run baseline**: scan the skills already installed on the machine after this auditor is installed.
- **Safe install wrapper**: make future skill installs go through scan-before-copy instead of direct installation.
- **Provenance-aware**: check GitHub owner/repo, full commit pinning, release artifacts, and SHA256 checksums.
- **Privacy-first**: flag access to local files, secrets, browser data, email, cloud drives, private repositories, and connector data.
- **Asset-loss focused**: block wallet seed/private-key handling, signing flows, transfers, withdrawals, payout changes, refunds, and payment-provider abuse.
- **Agent-injection aware**: detect prompt-injection language that tries to override user, system, or safety instructions.
- **No target execution**: the scanner treats the target skill as data and never runs its bundled scripts.

## Quick Start

Baseline-scan already installed skills:

```bash
python3 skills/audit-skill-supply-chain/scripts/scan_installed_skills.py \
  --report ~/.agent-skill-audit/installed-skills-baseline.md
```

Scan a local untrusted skill:

```bash
python3 skills/audit-skill-supply-chain/scripts/scan_skill.py /path/to/untrusted-skill
```

Scan a GitHub-sourced skill with provenance checks:

```bash
python3 skills/audit-skill-supply-chain/scripts/scan_skill.py /path/to/untrusted-skill \
  --source-url https://github.com/owner/repo \
  --expected-commit <40-character-commit-sha>
```

Verify a release archive before install:

```bash
python3 skills/audit-skill-supply-chain/scripts/scan_skill.py /path/to/extracted-skill \
  --artifact /path/to/release.zip \
  --expected-sha256 <sha256>
```

Safely install a quarantined skill only after it passes the gate:

```bash
python3 skills/audit-skill-supply-chain/scripts/safe_install_skill.py /path/to/quarantined-skill \
  --cli both \
  --source-url https://github.com/owner/repo \
  --expected-commit <40-character-commit-sha>
```

## Install This Skill

Clone the repository, then install into Codex, Claude Code, or both:

```bash
python3 tools/install_skill.py --target all --replace
```

Manual Codex install:

```bash
mkdir -p ~/.codex/skills
cp -R skills/audit-skill-supply-chain ~/.codex/skills/
```

Manual Claude Code install:

```bash
mkdir -p ~/.claude/skills
cp -R skills/audit-skill-supply-chain ~/.claude/skills/
```

Use the skill by asking your agent CLI:

```text
Use $audit-skill-supply-chain to review this open-source skill before installing it.
```

After installation, run the first baseline scan:

```bash
python3 ~/.codex/skills/audit-skill-supply-chain/scripts/scan_installed_skills.py \
  --report ~/.agent-skill-audit/installed-skills-baseline.md
```

## Review Workflow

1. **Acquire in quarantine**: clone or extract into a temporary review directory, not a live skill path.
2. **Verify provenance**: require a full commit SHA or a verified release checksum.
3. **Run static scanning**: inspect manifests, scripts, references, assets, symlinks, hidden files, URLs, and high-risk phrases.
4. **Review privacy and money flows**: check whether the skill can access private data, credentials, wallets, payment systems, or production systems.
5. **Decide the install gate**: return `BLOCK`, `QUARANTINE`, `ALLOW WITH CONDITIONS`, or `ALLOW`.
6. **Promote exact artifact only**: if allowed, copy the exact reviewed skill into the live install path.

The skill cannot magically intercept every external installer at the operating-system level. To enforce pre-install scanning, use `safe_install_skill.py` as the install path for new skills and ask Codex, Claude Code, or another compatible CLI to use `$audit-skill-supply-chain` whenever a new skill is being installed or updated.

## CLI Support

| Tool | Support level | Install / adapter |
| --- | --- | --- |
| Codex | Native `SKILL.md` directory | `~/.codex/skills/audit-skill-supply-chain` |
| Claude Code | Native `SKILL.md` directory | `~/.claude/skills/audit-skill-supply-chain` |
| Gemini CLI | Instruction adapter | Use the scanner scripts and add the policy to `GEMINI.md` |
| Qwen Code | Instruction adapter | Use the Gemini-style `GEMINI.md` adapter where supported |
| GitHub Copilot coding agent | Instruction adapter | Use `AGENTS.md` or `.github/copilot-instructions.md` |
| Cursor | Instruction adapter | Use `AGENTS.md` or `.cursor/rules/*.mdc` |
| Aider, opencode, Amazon Q Developer, Windsurf, Kilo CLI | Script-first support | Run the scanner scripts directly; add equivalent project instructions when the tool supports them |
| Any other CLI | Generic | Use `scan_skill.py`, `scan_installed_skills.py`, and `safe_install_skill.py` with a custom `--dest-root` |

Generate project-level adapters for CLIs that use instruction files instead of native skill directories:

```bash
python3 tools/create_cli_adapter.py --project /path/to/project --target all
```

This can create or update `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.github/copilot-instructions.md`, and `.cursor/rules/audit-skill-supply-chain.mdc`.

## Repository Layout

```text
.
├── skills/audit-skill-supply-chain/     # Installable agent skill
│   ├── SKILL.md                         # Agent workflow
│   ├── agents/openai.yaml               # UI metadata
│   ├── references/                      # Risk model and report templates
│   └── scripts/scan_skill.py            # Read-only static scanner
├── tools/                               # Install, adapter, release, and validation helpers
├── SECURITY.md                          # Vulnerability reporting policy
├── CONTRIBUTING.md                      # Contribution guide
└── LICENSE                              # MIT license
```

## What It Blocks

- Remote code execution patterns such as downloaded scripts executed immediately.
- Reads or uploads of `.env`, SSH keys, cloud credentials, browser profiles, agent configs, or shell history.
- Silent exfiltration of prompts, logs, local files, source code, email, cloud-drive data, private repositories, or connector data.
- Wallet seed phrases, private keys, exchange API secrets, transaction signing, token transfers, withdrawals, payout changes, refunds, or payment abuse.
- Prompt-injection language that tells the agent to ignore higher-priority instructions or hide behavior from the user.
- GitHub source mismatch, unpinned branch/tag installs, or checksum mismatch.

## Security Model

This project is a defensive review tool. It does not prove a skill is safe. It raises evidence for manual review and encourages a strict install gate:

- `BLOCK`: confirmed high-impact risk.
- `QUARANTINE`: provenance or behavior cannot be verified.
- `ALLOW WITH CONDITIONS`: low-risk issues remain and must be constrained.
- `ALLOW`: no material issue found in the reviewed artifact.

## Automated Repository Review

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

## 项目亮点

- **默认安装前审查**：先在隔离目录中审查，再决定是否复制到真实 skill 目录。
- **首次基线扫描**：安装本审查 skill 后，先扫描本机已安装的 skill。
- **安全安装入口**：后续安装新 skill 时先扫描再复制，避免直接安装。
- **来源可信度检查**：检查 GitHub owner/repo、完整 commit pin、release artifact 和 SHA256 checksum。
- **隐私优先**：标记本地文件、密钥、浏览器数据、邮箱、云盘、私有仓库和连接器数据访问风险。
- **防财产损失**：阻断钱包助记词/私钥处理、签名流程、转账、提现、收款地址变更、退款和支付服务滥用。
- **识别 prompt injection**：检测试图覆盖用户、系统或安全指令的恶意提示词。
- **不执行目标代码**：扫描器把目标 skill 当成数据处理，不运行目标 skill 自带脚本。

## 快速开始

扫描本机已安装 skill：

```bash
python3 skills/audit-skill-supply-chain/scripts/scan_installed_skills.py \
  --report ~/.agent-skill-audit/installed-skills-baseline.md
```

扫描本地未信任 skill：

```bash
python3 skills/audit-skill-supply-chain/scripts/scan_skill.py /path/to/untrusted-skill
```

扫描来自 GitHub 的 skill，并检查来源：

```bash
python3 skills/audit-skill-supply-chain/scripts/scan_skill.py /path/to/untrusted-skill \
  --source-url https://github.com/owner/repo \
  --expected-commit <40-character-commit-sha>
```

安装前校验 release 压缩包：

```bash
python3 skills/audit-skill-supply-chain/scripts/scan_skill.py /path/to/extracted-skill \
  --artifact /path/to/release.zip \
  --expected-sha256 <sha256>
```

只在候选 skill 通过闸门后安全安装：

```bash
python3 skills/audit-skill-supply-chain/scripts/safe_install_skill.py /path/to/quarantined-skill \
  --cli both \
  --source-url https://github.com/owner/repo \
  --expected-commit <40-character-commit-sha>
```

## 安装这个 Skill

克隆仓库后，可以安装到 Codex、Claude Code 或两者：

```bash
python3 tools/install_skill.py --target all --replace
```

手动安装到 Codex：

```bash
mkdir -p ~/.codex/skills
cp -R skills/audit-skill-supply-chain ~/.codex/skills/
```

手动安装到 Claude Code：

```bash
mkdir -p ~/.claude/skills
cp -R skills/audit-skill-supply-chain ~/.claude/skills/
```

在你的 agent CLI 中这样调用：

```text
Use $audit-skill-supply-chain to review this open-source skill before installing it.
```

安装后先跑一次本机基线扫描：

```bash
python3 ~/.codex/skills/audit-skill-supply-chain/scripts/scan_installed_skills.py \
  --report ~/.agent-skill-audit/installed-skills-baseline.md
```

## 审查流程

1. **隔离获取**：克隆或解压到临时审查目录，不直接放入真实 skill 路径。
2. **验证来源**：要求完整 commit SHA 或已验证 release checksum。
3. **运行静态扫描**：检查 manifest、脚本、参考文件、资产、符号链接、隐藏文件、URL 和高风险语句。
4. **审查隐私和资金路径**：确认 skill 是否能访问私有数据、凭据、钱包、支付系统或生产系统。
5. **给出安装闸门结论**：返回 `BLOCK`、`QUARANTINE`、`ALLOW WITH CONDITIONS` 或 `ALLOW`。
6. **只提升已审查产物**：如果允许安装，只复制已经审查过的同一份 skill。

这个 skill 不能在操作系统层面神奇拦截所有外部安装器。要强制安装前审查，请把 `safe_install_skill.py` 作为新 skill 的安装入口，并在安装或更新 skill 时要求 Codex、Claude Code 或其他兼容 CLI 使用 `$audit-skill-supply-chain`。

## CLI 支持

| 工具 | 支持级别 | 安装 / 适配方式 |
| --- | --- | --- |
| Codex | 原生 `SKILL.md` 目录 | `~/.codex/skills/audit-skill-supply-chain` |
| Claude Code | 原生 `SKILL.md` 目录 | `~/.claude/skills/audit-skill-supply-chain` |
| Gemini CLI | 指令适配 | 使用扫描脚本，并把策略加入 `GEMINI.md` |
| Qwen Code | 指令适配 | 在支持 Gemini 风格上下文时使用 `GEMINI.md` 适配 |
| GitHub Copilot coding agent | 指令适配 | 使用 `AGENTS.md` 或 `.github/copilot-instructions.md` |
| Cursor | 指令适配 | 使用 `AGENTS.md` 或 `.cursor/rules/*.mdc` |
| Aider、opencode、Amazon Q Developer、Windsurf、Kilo CLI | 脚本优先支持 | 直接运行扫描脚本；工具支持项目指令时加入等价规则 |
| 其他 CLI | 通用 | 使用 `scan_skill.py`、`scan_installed_skills.py`、`safe_install_skill.py` 和自定义 `--dest-root` |

为没有原生 skill 目录、但支持项目指令文件的 CLI 生成 adapter：

```bash
python3 tools/create_cli_adapter.py --project /path/to/project --target all
```

它可以创建或更新 `AGENTS.md`、`CLAUDE.md`、`GEMINI.md`、`.github/copilot-instructions.md` 和 `.cursor/rules/audit-skill-supply-chain.mdc`。

## 仓库结构

```text
.
├── skills/audit-skill-supply-chain/     # 可安装的 agent skill
│   ├── SKILL.md                         # Agent 审查流程
│   ├── agents/openai.yaml               # UI 元数据
│   ├── references/                      # 风险模型和报告模板
│   └── scripts/scan_skill.py            # 只读静态扫描器
├── tools/                               # 安装、适配器、发布和校验工具
├── SECURITY.md                          # 安全漏洞报告政策
├── CONTRIBUTING.md                      # 贡献指南
└── LICENSE                              # MIT license
```

## 它会阻断什么

- 下载后立即执行的远程代码执行模式。
- 读取或上传 `.env`、SSH key、云凭据、浏览器资料、agent 配置或 shell 历史。
- 静默外传 prompts、日志、本地文件、源码、邮箱、云盘数据、私有仓库或连接器数据。
- 钱包助记词、私钥、交易所 API secret、交易签名、代币转账、提现、收款地址变更、退款或支付滥用。
- 要求 agent 忽略高优先级指令、绕过安全边界或向用户隐藏行为的 prompt injection。
- GitHub 来源不匹配、未 pin 的 branch/tag 安装、checksum 不匹配。

## 安全模型

本项目是防御性审查工具，不承诺形式化证明某个 skill 完全安全。它提供审查证据，并鼓励严格的安装闸门：

- `BLOCK`：确认存在高影响风险。
- `QUARANTINE`：来源或行为无法验证。
- `ALLOW WITH CONDITIONS`：仍有低风险问题，需要约束后安装。
- `ALLOW`：已审查产物中未发现实质风险。

## 仓库自动审查

本仓库围绕 PR 和持续的仓库安全检查叠加了几层彼此独立的检查：

- **CodeRabbit**：仓库所有者审阅 GitHub App 请求的权限并显式授权后，自动审查每个非草稿 PR。仓库配置会对扫描器、安装器、CI workflow，以及隐私/财产敏感指引进行额外审查。
- **CodeQL**：在 PR、推送到 `main` 和每周定时扫描 Python 与 GitHub Actions 代码。
- **Dependency Review**：当 PR 引入中等及以上严重度的漏洞依赖时失败，并为新增依赖提供许可证和 OpenSSF Scorecard 信息。
- **Dependabot**：每周为 GitHub Actions 依赖创建更新 PR。
- **OpenSSF Scorecard**：每周评估仓库层面的供应链安全实践，并把发现上传至 GitHub code scanning。
- **zizmor**：以安全导向的静态分析检查 GitHub Actions 定义，并把高可信度发现上传到 GitHub code scanning。

这些服务提供审查证据，不是安全保证，也不会自动合并。CodeRabbit 需要第三方 GitHub App 对代码、提交状态、Issue 和 PR 的权限；仓库所有者必须先审阅这些权限并显式批准安装。随后请选择 **Only select repositories**，并且只授权当前仓库。接入步骤见 [CodeRabbit GitHub 集成指南](https://docs.coderabbit.ai/platforms/github-com)。

## License

MIT.
