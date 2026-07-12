# Audit Skill Supply Chain

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Codex Skill](https://img.shields.io/badge/Codex-Skill-blue.svg)](skills/audit-skill-supply-chain/SKILL.md)
[![Focus: Supply Chain Security](https://img.shields.io/badge/focus-supply--chain_security-red.svg)](skills/audit-skill-supply-chain/references/risk-model.md)

**English** | [中文](#中文)

A pre-install security gate for open-source agent skills.

Agent skills are not just documentation. They can become operating instructions for an agent with filesystem, shell, network, connector, wallet, payment, or repository access. This project helps review a third-party skill before it is installed, with a strong focus on preventing privacy leakage, credential theft, supply-chain substitution, and asset loss.

## Highlights

- **Pre-install by default**: review skills in quarantine before copying them into a live skill directory.
- **Provenance-aware**: check GitHub owner/repo, full commit pinning, release artifacts, and SHA256 checksums.
- **Privacy-first**: flag access to local files, secrets, browser data, email, cloud drives, private repositories, and connector data.
- **Asset-loss focused**: block wallet seed/private-key handling, signing flows, transfers, withdrawals, payout changes, refunds, and payment-provider abuse.
- **Agent-injection aware**: detect prompt-injection language that tries to override user, system, or safety instructions.
- **No target execution**: the scanner treats the target skill as data and never runs its bundled scripts.

## Quick Start

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

## Install This Skill

Clone the repository, then copy only the skill directory into your Codex skills folder:

```bash
mkdir -p ~/.codex/skills
cp -R skills/audit-skill-supply-chain ~/.codex/skills/
```

Use the skill by asking Codex:

```text
Use $audit-skill-supply-chain to review this open-source skill before installing it.
```

## Review Workflow

1. **Acquire in quarantine**: clone or extract into a temporary review directory, not a live skill path.
2. **Verify provenance**: require a full commit SHA or a verified release checksum.
3. **Run static scanning**: inspect manifests, scripts, references, assets, symlinks, hidden files, URLs, and high-risk phrases.
4. **Review privacy and money flows**: check whether the skill can access private data, credentials, wallets, payment systems, or production systems.
5. **Decide the install gate**: return `BLOCK`, `QUARANTINE`, `ALLOW WITH CONDITIONS`, or `ALLOW`.
6. **Promote exact artifact only**: if allowed, copy the exact reviewed skill into the live install path.

## Repository Layout

```text
.
├── skills/audit-skill-supply-chain/     # Installable Codex skill
│   ├── SKILL.md                         # Agent workflow
│   ├── agents/openai.yaml               # UI metadata
│   ├── references/                      # Risk model and report templates
│   └── scripts/scan_skill.py            # Read-only static scanner
├── tools/                               # Release and validation helpers
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

## 中文

一个用于开源 agent skill 安装前安全审查的闸门。

Agent skill 不只是普通文档。它可能会成为 agent 的操作说明，而 agent 可能拥有文件系统、Shell、网络、连接器、钱包、支付或代码仓库权限。本项目用于在安装第三方 skill 之前进行审查，重点防止隐私泄漏、凭据盗取、供应链替换和财产损失。

## 项目亮点

- **默认安装前审查**：先在隔离目录中审查，再决定是否复制到真实 skill 目录。
- **来源可信度检查**：检查 GitHub owner/repo、完整 commit pin、release artifact 和 SHA256 checksum。
- **隐私优先**：标记本地文件、密钥、浏览器数据、邮箱、云盘、私有仓库和连接器数据访问风险。
- **防财产损失**：阻断钱包助记词/私钥处理、签名流程、转账、提现、收款地址变更、退款和支付服务滥用。
- **识别 prompt injection**：检测试图覆盖用户、系统或安全指令的恶意提示词。
- **不执行目标代码**：扫描器把目标 skill 当成数据处理，不运行目标 skill 自带脚本。

## 快速开始

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

## 安装这个 Skill

克隆仓库后，只复制真正的 skill 目录到 Codex skills 目录：

```bash
mkdir -p ~/.codex/skills
cp -R skills/audit-skill-supply-chain ~/.codex/skills/
```

在 Codex 中这样调用：

```text
Use $audit-skill-supply-chain to review this open-source skill before installing it.
```

## 审查流程

1. **隔离获取**：克隆或解压到临时审查目录，不直接放入真实 skill 路径。
2. **验证来源**：要求完整 commit SHA 或已验证 release checksum。
3. **运行静态扫描**：检查 manifest、脚本、参考文件、资产、符号链接、隐藏文件、URL 和高风险语句。
4. **审查隐私和资金路径**：确认 skill 是否能访问私有数据、凭据、钱包、支付系统或生产系统。
5. **给出安装闸门结论**：返回 `BLOCK`、`QUARANTINE`、`ALLOW WITH CONDITIONS` 或 `ALLOW`。
6. **只提升已审查产物**：如果允许安装，只复制已经审查过的同一份 skill。

## 仓库结构

```text
.
├── skills/audit-skill-supply-chain/     # 可安装的 Codex skill
│   ├── SKILL.md                         # Agent 审查流程
│   ├── agents/openai.yaml               # UI 元数据
│   ├── references/                      # 风险模型和报告模板
│   └── scripts/scan_skill.py            # 只读静态扫描器
├── tools/                               # 发布和校验工具
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

## License

MIT.
