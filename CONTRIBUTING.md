# Contributing / 贡献指南

## English

Thanks for helping improve skill supply-chain safety.

Good contributions include:

- New detection patterns for privacy leakage, credential theft, wallet risk, payment risk, prompt injection, or provenance bypasses.
- Lower-noise rules that reduce false positives without hiding real risk.
- Safe test fixtures that do not contain real secrets.
- Better bilingual documentation.

Rules for contributions:

- Do not add real credentials, API keys, wallet seeds, private keys, customer data, or production URLs.
- Do not make the scanner execute code from the target skill.
- Keep the installable skill focused. Put GitHub project documentation at the repository root, not inside `skills/audit-skill-supply-chain/`.
- Treat automated review comments as evidence to investigate, not approval to merge. For changes that affect scanning, installation, provenance, CI permissions, wallets, payments, credentials, or private data, include the risk analysis and regression evidence in the pull request.
- Run validation before submitting:

```bash
python3 tools/validate_skill.py
python3 -m py_compile skills/audit-skill-supply-chain/scripts/*.py
python3 tools/install_skill.py --target all --dry-run
python3 tools/create_cli_adapter.py --target all --dry-run
```

## 中文

感谢你帮助提升 agent skill 供应链安全。

适合贡献的内容包括：

- 新增隐私泄漏、凭据盗取、钱包风险、支付风险、prompt injection 或 provenance 绕过检测规则。
- 降低误报但不隐藏真实风险的规则优化。
- 不包含真实密钥的安全测试 fixture。
- 更好的中英双语文档。

贡献规则：

- 不要提交真实凭据、API key、钱包助记词、私钥、客户数据或生产 URL。
- 不要让扫描器执行目标 skill 的代码。
- 保持可安装 skill 本体精简。GitHub 项目说明放在仓库根目录，不放进 `skills/audit-skill-supply-chain/`。
- 自动审查评论是需要调查的证据，不是可以直接合并的批准。涉及扫描、安装、来源验证、CI 权限、钱包、支付、凭据或私有数据的改动，必须在 PR 中写明风险分析和回归验证证据。
- 提交前运行校验：

```bash
python3 tools/validate_skill.py
python3 -m py_compile skills/audit-skill-supply-chain/scripts/*.py
python3 tools/install_skill.py --target all --dry-run
python3 tools/create_cli_adapter.py --target all --dry-run
```
