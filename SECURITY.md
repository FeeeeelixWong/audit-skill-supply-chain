# Security Policy / 安全政策

## English

This project is a defensive security review skill. Please report vulnerabilities responsibly.

Do not include secrets, private keys, seed phrases, production tokens, customer data, or exploit payloads that can harm third parties in a public issue.

Preferred reporting path:

1. Open a [private GitHub Security Advisory](https://github.com/FeeeeelixWong/audit-skill-supply-chain/security/advisories/new).
2. If private advisories are unavailable, open a minimal public issue that says a security report is needed, without sensitive details.
3. Include affected version, scanner output, reproduction steps using safe fixtures, and expected behavior.

Security-sensitive examples:

- False negatives for credential theft, data exfiltration, wallet/private-key access, payment abuse, or prompt injection.
- Provenance bypasses where a mismatched GitHub repo, commit, or checksum is not detected.
- Scanner behavior that executes target skill code.

## 中文

本项目是防御性安全审查 skill。请负责任地报告漏洞。

不要在公开 issue 中包含密钥、私钥、助记词、生产 token、客户数据，或可能伤害第三方的利用载荷。

推荐报告方式：

1. 创建 [GitHub 私有 Security Advisory](https://github.com/FeeeeelixWong/audit-skill-supply-chain/security/advisories/new)。
2. 如果没有私有 advisory，只创建一个最小公开 issue，说明需要提交安全报告，不放敏感细节。
3. 请包含受影响版本、扫描器输出、使用安全 fixture 的复现步骤，以及期望行为。

安全敏感问题示例：

- 对凭据盗取、数据外传、钱包/私钥访问、支付滥用或 prompt injection 的漏报。
- GitHub repo、commit 或 checksum 不匹配却未被检测到的 provenance 绕过。
- 扫描器执行了目标 skill 代码。
