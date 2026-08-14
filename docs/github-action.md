# GitHub Action security gate

The root `action.yml` turns Audit Skill Supply Chain into a reusable composite GitHub Action. It scans a checked-out agent skill as data, verifies the repository and commit when GitHub metadata is available, and writes both JSON and SARIF reports without executing target files.

## Minimal workflow

Pin this action to a reviewed full commit SHA. Replace `path/to/skill` and `<AUDIT_ACTION_COMMIT_SHA>` before use.

```yaml
name: Audit agent skill

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0
        with:
          persist-credentials: false

      - name: Audit agent skill
        id: skill-audit
        uses: FeeeeelixWong/audit-skill-supply-chain@<AUDIT_ACTION_COMMIT_SHA>
        with:
          target: path/to/skill
          fail-on: quarantine

      - name: Upload SARIF to GitHub code scanning
        if: ${{ always() && steps.skill-audit.outputs.sarif != '' && github.event.pull_request.head.repo.fork != true }}
        uses: github/codeql-action/upload-sarif@54f647b7e1bb85c95cddabcd46b0c578ec92bc1a # v4.36.3
        with:
          sarif_file: ${{ steps.skill-audit.outputs.sarif }}
```

GitHub does not grant `security-events: write` to workflows from untrusted forks. The example keeps the audit gate but skips SARIF upload for those pull requests. The JSON and SARIF files are written under `RUNNER_TEMP` by default, away from untrusted repository-controlled paths.

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `target` | `.` | Skill directory to scan. Relative paths start at `GITHUB_WORKSPACE`. |
| `source-url` | Current GitHub repository | Approved canonical source URL. |
| `expected-commit` | `GITHUB_SHA` | Approved full commit SHA. |
| `json-output` | Private runner temp path | Optional JSON output path. |
| `sarif-output` | Private runner temp path | Optional SARIF output path. |
| `fail-on` | `quarantine` | `block`, `quarantine`, `conditions`, or `never`. |

The Action exposes `gate`, `json`, and `sarif` outputs. `fail-on: quarantine` fails on `BLOCK` or `QUARANTINE`; `conditions` also fails on `ALLOW WITH CONDITIONS`; `never` produces evidence without enforcing a gate.

## Security boundary

- The Action runs only this repository's scanner, never scripts from the target.
- Python starts in isolated mode so target-controlled `PYTHONPATH` and user site packages cannot replace scanner imports.
- Provenance defaults bind the scan to the current GitHub repository and `GITHUB_SHA`.
- Reports are atomically written with private file permissions and reject a symlink as the final destination.
- CI logs contain only the gate summary and finding locations; detailed evidence stays in the private JSON and SARIF reports.
- SARIF uses repository-relative artifact locations and excludes the scanner host's absolute target path.
- An `ALLOW` remains a static review result for one commit, not proof that the skill is harmless.

## GitHub Action 安全闸门

仓库根目录的 `action.yml` 可直接作为复用型 GitHub Action。它会把已 checkout 的 agent skill 当作数据扫描，在可用时校验 GitHub 仓库与 commit，并生成 JSON 与 SARIF；整个过程不会执行目标 skill 的脚本。

接入时应把 Action 固定到已审查的完整 commit SHA，并把 `target` 改为实际 skill 目录。默认 `fail-on: quarantine` 会在结果为 `BLOCK` 或 `QUARANTINE` 时让任务失败；使用 `conditions` 时，`ALLOW WITH CONDITIONS` 也会失败。默认报告写入 `RUNNER_TEMP`，避免把报告写进未信任仓库可控制的路径。

SARIF 可上传到 GitHub code scanning，在 PR 的 Security 结果中直接显示文件与行号。来自外部 fork 的工作流通常没有 `security-events: write` 权限，此时应保留扫描步骤，并按仓库策略跳过 SARIF 上传。
