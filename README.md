# IaC Scanner

[![PyPI version](https://img.shields.io/pypi/v/iac-scanner)](https://pypi.org/project/iac-scanner/)
[![CI](https://github.com/alphacrack/iac-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/alphacrack/iac-scanner/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Python CLI that scans Terraform and AWS CDK Infrastructure-as-Code, reports security + best-practice findings, and **writes the fix**. Runs locally, keylessly, or grounded by Checkov.

iac-scanner **complements** rule-based scanners like Checkov, tfsec, and KICS — it doesn't replace them. Its differentiator is **AI-generated fixes** alongside findings, and keyless operation via GitHub Models, Ollama, or an MCP server.

> **AI-generated output — review before applying.** Fixed code is written to `scan-output/fixed/` and must be human-reviewed before overwriting your working tree. No auto-apply.

**License:** [Apache License 2.0](LICENSE).

## Quickstart (30 seconds, no cost)

Pick whichever path matches your setup:

### GitHub Models (free for any GitHub user)

```bash
pip install iac-scanner
export GITHUB_TOKEN=$(gh auth token)
iac-scan scan ./my-tf --provider github -o ./out
```

### Ollama (fully local, offline, free)

```bash
pip install iac-scanner[local]
ollama pull qwen2.5-coder:7b-instruct  # first run only
iac-scan scan ./my-tf --provider ollama -o ./out
```

### MCP server — drive from Claude Desktop / Cursor

```bash
pip install iac-scanner[mcp]
# Add to ~/Library/Application Support/Claude/claude_desktop_config.json:
#   "mcpServers": { "iac-scanner": { "command": "iac-scan-mcp" } }
# Then in Claude: "Scan the Terraform in ~/work/infra"
```

### OpenAI / Anthropic (bring your own key)

```bash
pip install iac-scanner
export OPENAI_API_KEY=sk-...
iac-scan scan ./my-tf --provider openai -o ./out
# or:  iac-scan scan ./my-tf --provider auto  (picks ollama → github → openai → anthropic)
```

### No-network demo (no AI, just parse)

```bash
iac-scan scan ./samples/tf -o ./out --scan-only
```

Every mode writes `scan-report.json` (findings) and, when AI is enabled, `fixed/` (corrected code).

## Input (CLI)

- **Terraform**: a directory containing `main.tf`, or the path to `main.tf` itself. Sibling `.tf` files are included.
- **CDK**: a directory containing `index.ts`/`index.js`, or the path to that file. `lib/` and `bin/` subdirectories are included.

### What we skip (automatic)

`terraform.tfstate*`, `*.tfvars`, `.env*`, `*.pem`, `*.key`, `id_rsa*`, `.terraform/`, `node_modules/`, `cdk.out/`. See [SECURITY.md](SECURITY.md) for the full skip-list and threat model.

## Process

1. **Factory** creates the right scanner (`TerraformScanner` or `CdkScanner`) from the given path.
2. **Scan**: load entry file(s), apply the skip-list, redact obvious secrets, enforce the 200 KB input cap.
3. *(Optional)* **Rule engine pre-pass** (`--rules-engine=checkov`) adds framework-mapped findings with CWE/CIS/NIST tags.
4. **Analysis** (LLM, structured output): findings as a Pydantic-validated JSON array with severity + location.
5. **Fix** (LLM, text output): regenerates corrected code with a mandatory `AI-generated — review before applying` banner.
6. **Output**: JSON and/or SARIF 2.1.0 report; fixed files under `fixed/`.

## Output

- **JSON report** (`scan-report.json`): `iac_type`, `entry_path`, `findings`, `metadata`, `provider`, `analysis_model`, `fix_model`, `prompt_version`.
- **SARIF 2.1.0** (`--format sarif|both`): consumed by GitHub Code Scanning, GitLab Security Dashboards, SonarQube.
- **Fixed code** (`fixed/`): multi-file output preserves the original layout; each file starts with the AI-generated banner.

## Usage

```bash
# Basic scan (analysis + fix)
iac-scan scan ./my-tf-dir

# No-AI parse only (no keys needed)
iac-scan scan ./my-tf-dir --scan-only

# Findings only, skip fix generation
iac-scan scan ./my-tf-dir --no-fix

# Output SARIF for GitHub Code Scanning
iac-scan scan ./my-tf-dir --format sarif -o ./out

# Or both at once
iac-scan scan ./my-tf-dir --format both -o ./out

# Choose a provider explicitly
iac-scan scan ./my-tf-dir --provider github
iac-scan scan ./my-tf-dir --provider ollama
iac-scan scan ./my-tf-dir --provider openai

# Ground the LLM with Checkov rule findings (hybrid mode)
pip install iac-scanner[rules]
iac-scan scan ./my-tf-dir --rules-engine checkov

# CI gate: exit non-zero on any HIGH or CRITICAL finding
iac-scan scan ./my-tf-dir --fail-on high

# Cost cap: abort if projected LLM cost exceeds $0.50
iac-scan scan ./my-tf-dir --max-spend 0.50

# Force-refresh: skip the response cache for this run
iac-scan scan ./my-tf-dir --no-cache
```

## Environment variables

| Variable              | Purpose                                                                                   |
|-----------------------|-------------------------------------------------------------------------------------------|
| `IAC_PROVIDER`        | `openai` \| `anthropic` \| `github` \| `ollama` (overrides auto-detect).                  |
| `OPENAI_API_KEY`      | Required when `--provider=openai`.                                                        |
| `ANTHROPIC_API_KEY`   | Required when `--provider=anthropic`.                                                     |
| `GITHUB_TOKEN`        | Required when `--provider=github`. Any `gh auth` token works (free tier).                 |
| `OLLAMA_HOST`         | Ollama endpoint. Default: `http://localhost:11434`.                                       |
| `IAC_ANALYSIS_MODEL`  | Override analysis model (e.g. `gpt-4o`, `claude-3-5-sonnet-20241022`).                    |
| `IAC_FIX_MODEL`       | Override fix model.                                                                       |
| `IAC_MAX_SPEND_USD`   | Hard dollar cap per run. Abort if projected cost exceeds it.                              |
| `IAC_MAX_INPUT_BYTES` | Input size cap (default 200 KB, floored to 1 KB, ceilinged to 10 MB).                     |
| `IAC_NO_CACHE`        | When set, skip the content-addressed response cache.                                      |
| `IAC_NO_REDACT`       | Disable secret redaction (not recommended — see SECURITY.md).                             |
| `IAC_CACHE_DIR`       | Override cache directory (default `~/.cache/iac-scanner/`).                               |
| `IAC_OUTPUT_FORMAT`   | Default output format (`json` \| `sarif` \| `both`).                                      |

## Install

```bash
# Base install — includes OpenAI and Anthropic providers + GitHub Models
pip install iac-scanner

# With optional extras
pip install iac-scanner[local]    # Ollama local-LLM provider
pip install iac-scanner[mcp]      # MCP server mode for Claude Desktop / Cursor
pip install iac-scanner[rules]    # Checkov hybrid mode
pip install iac-scanner[all]      # all of the above

# From source
git clone https://github.com/alphacrack/iac-scanner
cd iac-scanner
pip install -e ".[dev]"
```

## Blog and tutorial

Articles and a step-by-step tutorial are published on **GitHub Pages** at `https://alphacrack.github.io/iac-scanner/`. Source lives under [docs/](docs/).

## Contributing

See **[CONTRIBUTING.md](CONTRIBUTING.md)** for development setup, test strategy, and the release process (Trusted Publishing + SBOM + Sigstore signing).

## Security

See **[SECURITY.md](SECURITY.md)** for the threat model (prompt injection, secret exposure, hallucinated fixes, supply-chain, cost abuse) and private disclosure channel.

## Project layout

```
src/iac_scanner/
  cli.py                # CLI entry (click)
  factory.py            # create_scanner(path) → TerraformScanner | CdkScanner
  models.py             # Pydantic: Finding, FindingsList, ScanReport, VerificationResult
  cache.py              # content-addressed SHA-256 response cache
  cost.py               # tiktoken preflight + IAC_MAX_SPEND_USD enforcement
  mcp_server.py         # iac-scan-mcp entry — MCP server for host LLMs
  scanners/
    base.py             # IacScanner (abstract), ScanResult
    _filters.py         # skip-list, secret redaction, input size cap
    terraform.py        # TerraformScanner (main.tf)
    cdk.py              # CdkScanner (index.ts / index.js)
  llm/
    providers.py        # LLMClient + OpenAI / Anthropic / GitHub Models / Ollama
  orchestration/
    tasks.py            # analysis + fix LangChain tasks (structured output, XML fencing)
    runner.py           # run_pipeline: scan → cache → cost check → LLM → result
    hybrid.py           # rule-pre-pass + LLM augment + dedupe
  rules/
    engine.py           # rule-engine dispatcher
    checkov.py          # Checkov subprocess adapter with CWE/CIS/NIST mapping
  output/
    report.py           # write_report_and_fixes — JSON + fixed/ banner
    sarif.py            # SARIF 2.1.0 emitter
```
