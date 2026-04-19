---
layout: default
title: Keyless scanning
permalink: /keyless/
---

# Keyless scanning

Four ways to run iac-scanner **without bringing your own LLM API key.** Pick the one that matches your setup.

|                                  | Cost per scan | Network | Setup friction | Good for                              |
|----------------------------------|---------------|---------|----------------|----------------------------------------|
| **GitHub Models**                | $0 (free tier) | Yes    | 10 sec         | Anyone with a GitHub account          |
| **Ollama** (local)               | $0            | Offline | 2 min          | Privacy-sensitive repos, flights      |
| **MCP** (Claude Desktop, Cursor) | Uses host sub  | Yes    | 1 min config   | Interactive editor-driven workflows   |
| OpenAI / Anthropic direct        | Pay-per-token  | Yes    | API signup     | Production CI with budget control     |

## Why keyless matters

- **Cost control.** Platform teams rolling out to dozens of repos want scan cost ≈ $0.
- **Privacy.** Regulated data stays inside the enterprise perimeter when Ollama is used.
- **Simplicity.** New contributors don't need an OpenAI account to run the pre-commit hook.
- **Keyless CI.** GitHub Actions already sets `GITHUB_TOKEN` — zero additional secrets required.

## GitHub Models (recommended for most users)

GitHub Models gives every authenticated GitHub user a free-tier LLM quota. iac-scanner treats it as an OpenAI-compatible endpoint via `langchain-openai`.

```bash
pip install iac-scanner
export GITHUB_TOKEN=$(gh auth token)
iac-scan scan ./my-tf --provider github -o ./out
```

Inside GitHub Actions:

```yaml
- name: Scan IaC with iac-scanner
  env:
    IAC_PROVIDER: github
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  run: |
    pip install iac-scanner
    iac-scan scan . --format sarif -o ./scan-output --fail-on high

- name: Upload SARIF to Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ./scan-output/scan-report.sarif
```

Rate limits apply; see [GitHub Models docs](https://docs.github.com/en/github-models). For high-volume scans switch to Ollama or OpenAI.

## Ollama (local, offline, free)

Runs the LLM on your machine with no external network calls. Ideal for air-gapped envs or when you don't want any prompt to leave your laptop.

```bash
# One-time: install Ollama + pull a code-aware model
brew install ollama            # or curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5-coder:7b-instruct
ollama serve &                 # if not already running as a system service

# Install iac-scanner with the Ollama provider
pip install iac-scanner[local]

# Scan
iac-scan scan ./my-tf --provider ollama -o ./out
```

**Recommended models** (ranked by scan-quality observations):

| Model                          | Size  | Notes                                                          |
|--------------------------------|-------|----------------------------------------------------------------|
| `qwen2.5-coder:7b-instruct`    | ~5GB  | Default. Best fix-generation quality for the size.             |
| `qwen2.5-coder:14b-instruct`   | ~10GB | Noticeably better on complex CDK stacks; needs 16GB RAM.       |
| `deepseek-coder-v2:16b`        | ~10GB | Good at Terraform-specific remediation.                         |
| `llama3.1:8b-instruct-q4_K_M`  | ~5GB  | General-purpose fallback; weaker on IaC-specific idioms.       |

Override via `IAC_ANALYSIS_MODEL` / `IAC_FIX_MODEL`:

```bash
export IAC_ANALYSIS_MODEL="qwen2.5-coder:14b-instruct"
export IAC_FIX_MODEL="qwen2.5-coder:14b-instruct"
iac-scan scan ./my-tf --provider ollama
```

If you host Ollama on a different machine, point iac-scanner at it:

```bash
export OLLAMA_HOST="http://192.168.1.50:11434"
```

## MCP server (Claude Desktop, Cursor, Continue.dev)

When you already pay for Claude Pro, Cursor, or GitHub Copilot Business — don't re-pay. Let the host app drive iac-scanner via MCP; the host supplies the LLM.

```bash
pip install iac-scanner[mcp]
```

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "iac-scanner": {
      "command": "iac-scan-mcp"
    }
  }
}
```

Restart Claude Desktop. In chat:

> Scan the Terraform in `~/work/infra` and suggest a fix for anything critical.

Claude calls iac-scanner's `scan_iac_path` tool (and `run_rule_engine` if you have Checkov installed), then reasons over the returned code using its own subscription. iac-scanner itself never needs an API key in this mode.

The same config works in [Cursor](https://docs.cursor.com/context/mcp) and [Continue.dev](https://docs.continue.dev/customize/model-context-protocol).

## OpenAI / Anthropic direct (production CI)

Use when you need tight budget control, SLAs, or deterministic rate limits that the free tiers don't offer.

```bash
pip install iac-scanner
export OPENAI_API_KEY=sk-...
# or ANTHROPIC_API_KEY=sk-ant-...

iac-scan scan ./my-tf \
  --provider openai \
  --max-spend 0.25 \
  --fail-on high \
  --format sarif \
  -o ./out
```

The `--max-spend` guardrail aborts the run if `tiktoken` pre-flight estimates a projected cost above your cap.

## Auto-detect

`--provider auto` (the default) picks in this order, falling through to the next when the previous isn't available:

1. Whatever `IAC_PROVIDER` env var names (if set)
2. **Ollama**, if `OLLAMA_HOST` (or `http://localhost:11434`) responds
3. **GitHub Models**, if `GITHUB_TOKEN` / `GH_TOKEN` is set
4. **OpenAI**, if `OPENAI_API_KEY` is set
5. **Anthropic**, if `ANTHROPIC_API_KEY` is set
6. Otherwise, prints the full list of options and exits 1

So the shortest happy path is often simply:

```bash
gh auth login                          # or start ollama
pip install iac-scanner
iac-scan scan ./my-tf -o ./out         # auto-detect picks the first available
```

## Hybrid grounding with Checkov

Any of the four providers above can be paired with the Checkov rule-engine pre-pass to ground LLM findings in deterministic CIS / NIST / PCI-DSS tags:

```bash
pip install iac-scanner[rules]
iac-scan scan ./my-tf --provider github --rules-engine checkov
```

See [docs/checkov-hybrid.md](./checkov-hybrid.md) for details.

## See also

- [Tutorial](./tutorial.md) — step-by-step walkthrough
- [Blog](./blog.md) — release notes and deep-dives
- [Security model](https://github.com/alphacrack/iac-scanner/blob/development/SECURITY.md)
