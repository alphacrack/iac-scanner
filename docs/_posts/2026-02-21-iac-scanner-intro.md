---
layout: default
title: "Introducing IaC Scanner"
date: 2026-02-21
categories: blog
---

# Introducing IaC Scanner

IaC Scanner is a Python CLI that scans **Terraform** and **AWS CDK** Infrastructure-as-Code, produces a **report** of security and best-practice findings, and outputs **fixed code** that you can drop into your project.

## What it does

- **Input:** Point the CLI at a directory (or file) containing Terraform (`main.tf`) or CDK (`index.ts` / `index.js`).
- **Process:** A factory picks the right scanner, loads your IaC, then two AI steps run: one for **analysis** (findings as JSON) and one for **fixes** (corrected code).
- **Output:** A `scan-report.json` and a `fixed/` directory with corrected Terraform or CDK files.

So you get both a readable report and suggested fixes in one run.

## Architecture in short

- **Factory pattern:** One entry point; the tool detects Terraform vs CDK and uses the right scanner (`TerraformScanner` or `CdkScanner`).
- **LangChain orchestration:** Two separate tasks, each with its own AI (so you can use different models for analysis vs code generation).
- **Dual AI:** Analysis uses one model (e.g. for structured findings); the fix step uses another (e.g. for code generation). Configure via `IAC_ANALYSIS_AI` / `IAC_FIX_AI` and the usual API keys.

## Quick usage

```bash
pip install iac-scanner
export OPENAI_API_KEY=sk-...
iac-scan scan ./my-tf-dir -o ./out
```

- **Report only (no fix):** `iac-scan scan ./my-tf-dir --no-fix`
- **No AI (scan files only):** `iac-scan scan ./my-tf-dir --scan-only`
- **Different providers:** `--analysis-ai openai --fix-ai anthropic` (with the right keys set)

See the [tutorial]({{ site.baseurl }}/tutorial) for a step-by-step guide.

## Links

- **PyPI:** [iac-scanner](https://pypi.org/project/iac-scanner/)
- **Source:** [GitHub](https://github.com/bishwasjha/iac-scanner)
- **License:** Personal use permitted; redistribution requires permission (see repo [LICENSE](https://github.com/bishwasjha/iac-scanner/blob/main/LICENSE)).
