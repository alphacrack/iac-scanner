---
layout: default
title: Tutorial
---

# IaC Scanner tutorial

Step-by-step: install, run a scan on Terraform and CDK, read the report, and use the fixed code.

---

## Prerequisites

- **Python 3.10+**
- For full scans (analysis + fix): an **API key** for at least one of:
  - OpenAI (`OPENAI_API_KEY`)
  - Anthropic (`ANTHROPIC_API_KEY`)
- For scan-only (no AI): no API key needed.

---

## Install

From PyPI:

```bash
pip install iac-scanner
```

From the repo (editable):

```bash
git clone https://github.com/bishwasjha/iac-scanner.git
cd iac-scanner
pip install -e .
```

Check:

```bash
iac-scan --version
```

---

## Scan Terraform

1. Use a directory that contains `main.tf` (or point at `main.tf` itself). The repo includes samples in `samples/tf/`.

2. Run a full scan (analysis + fix). Set your API key, then:

```bash
export OPENAI_API_KEY=sk-...
iac-scan scan ./samples/tf -o ./out
```

3. Output:
   - **`out/scan-report.json`** – findings and metadata.
   - **`out/fixed/main.tf`** (and other `.tf` files) – suggested fixed code.

4. **Report only (no fix):**

```bash
iac-scan scan ./samples/tf -o ./out --no-fix
```

5. **Scan only (no AI):** useful to confirm the tool sees your files:

```bash
iac-scan scan ./samples/tf -o ./out --scan-only
```

---

## Scan CDK

1. Use a directory that contains `index.ts` or `index.js` (e.g. `samples/cdk/`).

2. Full scan:

```bash
iac-scan scan ./samples/cdk -o ./out-cdk
```

3. Output:
   - **`out-cdk/scan-report.json`**
   - **`out-cdk/fixed/index.ts`**, **`out-cdk/fixed/lib/demo-stack.ts`** (or similar), depending on your layout.

Same options apply: `--no-fix`, `--scan-only`, `-o`, etc.

---

## Options

| Option | Description |
|--------|-------------|
| `-o, --output-dir` | Directory for report and `fixed/` (default: `<path>/scan-output`) |
| `--report-name` | Report filename (default: `scan-report.json`) |
| `--no-fix` | Only produce the report; do not run the fix step |
| `--scan-only` | Only scan files and write report; no AI (no API key needed) |
| `--analysis-ai` | `openai` or `anthropic` for the analysis step |
| `--fix-ai` | `openai` or `anthropic` for the fix step |

Environment: `IAC_ANALYSIS_AI`, `IAC_FIX_AI`, `IAC_ANALYSIS_MODEL`, `IAC_FIX_MODEL`, plus `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`.

---

## Reading the report

Open `scan-report.json`. Important fields:

- **`iac_type`** – `"terraform"` or `"cdk"`.
- **`entry_path`** – entry file that was scanned.
- **`findings`** – list of issues. Each has:
  - **`severity`** – e.g. `high`, `medium`, `low`.
  - **`title`** – short name.
  - **`description`** – what’s wrong.
  - **`location`** – file or snippet reference.
- **`metadata.files`** – list of files included in the scan.

Use this to decide which fixes to apply.

---

## Using the fixed code

- Fixed files are under **`<output-dir>/fixed/`**, mirroring your layout (e.g. `main.tf`, `index.ts`, `lib/demo-stack.ts`).
- **Do not** overwrite your repo blindly. Review the diff, then copy or merge the changes you want.
- Re-run the scanner after changing your IaC to get a fresh report and new suggestions.

---

## What’s new (versions)

New posts and version highlights are published on the [blog]({{ site.baseurl }}/blog). Maintainers add “What’s new in vX.Y.Z” when releasing; the [Blog release workflow](https://github.com/bishwasjha/iac-scanner/actions) (manual) can create a new post and update this section.
