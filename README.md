# IaC Scanner

Python CLI that scans Terraform and AWS CDK Infrastructure-as-Code, then produces a **report** and **fixed code**. Built with a **factory pattern** (scanner per IaC type) and **LangChain** orchestration where **each task uses a different AI** (analysis vs code generation).

**License:** [Personal Use License](LICENSE) — personal use permitted; redistribution (including publishing or selling) requires permission. Contributing back via pull request is welcome.

## Input (CLI)

- **Terraform**: path to a directory containing `main.tf`, or path to `main.tf` itself.
- **CDK**: path to a directory containing `index.ts` or `index.js`, or path to that file.

## Process

1. **Factory** creates the right scanner (`TerraformScanner` or `CdkScanner`) from the given path.
2. **Scan**: load entry file(s) and gather content.
3. **Analysis task** (LangChain + **analysis AI**): security and best-practice findings.
4. **Fix task** (LangChain + **fix AI**): generate corrected code from findings.
5. **Output**: report (JSON) and fixed TF/CDK code under an output directory.

## Output

- **Report**: `scan-report.json` with `iac_type`, `entry_path`, `findings`, and metadata.
- **Fixed code**: under `fixed/` (same structure as detected files when the model returns multi-file blocks).

## Install

```bash
cd iac-scanner
pip install -e .
# or
pip install -r requirements.txt
```

## Usage

```bash
# Scan Terraform (directory with main.tf or path to main.tf)
iac-scan scan ./my-tf-dir
iac-scan scan ./my-tf-dir/main.tf

# Scan CDK (directory with index.ts or path to index.ts)
iac-scan scan ./my-cdk-app
iac-scan scan ./my-cdk-app/index.ts

# Custom output directory and report name
iac-scan scan ./my-tf-dir -o ./reports --report-name report.json

# Only report, no fix step
iac-scan scan ./my-tf-dir --no-fix

# Scan only (no AI), for testing without API keys
iac-scan scan ./my-tf-dir --scan-only

# Choose AI per task (analysis vs fix)
iac-scan scan ./my-tf-dir --analysis-ai openai --fix-ai anthropic
```

## Environment (different AI per task)

- **Analysis task**: `IAC_ANALYSIS_AI=openai` (default) or `anthropic`; `IAC_ANALYSIS_MODEL` for model name. Uses `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`.
- **Fix task**: `IAC_FIX_AI=openai` (default) or `anthropic`; `IAC_FIX_MODEL` for model name.

Example:

```bash
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...
iac-scan scan ./tf -o ./out
```

## Contributing

Contribution guidelines, development setup, and release process are in **[CONTRIBUTING.md](CONTRIBUTING.md)** (in the source repository). If you installed from PyPI, open the project repo to see that file.

## Project layout (factory + orchestration)

```
src/iac_scanner/
  cli.py              # CLI entry (click)
  factory.py          # create_scanner(path) -> TerraformScanner | CdkScanner
  scanners/
    base.py           # IacScanner (abstract), ScanResult
    terraform.py      # TerraformScanner (main.tf)
    cdk.py            # CdkScanner (index.ts / index.js)
  orchestration/
    tasks.py          # analysis_chain() / fix_chain() — different LLM per task
    runner.py         # run_pipeline(scanner) -> PipelineResult
  output/
    report.py         # write_report_and_fixes()
```
