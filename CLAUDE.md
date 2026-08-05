# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

`iac-scanner` is a Python CLI (`iac-scan`) and MCP server (`iac-scan-mcp`) that scans Terraform (`main.tf`) and AWS CDK (`index.ts`/`index.js`) IaC, then uses an LLM to both generate findings (structured output) and produce fixed code. It is **AI-augmented**, not rule-only — it complements Checkov/tfsec/KICS rather than replacing them. **Version is derived from git tags** (signed `vX.Y.Z`) by setuptools-scm; `pyproject.toml` has `dynamic = ["version"]` and no hardcoded version. The package reads the version from `_version.py` (written at build time) or falls back to `importlib.metadata`.

## Commands

```bash
# Setup
pip install -e ".[dev]"             # editable install + dev deps
pre-commit install                  # ruff + bandit + gitleaks + hygiene

# Test
pytest tests/ -m "not e2e"          # fast suite (mocked LLM, no keys)
pytest tests/ -m smoke              # CLI end-to-end smoke
pytest tests/ -m e2e                # opt-in: real provider APIs, needs keys
pytest tests/test_runner.py -v      # single file
pytest tests/test_runner.py::test_name  # single test
pytest tests/ --cov=iac_scanner     # coverage (CI threshold 80%, target 90%)

# Lint / type / security
ruff check src/ tests/              # lint
ruff format src/ tests/             # format
mypy src/iac_scanner                # CI hard-fails on any issue (strict mode)
bandit -r src/ -ll -c pyproject.toml
pip-audit

# Version + release (tag-driven, setuptools-scm)
make version                                # print version setuptools-scm would emit
make release-dry                            # preview a patch release
make release-patch | release-minor | release-major   # promote CHANGELOG + signed tag
# then: git push --follow-tags origin <branch>   # tag push → GitHub Release → PyPI publish
```

Make targets mirror most of the above (`make test`, `make lint`, `make check`, `make build`).

## Architecture

Data flows through five layers; each is isolated so a swap (e.g. LangChain → raw SDK) stays local.

1. **`factory.create_scanner(path)`** dispatches to a `TerraformScanner` or `CdkScanner` (both subclass `IacScanner` in `scanners/base.py`). The `can_handle` classmethod is what makes this a real factory — adding a new IaC type means a new scanner + factory entry, nothing else.
2. **Scanner.scan()** returns a `ScanResult` (Pydantic). `scanners/_filters.py` applies the skip-list (`*.tfvars`, `terraform.tfstate*`, `.env*`, keys, `node_modules/`, `.terraform/`, `cdk.out/`), secret redaction (AWS keys, RSA/EC privates, bearer/PAT patterns), and the input size cap (`IAC_MAX_INPUT_BYTES`, default 200 KB).
3. **Orchestration** (`orchestration/runner.py → run_pipeline`):
   - Builds `LLMClient`s up front so provider/model are known to the cache layer.
   - Calls `cost.estimate` per uncached call → `cost.enforce_budget` (raises `CostBudgetExceeded`).
   - Analysis: cache lookup → `run_analysis` (returns `FindingsList` via LangChain `with_structured_output`) → cache write.
   - Fix: cache lookup → `run_fix` (text, with mandatory AI-generated banner) → cache write.
4. **Hybrid pipeline** (`orchestration/hybrid.py`, triggered by `--rules-engine checkov`): runs Checkov first, dedupes against LLM findings by `rule_id` then `(title, location)`, then feeds the merged set to the fix step. **Rule findings are preserved**; LLM findings are appended only if not duplicates. Post-fix re-verification is a deferred v1.1 item.
5. **Output** (`output/report.py`, `output/sarif.py`): writes `scan-report.json` and/or SARIF 2.1.0, plus `fixed/` with the original layout preserved and every file prefixed by the AI-generated banner.

### LLM providers (`llm/providers.py`)

`LLMClient` is a thin dataclass over a LangChain `BaseChatModel`. Auto-detect order is `IAC_PROVIDER` env → `ollama` (if reachable) → `github` (token) → `openai` → `anthropic`. Default models live in `DEFAULT_MODELS[(provider, role)]` and can be overridden via `IAC_ANALYSIS_MODEL` / `IAC_FIX_MODEL`. GitHub Models uses `langchain-openai` against `https://models.inference.ai.azure.com` with `GITHUB_TOKEN` as the API key — no extra dep.

**LangChain is isolated to `llm/providers.py`** — orchestration code only calls `invoke_structured` / `invoke_text`. Dependabot is configured to ignore LangChain major-version bumps; those require a coordinated port, not a routine PR.

### Prompt-injection model

Two non-negotiable defenses, both in `orchestration/tasks.py`:

- Raw IaC is wrapped in `<user_iac>...</user_iac>` and the system prompt explicitly instructs the model to treat the contents as data, never as instructions.
- Analysis uses **Pydantic-validated structured output**, not free-form JSON parsing. Injection cannot change the output shape.

`PROMPT_VERSION` (currently `"2026-04-18.v1"`) is part of the cache key and is written to every report. **Bump it whenever prompt text changes** — stale cache entries with the old prompt are silently invalidated this way.

### Cache (`cache.py`)

Content-addressed (SHA-256 over `call_kind + raw_content + provider + model + prompt_version + schema_version + extra`). Default TTL 30 days. Lives under `IAC_CACHE_DIR` or `~/.cache/iac-scanner/` (XDG-respecting). Disabled per-run with `--no-cache` or `IAC_NO_CACHE=1`. `SCHEMA_VERSION` in `cache.py` invalidates everything when bumped — bump it on any on-disk format change.

## Conventions worth knowing

- **mypy is strict** (`disallow_untyped_defs`, `warn_unused_ignores`, etc.). CI hard-fails on any issue. Annotate fully.
- **`main` is the single trunk.** PRs target `main` (protected: required CI + review); there is no long-lived `development` branch. Sign off with `git commit -s` (DCO required).
- **Test markers** must be one of `smoke`, `integration`, `e2e` (declared in `pyproject.toml`; `--strict-markers` is on). `e2e` only runs in the nightly workflow.
- **Mocking the LLM**: use `FakeLLMClient` from `tests/conftest.py` and the `fake_analysis_client_*` / `fake_fix_client_*` fixtures. Do not hit real providers in unit tests. `isolate_cache_dir` and `clear_llm_env` fixtures are autouse, so tests get a clean cache + scrubbed env automatically.
- **Bandit** skips `B101` (assert in pytest) and `B310` (urlopen — guarded upstream). Don't broaden the skiplist without justification.
- **CHANGELOG.md** must be updated for any user-visible behavior change; `make bump-*` scaffolds the new section.
