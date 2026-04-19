# iac-scanner-cdk-nag

[![PyPI version](https://img.shields.io/pypi/v/iac-scanner-cdk-nag)](https://pypi.org/project/iac-scanner-cdk-nag/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](../../LICENSE)

[cdk-nag](https://github.com/cdklabs/cdk-nag) rule-engine adapter for [iac-scanner](https://github.com/alphacrack/iac-scanner).

Shells out to `cdk synth` against your CDK app, parses the AwsSolutions / HIPAA / NIST-800-53 / PCI-DSS nag annotations, and returns them as iac-scanner `Finding` objects with CWE and framework tags preserved. Pairs with iac-scanner's LLM augment + fix-generation pipeline.

## Why a separate package?

- Keeps the iac-scanner core **pure-Python** — no implicit Node runtime dependency.
- Lets cdk-nag evolve independently from the core; we pin narrowly to avoid sudden breakage.
- Discovered by iac-scanner core via Python entry points — `pip install iac-scanner-cdk-nag` and it just works.

## Install

```bash
# Prerequisite: Node.js 18+ and aws-cdk available on PATH (`npm i -g aws-cdk`).
# Your CDK app must have cdk-nag aspects applied, e.g.:
#   import { AwsSolutionsChecks } from "cdk-nag";
#   Aspects.of(app).add(new AwsSolutionsChecks());
pip install iac-scanner iac-scanner-cdk-nag
```

## Usage

Once installed, iac-scanner core auto-discovers the adapter:

```bash
iac-scan scan ./my-cdk-app --rules-engine cdk-nag
```

Or `--rules-engine auto` — iac-scanner picks the engine whose probe succeeds first (Checkov for Terraform, cdk-nag for CDK).

Findings from the adapter carry:

- `source=cdk-nag`
- `rule_id=AwsSolutions-IAM4` (or similar cdk-nag rule identifier)
- `framework=AWS Solutions` (or HIPAA / NIST-800-53 / PCI-DSS)
- `cwe=CWE-xxx` when the nag pack maps one
- `remediation` text pulled from the nag annotation

## How it works

1. Checks `cdk --version` is on PATH.
2. Runs `cdk synth --quiet` in the target directory.
3. Parses the stderr for `[Error at /<stack-path>] <RuleId>: <message>` lines emitted by cdk-nag.
4. Maps each annotation to an iac-scanner `Finding`.
5. Returns a list to iac-scanner core; the core pipeline merges with LLM findings and dedupes.

If the user's CDK app doesn't have cdk-nag aspects wired, the adapter returns an empty list (not an error) — the LLM analysis path still runs.

## Compatibility

- iac-scanner: `>=0.4.0, <1.0.0`
- Node.js: `>=18` (via `cdk synth`)
- aws-cdk: `>=2.100`
- cdk-nag: any version; the adapter parses the annotation format that has been stable since cdk-nag 2.0.

## License

Apache-2.0. Same as iac-scanner.
