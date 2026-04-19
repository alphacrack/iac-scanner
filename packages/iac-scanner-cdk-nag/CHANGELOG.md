# Changelog — iac-scanner-cdk-nag

All notable changes to this companion package will be documented in this file.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Semver.

## [Unreleased]

## [0.1.0] — 2026-04-19

### Added

- Initial release: cdk-nag rule-engine adapter for [iac-scanner](https://github.com/alphacrack/iac-scanner).
- Shells out to `cdk synth --quiet --ci`, parses AwsSolutions / HIPAA / NIST-800-53 / PCI-DSS / FedRAMP nag annotations from stderr, and maps each to an iac-scanner `Finding` with `source=cdk-nag`, `rule_id`, `framework`, and severity (CRITICAL for IAM wildcards / no-encryption / no-rotation, HIGH for other Errors, MEDIUM for Warnings).
- Auto-discovered by iac-scanner core via the `iac_scanner.rule_engines` entry-point group — `pip install iac-scanner-cdk-nag` and the `cdk-nag` engine becomes available to `iac-scan scan --rules-engine=cdk-nag` (or `--rules-engine=auto`).
- Apache-2.0 license, PEP 561 `py.typed` marker.
- 24 unit tests covering severity mapping, framework inference, annotation parsing (simple + dotted rule IDs like `HIPAA.Security-*` and `NIST800-53.R5-*`), `cdk synth` subprocess handling (happy, timeout, failure, missing CLI), and availability probing.
