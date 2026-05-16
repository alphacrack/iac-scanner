# Project governance

This document describes how `iac-scanner` is governed. It is intentionally lightweight; the goal is to make decision-making transparent without slowing down a small project.

## Roles

| Role             | Who                                | What they can do                                                                 |
|------------------|------------------------------------|----------------------------------------------------------------------------------|
| **Maintainer**   | Listed in [MAINTAINERS.md](MAINTAINERS.md) | Review and merge PRs, cut releases, manage CI/secrets, triage security reports.  |
| **Contributor**  | Anyone who opens an issue or PR    | Propose changes, report bugs, contribute code, docs, tests, samples.             |
| **User**         | Anyone running `iac-scan`          | File issues, request features, share feedback.                                   |

Becoming a maintainer is by invitation from existing maintainers, typically after a sustained track record of high-quality contributions and reviews. There is no minimum quota — invitations are issued when the project benefits.

## Decision-making

- **Lazy consensus.** Most changes go in via a PR with at least one maintainer approval. Silence = consent after 72 hours for non-controversial changes.
- **Disagreements** are resolved by discussion on the PR/issue. If consensus can't be reached, the maintainer team decides by simple majority. Ties go to the project lead (currently the original author, see [MAINTAINERS.md](MAINTAINERS.md)).
- **Architectural changes** (new IaC type, swapping the LLM SDK, breaking CLI changes) require an issue with `kind:proposal`, a 7-day comment window, and maintainer-team sign-off before implementation.
- **Security-sensitive changes** (prompt-injection defenses, secret redaction, the skip-list, supply-chain workflows) require **two** maintainer approvals.

## Branch protection and merge policy

`main` is protected. The current enforced rules are codified in [`scripts/apply_branch_protection.sh`](scripts/apply_branch_protection.sh) and applied via the GitHub API. Rules at a glance:

- PRs only — no direct pushes to `main`.
- All required CI checks must pass (lint, mypy, test matrix, smoke, CodeQL).
- At least 1 maintainer approval; CODEOWNERS review for paths in [.github/CODEOWNERS](.github/CODEOWNERS).
- Stale approvals dismissed on new commits.
- Linear history (squash or rebase merges only).
- Signed commits encouraged; **signed tags required** for releases (the release workflow verifies tag annotation).
- Force pushes and branch deletion: disabled.
- Branch protection rules themselves cannot be bypassed by admins (`enforce_admins: true`).

## Release authority

- Any maintainer may cut a release using the documented `make release-*` flow (see [CONTRIBUTING.md → Releases](CONTRIBUTING.md#releases)).
- PyPI publishing is gated by the **`release` GitHub Environment**. Reviewers configured on that environment hold the final approval before a build is pushed to PyPI.
- The PyPI project uses **Trusted Publishing (OIDC)** — no long-lived API tokens.

## Security

Reports go to the channel in [SECURITY.md](SECURITY.md). Acknowledgement within 72h; a fix or mitigation timeline within 7 days. See SECURITY.md for the supported-versions matrix and disclosure policy.

## Code of conduct

[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) (Contributor Covenant 2.1). Reports to the address listed there.

## Changing this document

Edits to GOVERNANCE.md require a PR with **two** maintainer approvals and a 7-day comment window.
