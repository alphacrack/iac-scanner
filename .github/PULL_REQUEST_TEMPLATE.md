<!--
Thanks for the PR! A quick guide:

- PRs target `development`, not `main`. See CONTRIBUTING.md.
- Sign off commits with `git commit -s` (DCO required).
- Update CHANGELOG.md under `## [Unreleased]` for any user-visible change.
- The `.github/labeler.yml` will auto-label `area:*` based on paths you
  touched. Maintainers add `type:*`, `priority:*`, and `status:*` on triage.
-->

## What & why

<!-- One or two paragraphs. What does this change do, and what problem does it solve? Link the issue with "Fixes #N" if one exists. Skip motivation for trivial fixes. -->

Fixes #

## Behavior change

- **User-facing:** <!-- What does a `iac-scan` user see differently? "None" is a fine answer. -->
- **CLI / API surface:** <!-- New flag? Removed one? Renamed a field in `scan-report.json`? -->
- **Config / env vars:** <!-- New `IAC_*` env? Any defaults changing? -->
- **Cost / performance:** <!-- Extra LLM calls? New cache invalidation? -->

## How to review

<!-- Highlight the interesting files and any assumptions you made. If the diff is large, tell reviewers where to start. -->

## Test evidence

<!--
Paste the relevant output or link a workflow run. Screenshots for CLI/UI. If this is a bugfix, include a test that fails without the change.
Preferred order: failing repro pre-fix → passing test post-fix → any manual verification.
-->

## Checklist

- [ ] Targets `development` (not `main`).
- [ ] Commits are DCO-signed (`git commit -s`).
- [ ] `ruff check src/ tests/` and `ruff format --check src/ tests/` clean.
- [ ] `mypy src/iac_scanner` clean (CI is `--strict`).
- [ ] Tests added / updated (`pytest tests/ -m "not e2e"`).
- [ ] CHANGELOG.md `[Unreleased]` updated for user-visible behavior.
- [ ] If this touches prompts in `orchestration/tasks.py`: `PROMPT_VERSION` bumped.
- [ ] If this changes cache format: `SCHEMA_VERSION` in `cache.py` bumped.
- [ ] No new runtime deps (or, if added, justified below).

## Roll-out notes

<!--
For maintainers / release manager. Anything unusual about how this ships?
Follow-ups planned? A flag we should announce? Docs on the site to update?
Leave empty if none.
-->
