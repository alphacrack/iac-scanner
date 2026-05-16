#!/usr/bin/env bash
# Apply the project's branch protection rules to `main` via the GitHub REST API.
# Idempotent — run any time the rules change.
#
# Requires:
#   - `gh` CLI authenticated as a user with admin rights on the repo.
#   - The repo's required-status-check names match what's set up in CI.
#
# Run from anywhere:
#   ./scripts/apply_branch_protection.sh                 # operates on origin
#   REPO=alphacrack/iac-scanner ./scripts/apply_branch_protection.sh
#
# This is the codified, reviewable version of the rules described in
# GOVERNANCE.md → "Branch protection and merge policy". Update *here*, not in
# the UI, so the policy is auditable.

set -euo pipefail

REPO="${REPO:-$(gh repo view --json nameWithOwner -q .nameWithOwner)}"
BRANCH="${BRANCH:-main}"

echo "Applying branch protection to ${REPO}@${BRANCH}"

# Required status check contexts. These must match the `name:` of jobs in your
# workflows. If you rename a job, update both here and the workflow.
read -r -d '' PAYLOAD <<JSON || true
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "Lint (ruff)",
      "Type check (mypy)",
      "Tests (py3.12 on ubuntu-latest)",
      "Smoke test (CLI --scan-only)",
      "Build sdist + wheel",
      "Analyze (python)"
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": true,
    "require_last_push_approval": true
  },
  "restrictions": null,
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "block_creations": false,
  "required_conversation_resolution": true,
  "lock_branch": false,
  "allow_fork_syncing": true,
  "required_signatures": false
}
JSON

gh api \
  --method PUT \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  "/repos/${REPO}/branches/${BRANCH}/protection" \
  --input - <<<"$PAYLOAD"

echo
echo "Done. Verify in GitHub UI: https://github.com/${REPO}/settings/branches"
echo
echo "Reminder: signed-tag enforcement for releases is implemented in the"
echo "release.yml workflow (it rejects lightweight tags). Required-signatures"
echo "for commits is intentionally off — DCO sign-off is the requirement."
