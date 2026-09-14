#!/usr/bin/env python3
"""Cut a release: promote CHANGELOG `[Unreleased]` → `[X.Y.Z]` and create a signed annotated tag.

Usage:
    python scripts/release.py [major|minor|patch]
    python scripts/release.py 1.2.3            # explicit version
    python scripts/release.py patch --dry-run  # preview without writing

What this does:
    1. Computes the next version from the latest `vX.Y.Z` git tag (or accepts an explicit one).
    2. Rewrites `CHANGELOG.md`: the `[Unreleased]` section becomes `[X.Y.Z] - YYYY-MM-DD`, and a fresh
       empty `[Unreleased]` is inserted at the top.
    3. Commits the CHANGELOG edit (signed off, DCO).
    4. Creates a signed annotated tag `vX.Y.Z` using the new CHANGELOG entry as the tag message.
    5. Prints the `git push --follow-tags` command — pushing the tag is what triggers PyPI publish.

There is intentionally no `pyproject.toml` edit: the package version is derived from the tag by
setuptools-scm. The tag is the single source of truth.
"""

from __future__ import annotations

import argparse
import re
import subprocess  # nosec B404 — invoked only on known git/CHANGELOG commands
import sys
from datetime import date, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHANGELOG = ROOT / "CHANGELOG.md"

SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


def run(cmd: list[str], *, check: bool = True, capture: bool = False) -> str:
    """Thin subprocess.run wrapper. Returns stdout when capture=True."""
    result = subprocess.run(  # nosec B603 — args are a fixed list, no shell
        cmd,
        cwd=ROOT,
        check=check,
        text=True,
        capture_output=capture,
    )
    return (result.stdout or "").strip() if capture else ""


def latest_tag_version() -> tuple[int, int, int] | None:
    """Return the highest semver tag (vX.Y.Z), or None if there are no tags."""
    out = run(["git", "tag", "--list", "v[0-9]*.[0-9]*.[0-9]*"], capture=True)
    versions: list[tuple[int, int, int]] = []
    for line in out.splitlines():
        m = SEMVER_RE.match(line.removeprefix("v"))
        if m:
            versions.append((int(m.group(1)), int(m.group(2)), int(m.group(3))))
    return max(versions) if versions else None


def parse_explicit(version: str) -> tuple[int, int, int]:
    m = SEMVER_RE.match(version.removeprefix("v"))
    if not m:
        raise SystemExit(f"Not a valid X.Y.Z version: {version!r}")
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def bump(current: tuple[int, int, int], kind: str) -> tuple[int, int, int]:
    major, minor, patch = current
    if kind == "major":
        return major + 1, 0, 0
    if kind == "minor":
        return major, minor + 1, 0
    if kind == "patch":
        return major, minor, patch + 1
    raise SystemExit(f"Unknown bump kind: {kind!r}")


def fmt(v: tuple[int, int, int]) -> str:
    return f"{v[0]}.{v[1]}.{v[2]}"


def ensure_unreleased(text: str) -> None:
    if "## [Unreleased]" not in text:
        raise SystemExit(
            "CHANGELOG.md is missing a `## [Unreleased]` section. Add one before cutting a release."
        )


def promote_changelog(text: str, new_version: str) -> tuple[str, str]:
    """Return (new_changelog, release_notes) — the latter is just the [X.Y.Z] body, used as tag msg."""
    today = date.today().isoformat()
    if f"## [{new_version}]" in text:
        raise SystemExit(f"CHANGELOG.md already has a section for {new_version}.")

    pattern = re.compile(r"^## \[Unreleased\]\s*\n", re.MULTILINE)
    m = pattern.search(text)
    if not m:
        raise SystemExit("Could not locate `## [Unreleased]` heading.")

    fresh = "## [Unreleased]\n\n"
    # The Unreleased-heading regex consumes the trailing blank line, so the
    # promoted heading needs its own to keep KaC formatting (blank line before
    # the next `###` subsection).
    promoted_heading = f"## [{new_version}] - {today}\n\n"

    new_text = text[: m.start()] + fresh + promoted_heading + text[m.end() :]

    # Extract the release-notes body (between the new heading and the next "## " heading) for the tag.
    section_start = new_text.index(promoted_heading) + len(promoted_heading)
    next_heading = new_text.find("\n## ", section_start)
    notes = new_text[section_start : next_heading if next_heading != -1 else None].strip("\n")
    if not notes.strip():
        notes = "(no changelog entries — please add them under [Unreleased] before releasing)"
    return new_text, notes


def git_clean() -> bool:
    return not run(["git", "status", "--porcelain"], capture=True)


def current_branch() -> str:
    return run(["git", "rev-parse", "--abbrev-ref", "HEAD"], capture=True)


def main() -> int:
    p = argparse.ArgumentParser(description="Cut a tag-driven release.")
    p.add_argument("bump", help="One of: major | minor | patch | X.Y.Z")
    p.add_argument("--dry-run", action="store_true", help="Show what would happen; do not modify the repo.")
    p.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Skip the clean-working-tree check (not recommended).",
    )
    p.add_argument(
        "--no-sign",
        action="store_true",
        help="Use a plain annotated tag instead of `git tag -s`. CI release verification expects signed tags.",
    )
    args = p.parse_args()

    if not args.dry_run and not args.allow_dirty and not git_clean():
        raise SystemExit("Working tree is dirty. Commit or stash first, or pass --allow-dirty.")

    if args.bump in ("major", "minor", "patch"):
        current = latest_tag_version() or (0, 0, 0)
        new = bump(current, args.bump)
    else:
        new = parse_explicit(args.bump)

    new_version = fmt(new)
    tag = f"v{new_version}"
    branch = current_branch() if not args.dry_run else "(dry-run)"
    print(f"Releasing {tag} from branch {branch} at {date.today().isoformat()} (UTC {timezone.utc})")

    text = CHANGELOG.read_text()
    ensure_unreleased(text)
    new_text, notes = promote_changelog(text, new_version)

    if args.dry_run:
        print("\n--- CHANGELOG diff (preview) ---")
        print(f"Promoted [Unreleased] → [{new_version}] - {date.today().isoformat()}")
        print("\n--- Tag message (preview) ---")
        print(f"Release {new_version}\n\n{notes}")
        print("\n--- Would run ---")
        print(f"  git add CHANGELOG.md")
        print(f'  git commit -s -m "Release {new_version}"')
        print(
            f'  git tag {"-s" if not args.no_sign else "-a"} {tag} '
            f'-m "Release {new_version}" -m "<changelog section>"'
        )
        print(f"  git push --follow-tags origin {branch}")
        return 0

    CHANGELOG.write_text(new_text)
    run(["git", "add", "CHANGELOG.md"])
    run(["git", "commit", "-s", "-m", f"Release {new_version}"])

    # --cleanup=verbatim prevents git from treating Markdown `### Changed` /
    # `### Added` lines as comments and stripping them out of the tag message.
    tag_args = [
        "git",
        "tag",
        "--cleanup=verbatim",
        "-s" if not args.no_sign else "-a",
        tag,
        "-m",
        f"Release {new_version}\n\n{notes}",
    ]
    try:
        run(tag_args)
    except subprocess.CalledProcessError:
        if args.no_sign:
            raise
        print(
            "\nSigned tag failed — likely no GPG key configured. Re-run with --no-sign,\n"
            "or set `git config user.signingkey <KEY>` and `git config commit.gpgsign true`.",
            file=sys.stderr,
        )
        return 1

    print(
        f"\nCreated {tag} and Release commit. To publish:\n"
        f"  git push --follow-tags origin {branch}\n\n"
        "The release workflow will then:\n"
        "  1. Create a GitHub Release from this tag (with the CHANGELOG section as the body).\n"
        "  2. Trigger publish-pypi.yml: build, SBOM, Trusted Publishing to PyPI, Sigstore signing."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
