#!/usr/bin/env python3
"""Bump version in pyproject.toml and add a new section to CHANGELOG.md. Usage: bump_version.py [major|minor|patch]"""

import re
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
CHANGELOG = ROOT / "CHANGELOG.md"


def parse_version(s: str) -> tuple[int, int, int]:
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)", s)
    if not m:
        raise ValueError(f"Invalid version: {s}")
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def format_version(t: tuple[int, int, int]) -> str:
    return f"{t[0]}.{t[1]}.{t[2]}"


def get_current_version() -> str:
    text = PYPROJECT.read_text()
    m = re.search(r'^version\s*=\s*["\']([^"\']+)["\']', text, re.MULTILINE)
    if not m:
        raise SystemExit("Could not find version in pyproject.toml")
    return m.group(1)


def set_pyproject_version(version: str) -> None:
    text = PYPROJECT.read_text()
    new_text = re.sub(r'^(version\s*=\s*)["\'][^"\']+["\']', rf'\1"{version}"', text, count=1, flags=re.MULTILINE)
    if new_text == text:
        raise SystemExit("Could not update version in pyproject.toml")
    PYPROJECT.write_text(new_text)


def add_changelog_section(version: str) -> None:
    today = date.today().isoformat()
    section = f"## [{version}] - {today}\n\n### Added\n- (describe changes)\n\n"
    if not CHANGELOG.exists():
        CHANGELOG.write_text(
            "# Changelog\n\n"
            "All notable changes to this project will be documented in this file.\n\n"
            "The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).\n\n" + section
        )
        return
    text = CHANGELOG.read_text()
    if f"## [{version}]" in text:
        raise SystemExit(f"CHANGELOG.md already has a section for {version}")
    # Insert after the first "## [" (first release section)
    insert_at = text.find("\n## [")
    if insert_at == -1:
        insert_at = text.find("\n\n", text.find("Changelog"))
        if insert_at == -1:
            CHANGELOG.write_text(text.rstrip() + "\n\n" + section)
            return
    new_text = text[: insert_at + 1] + section + text[insert_at + 1 :]
    CHANGELOG.write_text(new_text)


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in ("major", "minor", "patch"):
        print("Usage: bump_version.py [major|minor|patch]", file=sys.stderr)
        return 1
    kind = sys.argv[1]
    current = get_current_version()
    major, minor, patch = parse_version(current)
    if kind == "major":
        major += 1
        minor = 0
        patch = 0
    elif kind == "minor":
        minor += 1
        patch = 0
    else:
        patch += 1
    new_version = format_version((major, minor, patch))
    set_pyproject_version(new_version)
    add_changelog_section(new_version)
    print(f"Bumped {current} -> {new_version}. Updated pyproject.toml and CHANGELOG.md.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
