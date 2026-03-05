#!/usr/bin/env python3
"""
Generate a new Jekyll blog post and append a "What's new" section to the tutorial.
Called by the Blog release workflow. Usage:
  generate_blog_post.py <version> [--title "Post title"] [--summary "One line"]
"""

import argparse
import re
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHANGELOG = ROOT / "CHANGELOG.md"
POSTS_DIR = ROOT / "docs" / "_posts"
TUTORIAL = ROOT / "docs" / "tutorial.md"


def get_changelog_section(version: str) -> str:
    """Extract the section for this version from CHANGELOG (## [X.Y.Z] ... until next ##)."""
    text = CHANGELOG.read_text()
    pattern = rf"^## \[{re.escape(version)}\].*?^(?=## |\Z)"
    m = re.search(pattern, text, re.MULTILINE | re.DOTALL)
    if not m:
        return ""
    return m.group(0).strip()


def create_post(version: str, title: str | None, summary: str | None) -> Path:
    """Create docs/_posts/YYYY-MM-DD-release-vX.Y.Z.md. Returns the path."""
    today = date.today().isoformat()
    slug = f"release-v{version}"
    path = POSTS_DIR / f"{today}-{slug}.md"
    changelog_block = get_changelog_section(version)
    body = summary or f"Release v{version}. See changelog below for details."
    content = f"""---
layout: default
title: "{title or f'Release v{version}'}"
date: {today}
categories: blog
---

# {title or f"Release v{version}"}

{body}

## Changelog

```markdown
{changelog_block}
```
"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def append_tutorial_section(version: str) -> None:
    """Insert a 'What's new in vX.Y.Z' subsection under 'What's new (versions)' in the tutorial."""
    text = TUTORIAL.read_text()
    marker = "## What's new (versions)"
    new_block = f"\n### What's new in v{version}\n\n- See the [blog post]({{{{ site.baseurl }}}}/blog) for the latest release notes.\n\n"
    if marker in text:
        idx = text.find(marker) + len(marker)
        # Insert after the heading and its following newline
        rest = text[idx:]
        if rest.startswith("\n\n"):
            idx += 2
        elif rest.startswith("\n"):
            idx += 1
        text = text[:idx] + new_block + text[idx:]
    else:
        text = text.rstrip() + "\n\n---\n" + new_block.strip() + "\n"
    TUTORIAL.write_text(text, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("version", help="Version, e.g. 0.2.1")
    parser.add_argument("--title", default=None, help="Post title")
    parser.add_argument("--summary", default=None, help="One-line summary")
    args = parser.parse_args()
    create_post(args.version, args.title, args.summary)
    append_tutorial_section(args.version)
    print(f"Created post and updated tutorial for v{args.version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
