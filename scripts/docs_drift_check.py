#!/usr/bin/env python3
"""Detect documentation drift: which docs2/ files may be stale for a code change.

Two signals, both derived from conventions the docs already follow:
  1. Citations — every factual claim in docs2/ cites `path:line`. If a cited
     file changed since the pin the docs were verified against, the citing doc
     is suspect.
  2. Doc map — docs2/.docmap.yml maps code globs to docs, catching changes in
     a doc's territory that it happens not to cite line-by-line.

Usage:
  python3 scripts/docs_drift_check.py                 # pin (from docs2/README.md) .. HEAD
  python3 scripts/docs_drift_check.py --base <ref>    # explicit base ref
  python3 scripts/docs_drift_check.py --exit-zero     # report only, never fail (CI summary jobs)

Exit codes: 0 = no drift, 1 = drift found (suppressed by --exit-zero), 2 = usage/config error.
Stdlib only; the .docmap.yml subset it reads is "key:\n  - value" lines.
"""

import argparse
import fnmatch
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DOCS = REPO / "docs2"

# `src/services/auth.py:754`, `app.py:34-36`, `docker-compose.dev.yml:9-12`,
# or a bare cited file like `src/utils/journeys.py`. Requires the backticks the
# docs' citation convention mandates; repo-prefixed sibling cites (`flux: ...`)
# contain a space after the colon and never match.
CITATION_RE = re.compile(
    r"`([A-Za-z0-9_][A-Za-z0-9_./-]*\.(?:py|yml|yaml|js|jsx|ts|tsx|mjs|cjs|json|txt|cfg|ini|toml|html|css|scss|sql|sh|cs|csproj|sln|props|targets|xml|cshtml|razor|csv|md))(?::(\d+)(?:-(\d+))?)?`"
)

PIN_RE = re.compile(r"`develop @ ([0-9a-f]{7,40})`")


def git(*args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(REPO), *args], capture_output=True, text=True, check=True
    ).stdout


def read_pin() -> str:
    text = (DOCS / "README.md").read_text()
    m = PIN_RE.search(text)
    if not m:
        sys.exit("docs2/README.md carries no `develop @ <sha>` pin — cannot infer base (exit 2)")
    return m.group(1)


def load_docmap() -> dict[str, list[str]]:
    mapping: dict[str, list[str]] = {}
    current = None
    for raw in (DOCS / ".docmap.yml").read_text().splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" ") and line.endswith(":"):
            current = line[:-1]
            mapping[current] = []
        elif line.lstrip().startswith("- ") and current:
            mapping[current].append(line.lstrip()[2:].strip())
    return mapping


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base", help="base ref (default: the pin in docs2/README.md)")
    ap.add_argument("--head", default="HEAD")
    ap.add_argument("--exit-zero", action="store_true", help="always exit 0 (CI report mode)")
    args = ap.parse_args()

    base = args.base or read_pin()
    try:
        changed = set(filter(None, git("diff", "--name-only", base, args.head).splitlines()))
    except subprocess.CalledProcessError as e:
        print(e.stderr, file=sys.stderr)
        return 2
    changed_code = {c for c in changed if not c.startswith("docs2/")}

    # File sets at base and head, so basename shorthand and sibling-repo cites
    # never register: a citation is only "dead" if it was tracked at the base
    # and is gone at head.
    base_tree = set(git("ls-tree", "-r", "--name-only", base).splitlines())
    head_tree = set(git("ls-tree", "-r", "--name-only", args.head).splitlines())

    # Signal 1: citations into changed files
    cited_hits: dict[str, set[str]] = defaultdict(set)
    dead_cites: dict[str, set[str]] = defaultdict(set)
    for doc in sorted(DOCS.glob("**/*.md")):
        rel_doc = str(doc.relative_to(DOCS))
        for m in CITATION_RE.finditer(doc.read_text()):
            cited = m.group(1)
            if cited in changed_code:
                cited_hits[rel_doc].add(cited)
            if cited in base_tree and cited not in head_tree:
                dead_cites[rel_doc].add(cited)

    # Signal 2: docmap territory
    map_hits: dict[str, set[str]] = defaultdict(set)
    for doc, globs in load_docmap().items():
        for g in globs:
            for c in changed_code:
                if fnmatch.fnmatch(c, g):
                    map_hits[doc].add(c)

    affected = sorted(set(cited_hits) | set(map_hits))
    print(f"docs drift check — base {base[:10]} .. {args.head} "
          f"({len(changed_code)} code files changed)\n")
    if not affected and not dead_cites:
        print("OK: no doc cites a changed file and no changed file falls in any doc's territory.")
        return 0

    for doc in affected:
        print(f"## {doc}")
        for c in sorted(cited_hits.get(doc, ())):
            print(f"  - cites changed file: {c}")
        for c in sorted(map_hits.get(doc, set()) - cited_hits.get(doc, set())):
            print(f"  - territory changed:  {c}")
    if dead_cites:
        print("\n## citations pointing at files that no longer exist")
        for doc in sorted(dead_cites):
            for c in sorted(dead_cites[doc]):
                print(f"  - {doc}: {c}")

    print(f"\n{len(affected)} doc(s) potentially stale. "
          "Run the /docs-sync skill (or update by hand) and bump the pin in docs2/README.md.")
    return 0 if args.exit_zero else 1


if __name__ == "__main__":
    sys.exit(main())
