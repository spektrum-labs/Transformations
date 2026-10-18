#!/usr/bin/env python3
"""Every transform must compile in the sandbox the platform actually runs it in.

WHY THIS GATE EXISTS. `tools/check_fail_closed.py` imports each transform with
`importlib`, which is CPython. The pipeline does not: Token-Service compiles the file
with RestrictedPython (`tools/restricted_sandbox.py` mirrors it). The two disagree, and
a file that imports cleanly under CPython can be rejected outright by the sandbox --
RestrictedPython refuses any name beginning with an underscore, and refuses augmented
assignment to an object item. Such a file never returns a verdict; whatever wired it
receives a compile error instead.

Measured on origin/main at b357ddde: 49 transformation files defined a helper whose name
began with an underscore and 2 more used `x[k] += n`, so 51 of 1148 could not compile.
None was referenced by a live definition through `refs/heads/main` at the time, which is
the only reason it was invisible -- every one of them was one repoint away from
returning errors in production. The fail-closed contract judged all 51 and passed them,
because it never asked the question this gate asks.

No credentials, no network: it compiles each file and reports the ones the sandbox
rejects. The allowlist may only shrink.
"""
from __future__ import annotations

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
ALLOWLIST = ROOT / "contracts" / "sandbox-compile-allowlist.json"
SAFEGUARDS = ROOT / "safeguards"
DEF_TRANSFORM = re.compile(r"^def\s+transform\s*\(", re.MULTILINE)
TEST_MODULE = re.compile(r"^(test_.*|conftest)\.py$")

sys.path.insert(0, str(ROOT / "tools"))


def transform_files() -> list[pathlib.Path]:
    """The files the pipeline compiles: every non-test .py under safeguards/ with a transform()."""
    out = []
    for path in sorted(SAFEGUARDS.rglob("*.py")):
        if TEST_MODULE.match(path.name):
            continue
        if DEF_TRANSFORM.search(path.read_text(encoding="utf-8", errors="replace")):
            out.append(path)
    return out


def census() -> dict[str, str]:
    """{rel_path: reason} for every transform the sandbox refuses to compile."""
    from restricted_sandbox import load  # imported here so --help works without RestrictedPython

    failures: dict[str, str] = {}
    for path in transform_files():
        try:
            load(path.read_text(encoding="utf-8", errors="replace"))
        except Exception as exc:  # compile-time rejection, or an import the sandbox forbids
            failures[str(path.relative_to(ROOT))] = f"{type(exc).__name__}: {exc}"
    return failures


def load_allowlist() -> dict:
    if not ALLOWLIST.is_file():
        return {"instances": []}
    return json.loads(ALLOWLIST.read_text())


def main() -> int:
    if "--help" in sys.argv or "-h" in sys.argv:
        print(__doc__)
        return 0

    failures = census()
    total = len(transform_files())

    if "--emit-allowlist" in sys.argv:
        ALLOWLIST.parent.mkdir(parents=True, exist_ok=True)
        ALLOWLIST.write_text(json.dumps({
            "contract": "sandbox-compiles",
            "why": "every transform must compile under RestrictedPython, which is what the "
                   "pipeline runs; this list may only shrink",
            "generated_by": "tools/check_sandbox_compiles.py --emit-allowlist",
            "count": len(failures),
            "instances": sorted(failures),
            "reasons": {k: failures[k] for k in sorted(failures)},
        }, indent=2) + "\n")
        print(f"wrote {ALLOWLIST.relative_to(ROOT)}: {len(failures)} instance(s)")
        return 0

    allowed = set(load_allowlist().get("instances", []))
    new = sorted(set(failures) - allowed)
    stale = sorted(allowed - set(failures))

    print(f"{total} transform file(s) compiled in the sandbox; "
          f"{len(failures)} rejected, {len(allowed)} allowlisted")

    if stale:
        print(f"\nSTALE allowlist entries ({len(stale)}) -- they compile now; "
              f"regenerate with --emit-allowlist:")
        for rel in stale:
            print(f"  {rel}")

    if new:
        print(f"\n✗ {len(new)} transform(s) cannot compile in the sandbox the pipeline uses:")
        for rel in new:
            print(f"  {rel}: {failures[rel]}")
        print("\nRestrictedPython refuses names beginning with an underscore and augmented "
              "assignment to an object item. Rename the helper, or write `x[k] = x[k] + n`.")
        return 1

    print("\n✓ every transform compiles in the sandbox the pipeline uses")
    return 0


if __name__ == "__main__":
    sys.exit(main())
