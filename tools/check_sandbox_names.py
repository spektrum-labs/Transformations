"""INVARIANT: every name a transform looks up globally exists when production runs it.

THE RULE. A transform runs as RestrictedPython in a namespace Token-Service builds
(mirrored by tools/restricted_sandbox.py `load`): a fixed set of builtins, a few
pre-imported modules (json, re, datetime, ...) and the module's own definitions. Any
other global name -- a constant nobody defined, a helper nobody wrote, `timezone` used
after importing only `datetime`, or a CPython builtin the sandbox leaves out such as
`bytearray` or `format` -- raises NameError on the line that reads it. This checker finds
every such lookup statically and fails the build on it.

WHY THIS EXISTS. The NameError is nearly always swallowed. These transforms wrap their
body in `except Exception` and turn the error into a failed or errored verdict, so the
criterion can never pass, and every other gate here stays green: they feed bodies that
return early (empty, error envelope, null) before reaching the line that would raise.
Measured, not hypothetical:
  * 2026-10-05: PingFederate isMFAEnabled and authTypesAllowed read lists that were never
    defined, and answered False for every tenant.
  * #1406: AWS Backup inventory transforms called `isinstance(x, (bytes, bytearray))`;
    `bytearray` is not a sandbox builtin, so a full inventory came back "could not read".
  * 2026-11-24: eleven transforms (Safe Security, BeyondTrust, PingFederate, Netwrix) read
    thresholds, helpers or `timezone`/`timedelta` that were never defined or imported.
check_sandbox_compile.py cannot see this class: an undefined name compiles fine.

HOW. Each transform is parsed with the standard-library `symtable`. A name counts as
looked up globally when some scope references it and resolves it as global (not local,
not a closure variable). It is fine when the module binds it (assignment, import, def,
class, or a `global` declaration that assigns it) or when the sandbox namespace provides
it. That provided set is NOT hand-kept: it is read from `restricted_sandbox.load("")` --
the namespace plus its `__builtins__` -- so the rule moves with the mirror. The self-test
also executes every planted defect in that sandbox to prove each flagged name really
raises NameError there, and every cleared plant really runs.

A `class` statement is reported as `__metaclass__`: RestrictedPython compiles it to a global
lookup of that name, symtable cannot see it, and the mirror does not provide it.

Not modelled: a name that is bound only on some paths (assigned inside an `if`) counts as
bound. That under-reports, it never over-reports.

Usage:
    python tools/check_sandbox_names.py              # judge the tree
    python tools/check_sandbox_names.py --self-test  # prove it catches planted defects
"""
from __future__ import annotations

import argparse
import contextlib
import io
import pathlib
import re
import symtable
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SAFEGUARDS = ROOT / "safeguards"
TOOLS = pathlib.Path(__file__).resolve().parent

#: A collapsed walk prints "0 failures" in the same words a clean tree does. Measured
#: 2026-11-24 on develop: 1,681 transforms. The floor catches a walk that stopped reading.
MIN_JUDGED = 400

TEST_MODULE = re.compile(r"^(test_.*|conftest)\.py$")
DEF_TRANSFORM = re.compile(r"^def\s+transform\s*\(", re.MULTILINE)
METACLASS = "__metaclass__"


def transform_files() -> list[pathlib.Path]:
    """The same selection check_sandbox_compile.py judges."""
    return sorted(
        p for p in SAFEGUARDS.rglob("*.py")
        if "schemas" not in p.parts and p.name != "__init__.py" and not TEST_MODULE.match(p.name)
    )


def provided_names() -> set[str]:
    """Every global name the production sandbox supplies before the module's own code runs."""
    sys.path.insert(0, str(TOOLS))
    import restricted_sandbox
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        ns = restricted_sandbox.load("")
    builtins = ns.get("__builtins__", {})
    if not isinstance(builtins, dict):
        builtins = vars(builtins)
    return set(ns) | set(builtins)


def _walk(table, out):
    yield table
    for child in table.get_children():
        yield from _walk(child, out)


def undefined_names(code: str, provided: set[str], filename: str = "<transformation>") -> dict[str, int]:
    """Global lookups the sandbox cannot satisfy -> the first line that references each.

    Returns {} for a file that does not parse; check_sandbox_compile.py owns that failure.
    """
    try:
        top = symtable.symtable(code, filename, "exec")
    except SyntaxError:
        return {}
    bound = set()
    for s in top.get_symbols():
        if s.is_assigned() or s.is_imported() or s.is_namespace():
            bound.add(s.get_name())
    tables = list(_walk(top, None))
    for t in tables:
        if t is top:
            continue
        for s in t.get_symbols():
            if s.is_declared_global() and s.is_assigned():
                bound.add(s.get_name())
    missing = set()
    for t in tables:
        for s in t.get_symbols():
            if not s.is_referenced():
                continue
            if t is top:
                looked_up_globally = not (s.is_assigned() or s.is_imported() or s.is_namespace())
            else:
                looked_up_globally = s.is_global()
            name = s.get_name()
            if looked_up_globally and name not in bound and name not in provided:
                missing.add(name)
    # RestrictedPython compiles every `class` statement to a global lookup of
    # `__metaclass__`, which symtable cannot see. Report it when the sandbox lacks it.
    if any(t.get_type() == "class" for t in tables) and METACLASS not in bound | provided:
        missing.add(METACLASS)
    return {name: (_first_line(code, "class") if name == METACLASS else _first_line(code, name))
            for name in sorted(missing)}


def _first_line(code: str, name: str) -> int:
    pat = re.compile(r"(?<![\w.])" + re.escape(name) + r"\b")
    for i, line in enumerate(code.splitlines(), 1):
        stripped = line.split("#", 1)[0]
        if pat.search(stripped):
            return i
    return 0


def census() -> dict:
    provided = provided_names()
    failures: dict[str, dict[str, int]] = {}
    judged = 0
    for path in transform_files():
        code = path.read_text(encoding="utf-8", errors="replace")
        if not DEF_TRANSFORM.search(code):
            continue
        judged += 1
        missing = undefined_names(code, provided, str(path))
        if missing:
            failures[str(path.relative_to(ROOT))] = missing
    return {"judged": judged, "failures": failures}


def main() -> int:
    try:
        import RestrictedPython  # noqa: F401
    except ImportError:
        print("UNVERIFIABLE: RestrictedPython is not installed, so the production sandbox's "
              "names cannot be read; install requirements-test.txt. Refusing to report a pass.")
        return 2
    result = census()
    if result["judged"] < MIN_JUDGED:
        print(f"REFUSING TO REPORT: only {result['judged']} transform(s) found, under the floor "
              f"of {MIN_JUDGED} -- a collapsed walk and a clean tree both print 0 failures, so "
              "this is refused rather than passed.")
        return 2
    failures = result["failures"]
    print(f"{result['judged']} transform(s) judged; {len(failures)} look up a name that does not "
          "exist in the production sandbox")
    for rel, missing in sorted(failures.items()):
        print(f"  {rel}")
        for name, line in missing.items():
            print(f"      line {line}: {name}")
    if failures:
        print("\n✗ each name above raises NameError when production reaches it, which the "
              "transform's own `except` usually turns into a verdict that can never pass. Define "
              "the constant or helper in the module, import it (`from datetime import timezone, "
              "timedelta`), or replace a builtin the sandbox does not provide.")
        return 1
    print("\n✓ every global name a transform reads exists in the production sandbox")
    return 0


def self_test() -> int:
    """Plant each defect, prove it is caught AND really raises NameError in the sandbox mirror;
    prove the legitimate ways of binding a name are cleared AND really run there."""
    import tempfile
    try:
        import RestrictedPython  # noqa: F401
    except ImportError:
        print("self-test UNVERIFIABLE: RestrictedPython is not installed")
        return 2
    global SAFEGUARDS, ROOT, MIN_JUDGED
    failures = []
    provided = provided_names()
    for name in ("json", "datetime", "len", "isinstance", "dict"):
        if name not in provided:
            failures.append(f"sandbox should provide {name!r} but the derived set lacks it")
    for name in ("bytearray", "timezone", "open"):
        if name in provided:
            failures.append(f"sandbox should NOT provide {name!r} but the derived set has it")

    # name -> (source, names that must be reported)
    plants = {
        "undefined_constant.py": ("def transform(input):\n    try:\n        return {'isX': len(input) >= THRESHOLD}\n"
                                  "    except Exception as e:\n        return {'isX': False, 'error': str(e)}\n",
                                  {"THRESHOLD"}),
        "undefined_helper.py": ("def transform(input):\n    out = []\n    walk_node(input, out)\n"
                                "    return {'isX': bool(out)}\n", {"walk_node"}),
        "timezone_not_imported.py": ("from datetime import datetime\ndef transform(input):\n"
                                     "    now = datetime.now(timezone.utc) - timedelta(days=1)\n"
                                     "    return {'isX': False, 'at': now.isoformat()}\n",
                                     {"timezone", "timedelta"}),
        "missing_builtin.py": ("def transform(input):\n    ok = isinstance(input, (bytes, bytearray))\n"
                               "    return {'isX': False, 'raw': ok}\n", {"bytearray"}),
        "class_statement.py": ("class Limits:\n    floor = 1\n"
                               "def transform(input):\n    return {'isX': False, 'f': Limits.floor}\n",
                               {"__metaclass__"}),
        "clean.py": ("import json\nfrom datetime import datetime, timezone, timedelta\n"
                     "THRESHOLD = 1\nSTATE = {}\n"
                     "def remember(k):\n    global LAST\n    LAST = k\n"
                     "def helper(xs):\n    total = 0\n    def add(v):\n        return total + v\n"
                     "    return [add(x) for x in xs]\n"
                     "def transform(input):\n    remember('k')\n"
                     "    cutoff = datetime.now(timezone.utc) - timedelta(days=1)\n"
                     "    data = json.loads(json.dumps(input)) if isinstance(input, dict) else {}\n"
                     "    n = len(helper([1, 2]))\n"
                     "    return {'isX': False, 'n': n, 'b': n >= THRESHOLD, 'l': LAST,\n"
                     "            'c': cutoff.isoformat(), 'd': len(data)}\n", set()),
        "sandbox_preimports.py": ("def transform(input):\n"
                                  "    return {'isX': False, 'r': bool(re.match('a', 'a')), 'j': json.dumps(1),\n"
                                  "            't': datetime.datetime(2026, 1, 1).isoformat()}\n", set()),
    }

    sys.path.insert(0, str(TOOLS))
    import restricted_sandbox

    def run_in_sandbox(src):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return restricted_sandbox.load(src)["transform"]({"a": 1})

    with tempfile.TemporaryDirectory() as tmp:
        d = pathlib.Path(tmp)
        for name, (src, _) in plants.items():
            (d / name).write_text(src)
        saved = SAFEGUARDS, ROOT, MIN_JUDGED
        SAFEGUARDS, ROOT, MIN_JUDGED = d, d, 1
        try:
            found = census()["failures"]
        finally:
            SAFEGUARDS, ROOT, MIN_JUDGED = saved
        for name, (src, expected) in plants.items():
            got = set(found.get(name, {}))
            if got != expected:
                failures.append(f"{name}: reported {sorted(got)}, expected {sorted(expected)}")
            # Tie the static rule to runtime: a flagged plant must raise NameError (or swallow
            # it into an error verdict) in the mirror; a cleared plant must run cleanly.
            try:
                out = run_in_sandbox(src)
                raised = None
            except NameError as exc:
                out, raised = None, exc
            except Exception as exc:  # pragma: no cover - reported below
                failures.append(f"{name}: sandbox raised {type(exc).__name__}: {exc}")
                continue
            if expected:
                swallowed = isinstance(out, dict) and "is not defined" in str(out.get("error", ""))
                if raised is None and not swallowed:
                    failures.append(f"{name}: flagged, but ran in the sandbox without a NameError: {out}")
            elif raised is not None:
                failures.append(f"{name}: cleared, but raised in the sandbox: {raised}")

        # a collapsed walk must be refused, not passed
        saved = SAFEGUARDS, ROOT
        SAFEGUARDS, ROOT = d / "nothing-here", d
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                rc = main()
        finally:
            SAFEGUARDS, ROOT = saved
        if rc != 2:
            failures.append(f"a collapsed walk returned {rc}, not 2 (refused)")
    for f in failures:
        print(f"  self-test FAIL: {f}")
    print("self-test ok" if not failures else f"self-test FAILED ({len(failures)})")
    return 1 if failures else 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    sys.exit(self_test() if args.self_test else main())
