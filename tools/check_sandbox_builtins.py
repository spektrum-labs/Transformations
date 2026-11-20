"""INVARIANT: no transform names a builtin that the production sandbox does not provide.

THE RULE. Production runs each transform with a hand-built `__builtins__`: RestrictedPython's
`safe_builtins` plus the handful of names the executor adds (mirrored by
`tools/restricted_sandbox.load`). Every other builtin -- `bytearray`, `memoryview`,
`getattr`, `hasattr`, `iter`, `next`, `map`, `filter`, `reversed`, `frozenset`, `object`,
`super`, ... -- does not exist there. Naming one is not a compile error, so
check_sandbox_compile.py passes the file; it is a NameError the first time that line runs.

WHY THIS EXISTS. Measured November 2026: six AWS Backup inventory transforms used
`isinstance(data, (bytes, bytearray))`. `bytearray` is not in `safe_builtins`, so every
production call raised NameError, and each transform's own `except Exception` turned it into
"could not read the inventory" -- a well-formed answer, so nothing looked broken. Every gate
was green: the plain-Python gates import the file under CPython, where `bytearray` exists,
and the sandbox-compile gate only compiles. Fixed in Transformations #1406/#1407 with a
per-folder test; this is the repo-wide version.

HOW. Static, no fixtures. For each transform, the symbol table (stdlib `symtable`, so
function, class, lambda and comprehension scopes are resolved the way CPython resolves them)
gives every name that is looked up in globals/builtins. A name is flagged when it is
  * a builtin of the interpreter running this check (`dir(builtins)`), and
  * not bound at module level (assigned, imported, defined, or `global`-assigned), and
  * not provided by the sandbox -- the names in `restricted_sandbox.load("")`'s namespace
    and its `__builtins__`, or a name whose call the sandbox handles anyway. The last set is
    PROBED, not hand-kept: each candidate is called under the mirror and only a NameError
    counts as missing. That is how `print()` (rewritten by RestrictedPython onto `_print_`)
    is cleared, and why the rule moves with the mirror if the executor adds a name.
Names that are not builtins at all (a typo, a constant never defined) are out of scope here:
they fail in CPython too.

Usage:
    python tools/check_sandbox_builtins.py              # judge the tree
    python tools/check_sandbox_builtins.py --self-test  # prove it catches planted defects
"""
from __future__ import annotations

import argparse
import ast
import builtins
import contextlib
import io
import pathlib
import symtable
import sys
import warnings

ROOT = pathlib.Path(__file__).resolve().parents[1]
SAFEGUARDS = ROOT / "safeguards"
TOOLS = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))

from check_sandbox_compile import DEF_TRANSFORM, TEST_MODULE, normalize  # noqa: E402

#: Same floor as check_sandbox_compile.py: a walk that stopped reading the tree prints
#: "0 failures" in the same words a clean tree does, so a short count is refused.
MIN_SCANNED = 400


def transform_files() -> list[pathlib.Path]:
    return sorted(
        p for p in SAFEGUARDS.rglob("*.py")
        if "schemas" not in p.parts and p.name != "__init__.py" and not TEST_MODULE.match(p.name)
    )


def _quiet():
    stack = contextlib.ExitStack()
    stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
    stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
    stack.enter_context(warnings.catch_warnings())
    warnings.simplefilter("ignore")
    return stack


def missing_builtins() -> frozenset[str]:
    """Builtins of this interpreter that a transform cannot use in the production sandbox."""
    import restricted_sandbox
    with _quiet():
        ns = restricted_sandbox.load("")
    provided = set(ns) | set(ns["__builtins__"])
    missing = set()
    for name in dir(builtins):
        if name in provided:
            continue
        code = (f"def transform(input):\n    try:\n        {name}()\n"
                f"    except NameError:\n        return False\n"
                f"    except BaseException:\n        return True\n    return True\n")
        try:
            with _quiet():
                ok = restricted_sandbox.load(code)["transform"]({})
        except (SyntaxError, NameError):
            ok = False  # refused at compile time is not "provided" either
        if not ok:
            missing.add(name)
    return frozenset(missing)


def _global_lookups(table: symtable.SymbolTable, used: set[str], bound: set[str]) -> None:
    is_module = table.get_type() == "module"
    for sym in table.get_symbols():
        name = sym.get_name()
        if is_module and (sym.is_assigned() or sym.is_imported()):
            bound.add(name)
        elif sym.is_declared_global() and sym.is_assigned():
            bound.add(name)  # `global X; X = ...` inside a function binds X at module level
        if sym.is_referenced() and sym.is_global():
            used.add(name)
    for child in table.get_children():
        _global_lookups(child, used, bound)


def unprovided_names(code: str, missing: frozenset[str]) -> list[str]:
    """Lines naming a builtin the sandbox does not provide, or [] if none."""
    code = normalize(code)
    try:
        table = symtable.symtable(code, "<transformation>", "exec")
        tree = ast.parse(code)
    except SyntaxError:
        return []  # check_sandbox_compile.py reports files that do not parse
    used: set[str] = set()
    bound: set[str] = set()
    _global_lookups(table, used, bound)
    bad = (used - bound) & missing
    if not bad:
        return []
    lines: dict[str, list[int]] = {n: [] for n in bad}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in bad and isinstance(node.ctx, ast.Load):
            lines[node.id].append(node.lineno)
    out = []
    for name in sorted(bad):
        at = ", ".join(str(n) for n in sorted(set(lines[name]))) or "?"
        out.append(f"Line {at}: `{name}` is not a builtin in the production sandbox -- "
                   "NameError at run time")
    return out


def census() -> dict:
    missing = missing_builtins()
    failures: dict[str, list[str]] = {}
    scanned = 0
    for path in transform_files():
        code = path.read_text(encoding="utf-8", errors="replace")
        if not DEF_TRANSFORM.search(code):
            continue
        scanned += 1
        errs = unprovided_names(code, missing)
        if errs:
            failures[str(path.relative_to(ROOT))] = errs
    return {"scanned": scanned, "failures": failures, "missing": missing}


def main() -> int:
    try:
        import RestrictedPython  # noqa: F401
    except ImportError:
        print("UNVERIFIABLE: RestrictedPython is not installed, so the production sandbox's "
              "builtins cannot be built; install requirements-test.txt. Refusing to report a pass.")
        return 2
    result = census()
    if result["scanned"] < MIN_SCANNED:
        print(f"REFUSING TO REPORT: only {result['scanned']} transform(s) found, under the "
              f"floor of {MIN_SCANNED} -- a collapsed walk and a clean tree both print 0 "
              "failures, so this is refused rather than passed.")
        return 2
    failures = result["failures"]
    print(f"{result['scanned']} transform(s) scanned against the production sandbox's builtins "
          f"({len(result['missing'])} interpreter builtins are absent there); "
          f"{len(failures)} name one")
    for rel, errs in sorted(failures.items()):
        print(f"  {rel}")
        for e in errs:
            print(f"      {e}")
    if failures:
        print("\n✗ these transforms compile in production and raise NameError when the line "
              "runs; an `except Exception` around it turns that into a wrong answer, not an "
              "error. Use what the sandbox provides: `bytes` alone for bytes/bytearray, "
              "`x.get(k)` or `k in x` for getattr/hasattr on dicts, list comprehensions for "
              "map/filter, `x[::-1]` for reversed, a for loop for iter/next.")
        return 1
    print("\n✓ no transform names a builtin the production sandbox lacks")
    return 0


def self_test() -> int:
    """Plant each shape, prove it is caught or cleared, and prove the verdict matches a real run."""
    import tempfile
    try:
        import RestrictedPython  # noqa: F401
    except ImportError:
        print("self-test UNVERIFIABLE: RestrictedPython is not installed")
        return 2
    import restricted_sandbox
    global SAFEGUARDS, ROOT
    failures = []

    # The probe must reflect the mirror: absent names absent, provided ones provided, and
    # print() -- not in __builtins__ but handled by RestrictedPython -- cleared.
    missing = missing_builtins()
    for name in ("bytearray", "memoryview", "getattr", "hasattr", "iter", "next", "map", "filter"):
        if name not in missing:
            failures.append(f"probe says the sandbox provides {name}, which the mirror does not")
    for name in ("bytes", "isinstance", "sorted", "len", "print", "range"):
        if name in missing:
            failures.append(f"probe says the sandbox lacks {name}, which it provides")

    # name -> (source, flagged?, NameError when run in the sandbox?). The third column is the
    # ground truth: each plant is also executed under the mirror, so a verdict that disagrees
    # with what the sandbox actually does fails the self-test. None = not run (swallowed).
    plants = {
        # The production incident, verbatim in shape: caught, and swallowed at run time.
        "bytearray_swallowed.py": (
            "import json\ndef transform(input):\n    try:\n"
            "        if isinstance(input, (bytes, bytearray)):\n            input = input.decode()\n"
            "        return {'isX': bool(input)}\n    except Exception as e:\n"
            "        return {'isX': False, 'error': str(e)}\n", True, None),
        "bytearray.py": ("def transform(input):\n    return {'isX': isinstance(input, (bytes, bytearray))}\n",
                         True, True),
        "memoryview.py": ("def transform(input):\n    return {'isX': isinstance(input, memoryview)}\n",
                          True, True),
        "hasattr_in_helper.py": ("def check(d):\n    return hasattr(d, 'get')\n"
                                 "def transform(input):\n    return {'isX': check(input)}\n", True, True),
        "map_in_comprehension.py": ("def transform(input):\n    xs = [list(map(str, [i])) for i in range(2)]\n"
                                    "    return {'isX': bool(xs)}\n", True, True),
        "next_in_lambda.py": ("def transform(input):\n    f = lambda: next(iter([1]))\n"
                              "    return {'isX': f() == 1}\n", True, True),
        "frozenset_class_body.py": ("class K:\n    S = frozenset([1])\n"
                                    "def transform(input):\n    return {'isX': 1 in K.S}\n", True, True),
        # Cleared: shadowed, rebound, or provided.
        "local_shadow.py": ("def transform(input):\n    bytearray = bytes\n"
                            "    return {'isX': isinstance(input, bytearray)}\n", False, False),
        "module_def.py": ("def reversed(x):\n    return x[::-1]\n"
                          "def transform(input):\n    return {'isX': reversed([1, 2])[0] == 2}\n", False, False),
        "module_assign.py": ("memoryview = bytes\n"
                             "def transform(input):\n    return {'isX': isinstance(input, memoryview)}\n", False, False),
        "global_assign.py": ("def setup():\n    global filter\n    filter = lambda f, xs: [x for x in xs if f(x)]\n"
                             "setup()\ndef transform(input):\n    return {'isX': filter(bool, [1]) == [1]}\n", False, False),
        "imported.py": ("from json import loads as next\n"
                        "def transform(input):\n    return {'isX': next('true')}\n", False, False),
        "attribute_and_string.py": ("import json\ndef transform(input):\n"
                                    "    d = {'bytearray': 1}\n    return {'isX': d['bytearray'] == 1, 'n': json.dumps('map')}\n",
                                    False, False),
        "provided.py": ("import json\nfrom datetime import datetime\ndef transform(input):\n"
                        "    print('ok')\n    x = sorted([b'a', bytes(1)], key=len)\n"
                        "    return {'isX': isinstance(input, (bytes, dict)) and len(x) == 2 and datetime.now() is not None}\n",
                        False, False),
        "whitelisted_helper.py": ("def _parse_input(x):\n    return x\n"
                                  "def transform(input):\n    return {'isX': bool(_parse_input(input))}\n", False, False),
    }

    for name, (src, _, raises) in plants.items():
        if raises is None:
            continue
        try:
            with _quiet():
                restricted_sandbox.load(normalize(src))["transform"]({})
            got = False
        except NameError:
            got = True
        if got != raises:
            failures.append(f"ground truth drifted: {name} {'raised' if got else 'did not raise'} "
                            "NameError in the sandbox mirror")

    with tempfile.TemporaryDirectory() as tmp:
        d = pathlib.Path(tmp)
        for name, (src, _, _) in plants.items():
            (d / name).write_text(src)
        saved = SAFEGUARDS, ROOT
        SAFEGUARDS, ROOT = d, d
        try:
            found = census()["failures"]
        finally:
            SAFEGUARDS, ROOT = saved
        for name, (_, should_fail, _) in plants.items():
            if should_fail and name not in found:
                failures.append(f"planted {name} was NOT caught")
            if not should_fail and name in found:
                failures.append(f"{name} was wrongly flagged: {found[name]}")
        # A collapsed walk must be refused, not passed.
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
