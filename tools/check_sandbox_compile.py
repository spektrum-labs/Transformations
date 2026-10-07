"""INVARIANT: every transform compiles in the sandbox production actually runs it in.

THE RULE. Production does not import these files. It downloads each one and compiles it
with RestrictedPython (`compile_restricted(code, "<transformation>", "exec")`), after
rewriting exactly two whitelisted helper names -- `_parse_input` -> `parse_input` and
`_listify` -> `listify`. A file that does not compile there never runs: every criterion
wired to it renders "Transformation did not run" for every customer, on every evaluation,
whatever the vendor returned. This checker compiles every transform the same way and fails
the build on any file that would not.

WHY THIS EXISTS. check_fail_closed.py imports each transform as ordinary Python, which
accepts things RestrictedPython refuses -- names that start with "_", `x["k"] += 1`,
`nonlocal`. So a transform can pass every gate in this repo and be dead on arrival.
Measured, not hypothetical:
  * 2026-09-16: all 26 Tenable ASM transforms shipped with underscore-prefixed helpers and
    were rejected on arrival (fixed in 6f435b6c).
  * 2026-09-22: a fail-closed sweep added `_affirmative_signal` to 73 files and three
    siblings; 80 live transforms stopped compiling in production. tokens-ecs-prod logged
    '"_affirmative_signal" is an invalid variable name because it starts with "_"' from
    02:46Z that day, and 48 production criteria went dark. Every gate here was green.
A plain-Python gate cannot see this class at all. This one exists so the next one fails in
CI instead of in production.

WHAT IS MODELLED, and what deliberately is not. Only behaviour confirmed against production:
  * RestrictedPython compile -- the "invalid variable name because it starts with" and
    "Augmented assignment of object items" rejections both appear in tokens-ecs-prod logs.
  * the `_parse_input` / `_listify` rewrite -- the executor source
    (fabric/utils/codeexecutor.py `_normalize_underscore_names`) does it, and production
    logs carry no `_parse_input` rejection although many transforms use that name.
  * calls that compile but die at run time because CPython imports a module inside them
    and the executor's `safe_import` refuses it: `datetime.strftime()` imports `time`,
    `datetime.strptime()` imports `_strptime`. Measured 2026-09-29 by running each call
    under Token-Service's real PyCodeExecutor, and in production: ThreatDown at Trebron
    reported a blank `earliestExpiry` across 9 licences because its `strptime` died inside
    an `except Exception`. The banned calls are not a hand-kept list -- PROBES runs each
    candidate under tools/restricted_sandbox.py's import hook and bans only the ones it
    refuses, so the rule moves with the mirror.
Other runtime restrictions (guarded builtins) are NOT modelled: a mirror that guesses would
either pass things production rejects or fail things it accepts.

Usage:
    python tools/check_sandbox_compile.py              # judge the tree
    python tools/check_sandbox_compile.py --self-test  # prove it catches planted defects
"""
from __future__ import annotations

import argparse
import ast
import contextlib
import io
import pathlib
import re
import sys
import warnings

ROOT = pathlib.Path(__file__).resolve().parents[1]
SAFEGUARDS = ROOT / "safeguards"

#: Exactly the rewrite the production executor applies before compiling. Nothing else is
#: allowed to start with "_" -- if a new helper needs one, rename the helper.
WHITELIST = {"_parse_input": "parse_input", "_listify": "listify"}

#: A collapsed walk prints "0 failures" in the same words a clean tree does. Measured
#: 2026-09-24: 967 transforms. The floor catches a walk that stopped reading the tree.
MIN_COMPILED = 400

#: Candidate calls, run under the mirror's import hook. A method name is banned only when its
#: probe raises "Import of ... is not allowed"; "fstring" stands for a `%` format spec in an
#: f-string (`f"{dt:%Y}"`), which calls strftime. isoformat/fromisoformat are the controls.
PROBES = {
    "strftime": "datetime.datetime(2026, 1, 1).strftime('%Y')",
    "strptime": "datetime.datetime.strptime('2026', '%Y')",
    "today": "datetime.date.today()",
    "timetuple": "datetime.datetime(2026, 1, 1).timetuple()",
    "fstring": "f'{datetime.datetime(2026, 1, 1):%Y}'",
    "isoformat": "datetime.datetime(2026, 1, 1).isoformat()",
    "fromisoformat": "datetime.datetime.fromisoformat('2026-01-01')",
    "now": "datetime.datetime.now()",
}


def refused_calls() -> dict[str, str]:
    """Probe name -> the refusal, for every probe the production import hook refuses."""
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    import restricted_sandbox
    refused = {}
    for name, expr in PROBES.items():
        code = "import datetime\ndef transform(input):\n    return {'v': str(%s)}\n" % expr
        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                restricted_sandbox.load(code)["transform"]({})
        except ImportError as exc:
            if "is not allowed" in str(exc):
                refused[name] = str(exc)
    return refused


def runtime_refusals(code: str, refused: dict[str, str]) -> list[str]:
    """Lines calling something the production import hook refuses at run time."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in refused:
            out.append(f"Line {node.lineno}: .{node.func.attr}() fails at run time -- {refused[node.func.attr]}")
        if "fstring" in refused and isinstance(node, ast.FormattedValue) and node.format_spec is not None:
            spec = "".join(v.value for v in node.format_spec.values if isinstance(v, ast.Constant))
            if "%" in spec:
                out.append(f"Line {node.lineno}: f-string date format '{spec}' calls strftime -- {refused['fstring']}")
    return out

TEST_MODULE = re.compile(r"^(test_.*|conftest)\.py$")
DEF_TRANSFORM = re.compile(r"^def\s+transform\s*\(", re.MULTILINE)


def transform_files() -> list[pathlib.Path]:
    return sorted(
        p for p in SAFEGUARDS.rglob("*.py")
        if "schemas" not in p.parts and p.name != "__init__.py" and not TEST_MODULE.match(p.name)
    )


def normalize(code: str) -> str:
    for old, new in WHITELIST.items():
        code = re.sub(r"\b" + re.escape(old) + r"\b", new, code)
    return code


def compile_errors(code: str) -> list[str]:
    """RestrictedPython's rejection messages for this source, or [] if it compiles."""
    from RestrictedPython import compile_restricted
    warnings.filterwarnings("ignore")
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            compile_restricted(normalize(code), "<transformation>", "exec")
    except SyntaxError as exc:
        msgs = exc.args[0] if exc.args and isinstance(exc.args[0], tuple) else (str(exc),)
        return [str(m) for m in msgs]
    return []


def census() -> dict:
    failures: dict[str, list[str]] = {}
    compiled = 0
    refused = refused_calls()
    for path in transform_files():
        code = path.read_text(encoding="utf-8", errors="replace")
        if not DEF_TRANSFORM.search(code):
            continue
        compiled += 1
        errs = compile_errors(code) + runtime_refusals(code, refused)
        if errs:
            failures[str(path.relative_to(ROOT))] = errs
    return {"compiled": compiled, "failures": failures}


def main() -> int:
    try:
        import RestrictedPython  # noqa: F401
    except ImportError:
        print("UNVERIFIABLE: RestrictedPython is not installed, so the production sandbox "
              "cannot be modelled; install requirements-test.txt. Refusing to report a pass.")
        return 2
    result = census()
    if result["compiled"] < MIN_COMPILED:
        print(f"REFUSING TO REPORT: only {result['compiled']} transform(s) found, under the "
              f"floor of {MIN_COMPILED} -- a collapsed walk and a clean tree both print 0 "
              "failures, so this is refused rather than passed.")
        return 2
    failures = result["failures"]
    print(f"{result['compiled']} transform(s) compiled under RestrictedPython; "
          f"{len(failures)} would not run in production")
    for rel, errs in sorted(failures.items()):
        print(f"  {rel}")
        for e in errs[:3]:
            print(f"      {e}")
    if failures:
        print("\n✗ these transforms pass every plain-Python gate and are dead on arrival in "
              "production. Rename underscore-prefixed names; replace `x[k] += v` with "
              "`x[k] = x[k] + v`; replace `nonlocal` with a mutable container; replace "
              "strftime with isoformat, strptime with fromisoformat, date.today() with "
              "datetime.now().date().")
        return 1
    print("\n✓ every transform compiles in the production sandbox")
    return 0


def self_test() -> int:
    """Plant each rejected shape and prove it is caught; prove the whitelist is honoured."""
    import tempfile
    try:
        import RestrictedPython  # noqa: F401
    except ImportError:
        print("self-test UNVERIFIABLE: RestrictedPython is not installed")
        return 2
    global SAFEGUARDS, ROOT, MIN_COMPILED
    failures = []
    plants = {
        "underscore_helper.py": ("def _affirmative_signal(d):\n    return bool(d)\n"
                                 "def transform(input):\n    return {'isX': _affirmative_signal(input)}\n", True),
        "augmented_item.py": ("def transform(input):\n    c = {'n': 0}\n    c['n'] += 1\n"
                              "    return {'isX': False, 'n': c['n']}\n", True),
        "nonlocal_use.py": ("def transform(input):\n    n = 0\n    def f():\n        nonlocal n\n"
                            "        n = n + 1\n    f()\n    return {'isX': False}\n", True),
        "whitelisted.py": ("def _parse_input(x):\n    return x\ndef _listify(x):\n    return [x]\n"
                           "def transform(input):\n    return {'isX': bool(_listify(_parse_input(input)))}\n", False),
        "clean.py": ("def transform(input):\n    c = {'n': 0}\n    c['n'] = c['n'] + 1\n"
                     "    return {'isX': False}\n", False),
        "strftime_call.py": ("from datetime import datetime\ndef transform(input):\n"
                             "    return {'isX': False, 'at': datetime.now().strftime('%Y')}\n", True),
        "strptime_swallowed.py": ("from datetime import datetime\ndef transform(input):\n    try:\n"
                                  "        d = datetime.strptime('2026-01-01', '%Y-%m-%d')\n"
                                  "    except Exception:\n        d = None\n    return {'isX': d is not None}\n", True),
        "date_today.py": ("from datetime import date\ndef transform(input):\n"
                          "    return {'isX': date.today().year > 2000}\n", True),
        "fstring_date.py": ("from datetime import datetime\ndef transform(input):\n"
                            "    return {'isX': False, 'at': f'{datetime.now():%Y-%m-%d}'}\n", True),
        "iso_dates.py": ("from datetime import datetime\ndef transform(input):\n"
                         "    d = datetime.fromisoformat('2026-01-01T00:00:00')\n"
                         "    return {'isX': d < datetime.now(), 'at': d.isoformat(), 'w': f'{3:>4}'}\n", False),
    }
    # The rule is only as good as the probe: it must refuse what production refuses and
    # allow the replacements. If the mirror's allowlist drifts, this fails loudly.
    refused = refused_calls()
    for name in ("strftime", "strptime", "today", "fstring"):
        if name not in refused:
            failures.append(f"probe {name} was not refused by the mirror's import hook")
    for name in ("isoformat", "fromisoformat", "now"):
        if name in refused:
            failures.append(f"probe {name} was refused, but production allows it")
    with tempfile.TemporaryDirectory() as tmp:
        d = pathlib.Path(tmp)
        for name, (src, _) in plants.items():
            (d / name).write_text(src)
        saved = SAFEGUARDS, ROOT
        SAFEGUARDS, ROOT = d, d
        try:
            found = census()["failures"]
        finally:
            SAFEGUARDS, ROOT = saved
        for name, (_, should_fail) in plants.items():
            if should_fail and name not in found:
                failures.append(f"planted {name} was NOT caught")
            if not should_fail and name in found:
                failures.append(f"{name} was wrongly flagged: {found[name]}")
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
