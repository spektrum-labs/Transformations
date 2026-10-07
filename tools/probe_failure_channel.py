"""Which channel does a transform report an unexpected failure through?

Token-Service's not-evaluated gate reads additionalInfo.dataCollection.status only
(_data_collection_failure_message, evaluate.py). additionalInfo.transformation.status is
read by _self_reported_failure in vacuous_output.py, which is wired into onboarding
validation and phase-4 but NEVER into evaluate.py -- so a transform that reports its
failure through the transformation channel alone is graded at runtime regardless.

This drives each transform down its except path with the POISONED body from
check_none_not_evaluated.py (a dict whose every read raises) and prints both channels.

Exit status is 1 when any probed criterion is graded at runtime, so this can gate CI.

SCOPE. This establishes the POISONED path only -- what a transform does when its own code
raises. The other two no-evidence routes, a vendor refusal envelope and an empty-but-valid
body, are separate replays and a file can pass one while failing another. Do not read a
clean run here as "this transform handles no evidence correctly".

Usage:
    probe_failure_channel.py <transform.py> [<criteriaKey> ...]   # keys optional
    probe_failure_channel.py --all <dir>                          # walk a tree
    probe_failure_channel.py --self-test                          # prove it catches a defect

Exits 1 when any file is graded at runtime, so it can gate CI unchanged.

Needs RestrictedPython and the Transformations repo's own tools/restricted_sandbox.py.
If this file is run from inside the Transformations repo, both are found automatically;
otherwise point TX_REPO at a checkout.
"""
from __future__ import annotations

import os
import re
import sys


def _find_sandbox():
    """Locate the repo's restricted_sandbox.py without hardcoding a scratch path.

    The first version of this script hardcoded /tmp/tx-main/tools, which works exactly
    until /tmp is cleared. Search, in order: TX_REPO, this file's own repo (so it works
    once committed into Transformations/tools/), then the review's pinned worktrees.
    """
    candidates = []
    if os.environ.get("TX_REPO"):
        candidates.append(os.path.join(os.environ["TX_REPO"], "tools"))
    here = os.path.dirname(os.path.abspath(__file__))
    candidates += [here, os.path.join(here, "..", "tools"), "/tmp/tx-main/tools"]
    for c in candidates:
        if os.path.isfile(os.path.join(c, "restricted_sandbox.py")):
            sys.path.insert(0, os.path.abspath(c))
            return os.path.abspath(c)
    raise SystemExit(
        "restricted_sandbox.py not found. Set TX_REPO to a Transformations checkout, "
        "or run this from inside one. Searched: " + ", ".join(candidates))


SANDBOX_DIR = _find_sandbox()
import restricted_sandbox  # noqa: E402


class Poison(dict):
    """Every read raises. Forces the transform down its own `except` branch."""

    def get(self, *a, **k):
        raise RuntimeError("poisoned read")

    def __getitem__(self, k):
        raise RuntimeError("poisoned read")

    def keys(self):
        raise RuntimeError("poisoned read")

    def items(self):
        raise RuntimeError("poisoned read")


def load(path):
    src = open(path, encoding="utf-8").read()
    for name in ("_parse_input", "_listify"):
        src = re.sub(r"\b" + name + r"\b", name.lstrip("_") + "_sandboxed", src)
    ns = restricted_sandbox.load(src, filename=os.path.basename(path))
    return ns["transform"]


def probe(path):
    """Run the transform on the poisoned body. Returns (status, dataCollection, transformation,
    {key: value}) -- the keys are read off the result, never guessed from the filename."""
    try:
        out = load(path)(Poison())
    except Exception as exc:
        # Raising into the pipeline is its own defect: Token-Service wraps it in the error
        # envelope, which IS not-evaluated, so it is safe -- but it is not self-reported.
        return "RAISED:" + type(exc).__name__, None, None, {}
    if not isinstance(out, dict):
        return "NOT_A_DICT", None, None, {}
    inner = out.get("transformedResponse", out)
    info = out.get("additionalInfo") or {}
    dc = (info.get("dataCollection") or {}).get("status")
    tx = (info.get("transformation") or {}).get("status")
    vals = inner if isinstance(inner, dict) else {}
    return "OK", dc, tx, vals


DECORATIVE = {"error", "reason", "httpStatus", "endpointReachable", "evaluatedAt"}


def report(path, wanted):
    """Print one line per file. Returns (graded_at_runtime, inconclusive)."""
    status, dc, tx, vals = probe(path)
    name = os.path.relpath(path)
    if status != "OK":
        # Not a self-reported failure, and not graded either -- Token-Service's own
        # envelope catches a raise. Report it, do not count it as this defect.
        print(f"  ??   {name:<60} {status}")
        return 0, 1
    keys = [k for k in (wanted or vals) if k in vals] or sorted(set(vals) - DECORATIVE)
    shown = ", ".join(f"{k}={vals[k]!r}" for k in keys[:3]) or "(no criterion key returned)"
    graded = str(dc).lower() != "error"
    print(f"  {'FAIL' if graded else 'ok  '} {name:<60} "
          f"dataCollection={dc!r:<10} transformation={tx!r:<10} {shown}")
    return (1 if graded else 0), 0


SELF_TEST_GRADED = '''
def transform(input):
    try:
        return {"transformedResponse": {"isThing": input["x"]},
                "additionalInfo": {"dataCollection": {"status": "success", "errors": []},
                                   "transformation": {"status": "success", "errors": []}}}
    except Exception as exc:
        # The defect: the crash is reported under `transformation`, which evaluate.py
        # never reads, while dataCollection still says the collection succeeded.
        return {"transformedResponse": {"isThing": False},
                "additionalInfo": {"dataCollection": {"status": "success", "errors": []},
                                   "transformation": {"status": "error", "errors": [str(exc)]}}}
'''

SELF_TEST_CLEAN = '''
def transform(input):
    try:
        return {"transformedResponse": {"isThing": input["x"]},
                "additionalInfo": {"dataCollection": {"status": "success", "errors": []},
                                   "transformation": {"status": "success", "errors": []}}}
    except Exception as exc:
        return {"transformedResponse": {"isThing": None},
                "additionalInfo": {"dataCollection": {"status": "error", "errors": [str(exc)]},
                                   "transformation": {"status": "error", "errors": [str(exc)]}}}
'''


def self_test():
    """Prove the probe catches a planted defect and clears a correct file."""
    import tempfile
    ok = True
    for label, src, want_graded in (("planted defect", SELF_TEST_GRADED, True),
                                    ("correct file", SELF_TEST_CLEAN, False)):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "isThing.py")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(src)
            status, dc, _tx, _vals = probe(p)
            graded = status == "OK" and str(dc).lower() != "error"
            good = graded == want_graded
            ok = ok and good
            print(f"  {'PASS' if good else 'FAIL'}  {label:<16} "
                  f"dataCollection={dc!r} -> {'graded' if graded else 'not evaluated'}")
    print("\nself-test " + ("passed" if ok else "FAILED"))
    sys.exit(0 if ok else 1)


def main():
    args = sys.argv[1:]
    if not args:
        raise SystemExit(__doc__)
    if args[0] == "--self-test":
        self_test()
    graded = inconclusive = 0
    if args[0] == "--all":
        for dirpath, dirnames, names in os.walk(args[1]):
            dirnames[:] = [d for d in dirnames if d != "schemas"]   # helper modules, not transforms
            for n in sorted(names):
                if not n.endswith(".py") or n.startswith("test_") or n == "__init__.py":
                    continue
                g, i = report(os.path.join(dirpath, n), None)
                graded += g
                inconclusive += i
    else:
        graded, inconclusive = report(args[0], args[1:] or None)
    print(f"\n{graded} file(s) report a crash through a channel evaluate.py never reads, "
          f"and are graded at runtime.")
    if inconclusive:
        print(f"{inconclusive} inconclusive (raised, or returned no criterion key) "
              f"-- these need a look, not a verdict.")
    sys.exit(1 if graded else 0)


if __name__ == "__main__":
    main()
