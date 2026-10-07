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

THE RATCHET. Known instances live in contracts/failure-channel-allowlist.json and MAY ONLY
SHRINK, exactly as in check_fail_closed.py and check_none_not_evaluated.py. A listed file is
reported and does not fail the run; an unlisted one does; a listed entry that no longer
reproduces is reported STALE so the list keeps moving. That is what lets this run blocking
from the day it merges while 31 known files are still being fixed -- the alternative, leaving
it unwired until the last fix lands, leaves nothing stopping a 32nd file in the meantime.

Usage:
    probe_failure_channel.py                                      # judge the tree (CI mode)
    probe_failure_channel.py --emit-allowlist                     # regenerate from the tree
    probe_failure_channel.py --self-test                          # prove it catches a defect
    probe_failure_channel.py <transform.py> [<criteriaKey> ...]   # one file
    probe_failure_channel.py --all <dir>                          # walk a subtree
    probe_failure_channel.py <transform.py> --expect-key isFoo    # assert the RTA's key

Without --expect-key this reports what a file ANSWERS, reading the keys off its own
returned transformedResponse. With it, it also asserts the file answers what it was WIRED
to answer: Token-Service extracts transformedResponse[criteriaKey] by exact, case-sensitive
match, so a right value under a wrong name is a miss, not a pass -- extraction falls through
and the comparison proceeds against the wrong shape. Pass the key from the integration's
retrievalTransformationArray row, not from the filename (see the note below on why the
filename cannot be trusted).

Exits 1 when any file is graded at runtime, so it can gate CI unchanged.

Needs RestrictedPython and the Transformations repo's own tools/restricted_sandbox.py.
If this file is run from inside the Transformations repo, both are found automatically;
otherwise point TX_REPO at a checkout.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import sys


def _repo_root():
    """The Transformations checkout this is judging.

    When the file sits in tools/, that is its own parent. TX_REPO overrides, which is how
    the 2026-10-06 QC ran it against a pinned worktree from outside the repo.
    """
    if os.environ.get("TX_REPO"):
        return pathlib.Path(os.environ["TX_REPO"]).resolve()
    return pathlib.Path(__file__).resolve().parents[1]


ROOT = _repo_root()
SAFEGUARDS = ROOT / "safeguards"
ALLOWLIST = ROOT / "contracts" / "failure-channel-allowlist.json"

# A clean tree and a tree this checker has stopped reading both print zero findings.
# Same floor and same reasoning as check_fail_closed.MIN_JUDGED_TRANSFORMS.
MIN_JUDGED_TRANSFORMS = 400


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


def report(path, wanted, expect=()):
    """Print one line per file. Returns (graded_at_runtime, inconclusive, key_missing).

    `wanted` only selects which keys to display. `expect` is stronger: these are the keys the
    RTA row CLAIMS this file answers, i.e. the exact names Token-Service will extract. A file
    that returns the right value under a different name is a miss, not a pass -- extraction
    falls through and the comparison proceeds against the wrong shape.
    """
    status, dc, tx, vals = probe(path)
    name = os.path.relpath(path)
    if status != "OK":
        # Not a self-reported failure, and not graded either -- Token-Service's own
        # envelope catches a raise. Report it, do not count it as this defect.
        print(f"  ??   {name:<60} {status}")
        return 0, 1, 0
    absent = [k for k in expect if k not in vals]
    keys = [k for k in (wanted or expect or vals) if k in vals] or sorted(set(vals) - DECORATIVE)
    shown = ", ".join(f"{k}={vals[k]!r}" for k in keys[:3]) or "(no criterion key returned)"
    graded = str(dc).lower() != "error"
    print(f"  {'FAIL' if graded else 'ok  '} {name:<60} "
          f"dataCollection={dc!r:<10} transformation={tx!r:<10} {shown}")
    if absent:
        print(f"  KEY! {name:<60} expected but not returned: {', '.join(absent)}"
              f"  (returned: {', '.join(sorted(set(vals) - DECORATIVE)) or 'nothing'})")
    return (1 if graded else 0), 0, len(absent)


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


TEST_MODULE = re.compile(r"^(test_|conftest)")


def transform_files(root=None):
    """Every transform under safeguards/, excluding tests and helper packages."""
    base = pathlib.Path(root) if root else SAFEGUARDS
    out = []
    for p in sorted(base.rglob("*.py")):
        if TEST_MODULE.match(p.name) or p.name == "__init__.py":
            continue
        if "schemas" in p.parts:            # helper modules, not transforms
            continue
        out.append(p)
    return out


def census(root=None):
    """Judge the tree. Returns {graded: [rel], judged: n, examined: n, inconclusive: {rel: why}}."""
    graded, inconclusive, judged = [], {}, 0
    files = transform_files(root)
    for p in files:
        rel = str(p.relative_to(ROOT)) if str(p).startswith(str(ROOT)) else str(p)
        status, dc, _tx, _vals = probe(str(p))
        if status != "OK":
            inconclusive[rel] = status
            continue
        judged += 1
        if str(dc).lower() != "error":
            graded.append(rel)
    return {"graded": sorted(graded), "inconclusive": inconclusive,
            "judged": judged, "examined": len(files)}


def load_allowlist():
    if not ALLOWLIST.is_file():
        return {"instances": []}
    return json.loads(ALLOWLIST.read_text())


def emit_allowlist():
    result = census()
    instances = result["graded"]
    out = {
        "contract": "failure-channel",
        "why": "a transform that catches its own exception must report it under "
               "additionalInfo.dataCollection.status \"error\", which is the only channel "
               "Token-Service's evaluator reads; reporting it under "
               "additionalInfo.transformation.status alone leaves the criterion graded at "
               "runtime; this list may only shrink",
        "generated_by": "tools/probe_failure_channel.py --emit-allowlist",
        "count": len(instances),
        "instances": instances,
    }
    ALLOWLIST.parent.mkdir(parents=True, exist_ok=True)
    ALLOWLIST.write_text(json.dumps(out, indent=2) + "\n")
    return out


def judge_tree():
    """CI mode: census against the ratchet. Returns an exit code."""
    result = census()
    if result["judged"] < MIN_JUDGED_TRANSFORMS:
        print(f"✗ REFUSING TO REPORT: only {result['judged']} file(s) with a callable transform "
              f"were found, below the floor of {MIN_JUDGED_TRANSFORMS}. A clean tree and a tree "
              "this checker has stopped reading both print zero findings.")
        return 1
    allowed = set(load_allowlist().get("instances", []))
    graded = set(result["graded"])
    new = sorted(graded - allowed)
    stale = sorted(allowed - graded)
    print(f"{result['examined']} transform file(s) examined, {result['judged']} judged; "
          f"{len(graded)} report a crash through a channel evaluate.py never reads "
          f"({len(new)} outside the allowlist)")
    if result["inconclusive"]:
        print(f"\nNOT JUDGED ({len(result['inconclusive'])}) -- the transform raised rather than "
              f"returning, which Token-Service's own envelope catches as not evaluated:")
        for rel, why in sorted(result["inconclusive"].items()):
            print(f"  {rel}: {why}")
    if stale:
        print(f"\nSTALE allowlist entries ({len(stale)}) -- no longer reproduce; remove to let "
              f"the ratchet shrink:")
        for rel in stale:
            print(f"  {rel}")
    if new:
        print(f"\n✗ {len(new)} transform(s) not on the allowlist catch their own exception and "
              "report it under additionalInfo.transformation only, leaving the criterion graded "
              "at runtime (derive dataCollection.status from the same errors argument -- see "
              "safeguards/cloudsecurity/awssecurityhub/compliancepercentage.py:43-54):")
        for rel in new:
            print(f"  {rel}")
        return 1
    print("\n✓ every unallowlisted transform reports its own failure on the channel the "
          "evaluator reads")
    return 0


def main():
    args = sys.argv[1:]
    if not args:
        sys.exit(judge_tree())
    if args[0] == "--emit-allowlist":
        out = emit_allowlist()
        print(f"wrote {ALLOWLIST.relative_to(ROOT)}: {out['count']} instance(s)")
        sys.exit(0)
    if args[0] == "--self-test":
        self_test()
    # --expect-key K: the key the RTA row claims this file answers. Repeatable. With --all,
    # applies to every file, so it is normally used with a single path.
    expect = []
    while "--expect-key" in args:
        i = args.index("--expect-key")
        expect.append(args[i + 1])
        del args[i:i + 2]
    graded = inconclusive = keymiss = 0
    if args[0] == "--all":
        for dirpath, dirnames, names in os.walk(args[1]):
            dirnames[:] = [d for d in dirnames if d != "schemas"]   # helper modules, not transforms
            for n in sorted(names):
                if not n.endswith(".py") or n.startswith("test_") or n == "__init__.py":
                    continue
                g, i, k = report(os.path.join(dirpath, n), None, expect)
                graded += g
                inconclusive += i
                keymiss += k
    else:
        graded, inconclusive, keymiss = report(args[0], args[1:] or None, expect)
    print(f"\n{graded} file(s) report a crash through a channel evaluate.py never reads, "
          f"and are graded at runtime.")
    if keymiss:
        print(f"{keymiss} expected criteria key(s) were not returned at all -- Token-Service's "
              f"extraction falls through and compares the wrong shape.")
    if inconclusive:
        print(f"{inconclusive} inconclusive (raised, or returned no criterion key) "
              f"-- these need a look, not a verdict.")
    sys.exit(1 if (graded or keymiss) else 0)


if __name__ == "__main__":
    main()
