"""INVARIANT: a criterion that can never be false is not a check.

THE RULE. Every `transform()` in safeguards/ is handed a battery of BAD-POSTURE bodies --
controls explicitly off, enrolments explicitly false, empty policy and device populations,
counts at zero. A satisfaction-style criterion that comes back `true` for every one of them
has no reachable `false`, and therefore cannot ever report the thing it exists to report.

THIS IS A DIFFERENT DEFECT FROM FAIL-OPEN and neither checker subsumes the other.
tools/check_fail_closed.py asks "does it answer from a body that proves nothing?" -- a
transform hard-wired to `true` sails through it, because it answers the same way from
everything. This one asks "is there any input at all that makes it say no?" Measured
2026-09-21: 111 transforms answered `true` to every bad-posture probe, among them
isPatchManagementEnabled, isRemovableMediaControlled, isSSOEnabled and 38 copies of
confirmedLicensePurchased. A customer with patch management switched off was told it was
on.

WHAT IS NOT A FINDING, and why the exemptions are a list rather than an inference:

  * A control the vendor's product does not let anyone disable is legitimately always
    true, and saying so is correct rather than lazy. CrashPlan and Datto encryption are
    argued on exactly these grounds. Such a criterion belongs in the allowlist with a
    reason, adjudicated by someone who owns the vendor relationship -- NOT by this
    checker, which cannot read a product manual.
  * A criterion whose `true` denotes the INSECURE condition is handled by the shared
    INVERTED set in check_fail_closed.py; `true` everywhere is a different (and also
    wrong) shape there, but it is not THIS contract's business.
  * A transform that returns no satisfaction-style key at all is out of scope.

THE PROBE BATTERY IS DELIBERATELY BROAD, because a transform that recognises none of the
shapes fed to it would otherwise look like a defect. A file is flagged only when it
returns `true` for a key on EVERY probe AND at least one probe was in a shape it plainly
understood -- i.e. it never once said no to anything.

THE RATCHET. contracts/discriminates-allowlist.json carries the known population and MAY
ONLY SHRINK, same contract as the fail-closed list: listed files are reported and do not
fail the run, unlisted ones do, and entries that stop reproducing are named STALE.

Usage:
    python tools/check_discriminates.py
    python tools/check_discriminates.py --emit-allowlist
    python tools/check_discriminates.py --self-test
"""
from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import json
import pathlib
import sys
import warnings

ROOT = pathlib.Path(__file__).resolve().parents[1]
SAFEGUARDS = ROOT / "safeguards"
ALLOWLIST = ROOT / "contracts" / "discriminates-allowlist.json"

sys.path.insert(0, str(ROOT / "tools"))
try:
    # one definition, not two -- the file set as well as the key rules, so a pytest
    # module excluded there cannot reappear as a transform here
    from check_fail_closed import INVERTED, SATISFACTION, TEST_MODULE
except ImportError:  # pragma: no cover - only when run from an odd cwd
    import re
    TEST_MODULE = re.compile(r"^(test_.*|conftest)\.py$")
    SATISFACTION = re.compile(r"^(confirmed|is|are|has)[A-Z]")
    INVERTED = frozenset()

#: bodies describing an estate that is PLAINLY NON-COMPLIANT. A working criterion must say
#: no to at least one of these. They are varied in shape because transforms disagree about
#: what a response looks like, and a transform that understands none of them must not be
#: mistaken for one that understands them and approves.
BAD_POSTURE = [
    {"enabled": False, "status": "disabled", "count": 0, "items": [], "totalRecords": 0},
    {"users": [{"is_enrolled": "false", "status": "active", "mfaEnabled": False}],
     "policies": [], "mfaEnabled": False, "totalRecords": 0},
    {"settings": {"enabled": False}, "devices": [{"encryption": False, "protected": False}],
     "agents": [{"enabled": False}]},
    {"data": [{"enabled": False, "status": "inactive"}], "licensed": False,
     "subscription": None, "licensePurchased": False},
    {"result": {"enabled": False}, "configured": False, "compliant": False,
     "isEnabled": False, "installed": False},
]

#: a body describing a plainly COMPLIANT estate -- used only to establish that the
#: transform reacts to input at all
GOOD_POSTURE = {
    "enabled": True, "status": "active", "count": 5, "totalRecords": 7,
    "items": [{"id": 1, "enabled": True}], "devices": [{"encryption": True, "protected": True}],
    "users": [{"is_enrolled": "true", "status": "active", "mfaEnabled": True}],
    "policies": [{"Enabled": True}], "licensed": True, "licensePurchased": True,
    "settings": {"enabled": True}, "isEnabled": True, "installed": True, "configured": True,
}


def satisfaction_true(response) -> frozenset[str]:
    if not isinstance(response, dict):
        return frozenset()
    inner = response.get("transformedResponse", response)
    if not isinstance(inner, dict):
        return frozenset()
    return frozenset(
        k for k, v in inner.items()
        if v is True and SATISFACTION.match(k) and k not in INVERTED
    )


def transform_files() -> list[pathlib.Path]:
    return sorted(
        p for p in SAFEGUARDS.rglob("*.py")
        if "schemas" not in p.parts
        and p.name != "__init__.py"
        and not TEST_MODULE.match(p.name)
    )


def census(files=None) -> dict:
    warnings.filterwarnings("ignore")
    findings: dict[str, list[str]] = {}
    files = files if files is not None else transform_files()
    for i, path in enumerate(files):
        rel = str(path.relative_to(ROOT))
        try:
            spec = importlib.util.spec_from_file_location(f"_disc_{i}", path)
            module = importlib.util.module_from_spec(spec)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                spec.loader.exec_module(module)
        except Exception:
            continue  # unloadable is check_fail_closed's finding, not this one
        if not callable(getattr(module, "transform", None)):
            continue

        def run(body):
            try:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    return satisfaction_true(module.transform(body))
            except Exception:
                return None

        good = run(GOOD_POSTURE)
        if not good:
            continue  # says yes to nothing; not this contract's concern

        never_false = set(good)
        understood = False
        for body in BAD_POSTURE:
            got = run(body)
            if got is None:
                continue
            understood = True
            never_false &= got
        if understood and never_false:
            findings[rel] = sorted(never_false)
    return {"findings": findings, "examined": len(files)}


def load_allowlist() -> dict:
    if not ALLOWLIST.is_file():
        return {"instances": []}
    return json.loads(ALLOWLIST.read_text())


def emit_allowlist() -> dict:
    result = census()
    instances = sorted(result["findings"])
    out = {
        "contract": "discriminates",
        "why": "a satisfaction-style criterion must have some input that makes it false; "
               "this list may only shrink",
        "generated_by": "tools/check_discriminates.py --emit-allowlist",
        "how_to_exempt": "a control the vendor's product does not permit disabling is "
                         "legitimately always true. Record it here WITH A REASON, "
                         "adjudicated by whoever owns the vendor relationship.",
        "count": len(instances),
        "instances": instances,
    }
    ALLOWLIST.parent.mkdir(parents=True, exist_ok=True)
    ALLOWLIST.write_text(json.dumps(out, indent=2) + "\n")
    return out


def self_test() -> int:
    import tempfile
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        d = pathlib.Path(tmp)
        (d / "isalwaystrue.py").write_text(
            "def transform(input):\n    return {'isAlwaysTrue': True}\n")
        (d / "isdiscriminating.py").write_text(
            "def transform(input):\n"
            "    data = input if isinstance(input, dict) else {}\n"
            "    return {'isDiscriminating': bool(data.get('enabled'))}\n")
        (d / "isalwaysfalse.py").write_text(
            "def transform(input):\n    return {'isAlwaysFalse': False}\n")
        global SAFEGUARDS, ROOT
        saved = (SAFEGUARDS, ROOT)
        SAFEGUARDS, ROOT = d, d
        try:
            found = census()["findings"]
        finally:
            SAFEGUARDS, ROOT = saved
        if "isalwaystrue.py" not in found:
            failures.append("a criterion with no reachable false was NOT caught")
        if "isdiscriminating.py" in found:
            failures.append("a discriminating criterion was wrongly flagged")
        if "isalwaysfalse.py" in found:
            failures.append("an always-false criterion was flagged (out of scope)")
    for f in failures:
        print(f"  self-test FAIL: {f}")
    print("self-test ok" if not failures else f"self-test FAILED ({len(failures)})")
    return 1 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--emit-allowlist", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    if args.emit_allowlist:
        out = emit_allowlist()
        print(f"wrote {ALLOWLIST.relative_to(ROOT)}: {out['count']} instance(s)")
        return 0

    result = census()
    findings = result["findings"]
    allowed = set(load_allowlist().get("instances", []))
    new = sorted(set(findings) - allowed)
    stale = sorted(allowed - set(findings))

    print(f"{result['examined']} transform file(s) examined; {len(findings)} carry a "
          f"criterion with no reachable false ({len(new)} outside the allowlist)")
    if stale:
        print(f"\nSTALE allowlist entries ({len(stale)}) -- now discriminate; remove to let "
              f"the ratchet shrink:")
        for rel in stale:
            print(f"  {rel}")
    if new:
        print(f"\n✗ {len(new)} transform(s) not on the allowlist can never report a failure:")
        for rel in new:
            print(f"  {rel}: always true -> {', '.join(findings[rel])}")
        return 1
    print("\n✓ no unallowlisted transform carries a criterion that can never be false")
    return 0


if __name__ == "__main__":
    sys.exit(main())
