"""INVARIANT: no transformation asserts a control is satisfied from a body that proves nothing.

THE RULE. Every `transform()` in safeguards/ is handed four inputs that contain no evidence
about any customer's estate -- an empty object, an authentication-error envelope, a body
that is null, and the string "{}" -- and no SATISFACTION-STYLE criterion it returns may be
`true` for any of them.

"Satisfaction-style" means a key whose `true` asserts the control IS in place
(`confirmedLicensePurchased`, `isBackupEncrypted`, `isMFAEnforcedForUsers`, ...). Keys whose
`true` denotes the INSECURE condition are the opposite case: for those, `true` on unknown
input is the safe direction, so they are listed in INVERTED and exempted. Getting that
backwards would turn a correct fail-closed transform into a finding, so the list is
explicit rather than inferred from the name.

WHY THIS EXISTS. Measured 2026-09-21 across 802 loadable transforms: 120 asserted a
satisfaction-style criterion true for an empty or error body, and 18 did so for `null`.
The mechanism is almost always the same shape --

    default_value = data is not None          # "we got something, so the control holds"
    value = data.get('someKey', default_value)

-- or an `except` branch that returns True with a note. The effect is that a rejected
credential, an empty response and an unrecognised payload are all reported as a satisfied
control. A read that failed is not a control that passed.

BOTH FORMS OF INPUT ARE TESTED, and that is not redundant. Many transforms did not decode a
JSON string at all, so a str body fell through every shape test and was read as an empty
object -- which means a sweep that passed only strings UNDERCOUNTED this population by 8.
The dict and string cases catch different bugs; keep both.

THE RATCHET. The known population lives in contracts/fail-closed-allowlist.json and MAY
ONLY SHRINK. A file on the list is reported and does not fail the run; a file not on the
list does. Adding to it requires editing a committed artefact, which a diff review sees.
An allowlist entry that no longer reproduces is reported as STALE and should be removed --
the checker will not remove it silently, because a list that edits itself is not a ratchet.

Usage:
    python tools/check_fail_closed.py                 # judge the tree against the allowlist
    python tools/check_fail_closed.py --emit-allowlist  # regenerate from the live tree
    python tools/check_fail_closed.py --self-test     # prove the checker catches a planted defect
"""
from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import json
import pathlib
import re
import sys
import warnings

ROOT = pathlib.Path(__file__).resolve().parents[1]
SAFEGUARDS = ROOT / "safeguards"
ALLOWLIST = ROOT / "contracts" / "fail-closed-allowlist.json"

#: A CLEAN TREE AND A TREE THIS CHECKER HAS STOPPED READING BOTH PRINT ZERO FINDINGS.
#: The self-test proves the logic on a corpus it builds itself in a temp directory, so
#: it cannot notice that the real walk has collapsed -- a moved `safeguards/`, a renamed
#: directory, a bad ROOT -- and a collapsed walk exits 0 and reads as a pass. Measured
#: 2026-09-22: 937 files walked, 936 of them defining a callable `transform` (the one
#: that does not is safeguards/common/response_helper.py, a shared helper). The floor is
#: set well below that: it is here to catch a collapse, not to track the population.
MIN_JUDGED_TRANSFORMS = 400

#: a key whose True asserts the control IS in place
SATISFACTION = re.compile(r"^(confirmed|is|are|has)[A-Z]")

#: keys whose True denotes the INSECURE condition -- True on unknown input is fail-CLOSED
#: for these, so they are never a finding. Named explicitly: inferring this from the key
#: name is exactly the mistake that would turn a correct transform into a defect.
INVERTED = frozenset({
    "localLoginAllowed",
    "isPublicStorageBucketExposed",
    "isAnonymousAccessAllowed",
    "isLegacyAuthAllowed",
    "isLocalLoginAllowed",
    "isPublicSharingAllowed",
    # SonicWall service accounts: True means A GAP WAS FOUND. Established from the
    # transform's own output rather than from the key name -- True is returned only
    # alongside failReasons ("Required service-account evidence was not collected"),
    # False only alongside passReasons ("No configured MFA gap was identified..."),
    # and the vendor's own suite tabulates True as the SAFE value for a partial
    # envelope while tabulating False for its four normal-polarity siblings
    # (safeguards/firewall/sonicwall/test_haslocalaccountinventoryvisibility.py:99).
    # Forcing this key False on no evidence would report "no MFA gap" from a body
    # that proves nothing -- the opposite of fail-closed.
    "hasIdentifiedServiceAccountsMFAGap",
})

#: bodies that contain no evidence about any estate
NO_EVIDENCE = {
    "empty_dict": {},
    "auth_error": {"error": {"type": "authentication_error", "message": "invalid credentials"}},
    "null": None,
    "empty_string": "{}",
    # AN UNRELATED PAYLOAD IS ALSO NO EVIDENCE, and leaving it out was a hole in this
    # checker for its first day. The very first negative control that started this work
    # recorded `{"hello": "world"} -> True` against the MDR rubber stamp -- then this
    # battery shipped testing only emptiness and errors. A transform whose rule is
    # effectively `len(data) > 0` passes every case above and is still a rubber stamp:
    # it confirms a control from a body that says nothing about that control. Measured
    # 2026-09-22 after adding these: 1 file of 804 (crashplan isbackupencrypted, which
    # required non-emptiness but not a RECOGNISED setting -- fixed in the same commit),
    # so the gate closes at 0 and the allowlist does not grow to accommodate it.
    "unrelated_json": {"hello": "world"},
    "unrelated_nested": {"foo": {"bar": [1, 2, 3]}},
}


def satisfaction_keys_true(response) -> list[str]:
    """Satisfaction-style keys this response asserts True.

    Transforms use two envelopes: the 5-section shape with `transformedResponse`, and a
    flat dict of criteria. Read both -- crashplan/isbackupencrypted.py returns the flat
    form, and a reader that only understood the envelope scored it clean while it was
    reporting encrypted backups from a parse failure.
    """
    if not isinstance(response, dict):
        return []
    inner = response.get("transformedResponse", response)
    if not isinstance(inner, dict):
        return []
    return sorted(
        k for k, v in inner.items()
        if v is True and SATISFACTION.match(k) and k not in INVERTED
    )


#: a pytest module: never something the evaluator loads as a transform
TEST_MODULE = re.compile(r"^(test_.*|conftest)\.py$")
DEF_TRANSFORM = re.compile(r"^def\s+transform\s*\(", re.MULTILINE)


def _candidate_files() -> list[pathlib.Path]:
    return sorted(
        p for p in SAFEGUARDS.rglob("*.py")
        if "schemas" not in p.parts and p.name != "__init__.py"
    )


def transform_files() -> list[pathlib.Path]:
    return [p for p in _candidate_files() if not TEST_MODULE.match(p.name)]


def smuggled_transforms() -> list[str]:
    """Excluded pytest modules that nonetheless define a top-level `transform`.

    UNLOADABLE is FATAL in this checker on purpose: a transform that cannot be
    imported standalone cannot run under RestrictedPython in Token-Service either,
    so "I could not judge this" must never pass for "clean". That made the five
    safeguards/firewall/sonicwall/test_*.py files fatal -- not because they are
    broken (`pytest -q` there is 26 passed) but because importlib does not put a
    file's own directory on sys.path the way pytest does, so their `import conftest`
    raised, while conftest.py is present.

    The fix is NOT to put each file's directory on sys.path during the load. That
    would make a sibling import succeed here and still fail in the pipeline, hiding
    exactly the defect the UNLOADABLE category exists to catch. A pytest module is
    instead excluded by name -- and because a name-based exclusion could in principle
    drop something judgeable, this reads the SOURCE of every excluded file and the
    run fails if any of them defines a transform. Measured 2026-09-22: 5 excluded,
    0 smuggled, and the finding count is unchanged by the exclusion.
    """
    out = []
    for p in _candidate_files():
        if not TEST_MODULE.match(p.name):
            continue
        if DEF_TRANSFORM.search(p.read_text(encoding="utf-8", errors="replace")):
            out.append(str(p.relative_to(ROOT)))
    return sorted(out)


def census(files=None) -> dict:
    """{rel_path: {case: [keys]}} for every file that asserts something from nothing."""
    warnings.filterwarnings("ignore")
    findings: dict[str, dict[str, list[str]]] = {}
    unloadable: dict[str, str] = {}
    judged = 0
    files = files if files is not None else transform_files()
    for i, path in enumerate(files):
        rel = str(path.relative_to(ROOT))
        try:
            spec = importlib.util.spec_from_file_location(f"_fc_{i}", path)
            module = importlib.util.module_from_spec(spec)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                spec.loader.exec_module(module)
        except Exception as exc:
            unloadable[rel] = f"{type(exc).__name__}: {exc}"
            continue
        if not callable(getattr(module, "transform", None)):
            continue
        judged += 1
        per_case: dict[str, list[str]] = {}
        for case, body in NO_EVIDENCE.items():
            try:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    result = module.transform(body)
            except Exception:
                # raising is fail-closed: the pipeline records a transformation error
                continue
            keys = satisfaction_keys_true(result)
            if keys:
                per_case[case] = keys
        if per_case:
            findings[rel] = per_case
    return {"findings": findings, "unloadable": unloadable, "examined": len(files), "judged": judged}


def load_allowlist() -> dict:
    if not ALLOWLIST.is_file():
        return {"instances": [], "entries": {}}
    return json.loads(ALLOWLIST.read_text())


def emit_allowlist() -> dict:
    result = census()
    instances = sorted(result["findings"])
    out = {
        "contract": "fail-closed",
        "why": "no transformation may assert a satisfaction-style criterion true from a "
               "body that proves nothing; this list may only shrink",
        "generated_by": "tools/check_fail_closed.py --emit-allowlist",
        "count": len(instances),
        "instances": instances,
    }
    ALLOWLIST.parent.mkdir(parents=True, exist_ok=True)
    ALLOWLIST.write_text(json.dumps(out, indent=2) + "\n")
    return out


def self_test() -> int:
    """Plant a transform with the exact defect and prove the checker names it."""
    import tempfile
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        d = pathlib.Path(tmp)
        planted = d / "isplanteddefect.py"
        planted.write_text(
            "def transform(input):\n"
            "    data = input if isinstance(input, dict) else {}\n"
            "    return {'isPlantedDefect': data.get('x', data is not None)}\n"
        )
        clean = d / "iscleancontrol.py"
        clean.write_text(
            "def transform(input):\n"
            "    data = input if isinstance(input, dict) else {}\n"
            "    return {'isCleanControl': bool(data.get('x'))}\n"
        )
        inverted = d / "isinvertedkey.py"
        inverted.write_text(
            "def transform(input):\n"
            "    return {'localLoginAllowed': True}\n"
        )
        # a genuine pytest module: imports a sibling the way the sonicwall suite does,
        # defines no transform, and must be excluded rather than reported UNLOADABLE
        (d / "conftest.py").write_text("HELPER = 1\n")
        test_mod = d / "test_something.py"
        test_mod.write_text(
            "import conftest\n"
            "def transformation():\n"
            "    return conftest.HELPER\n"
        )
        # a pytest-named file that DOES define a transform: the exclusion must not
        # silently swallow it
        smuggler = d / "test_smuggled.py"
        smuggler.write_text(
            "def transform(input):\n"
            "    return {'isSmuggled': True}\n"
        )
        global SAFEGUARDS, ROOT
        saved_s, saved_r = SAFEGUARDS, ROOT
        SAFEGUARDS, ROOT = d, d
        try:
            result = census()
            found = result["findings"]
            walked = {p.name for p in transform_files()}
            unloadable = result["unloadable"]
            smuggled = smuggled_transforms()
        finally:
            SAFEGUARDS, ROOT = saved_s, saved_r
        if "isplanteddefect.py" not in found:
            failures.append("a planted `data is not None` default was NOT caught")
        if "iscleancontrol.py" in found:
            failures.append("a clean fail-closed transform was wrongly flagged")
        if "isinvertedkey.py" in found:
            failures.append("an INVERTED key (true == insecure) was wrongly flagged")
        if "test_something.py" in walked or "conftest.py" in walked:
            failures.append("a pytest module was walked as a transform")
        if unloadable:
            failures.append(
                "a pytest module importing a present sibling was reported UNLOADABLE: "
                + ", ".join(sorted(unloadable))
            )
        if "isplanteddefect.py" not in walked:
            failures.append("the pytest exclusion also dropped a real transform")
        if smuggled != ["test_smuggled.py"]:
            failures.append(
                "a file excluded as a pytest module that DEFINES a transform was not "
                f"caught; smuggled_transforms() returned {smuggled!r}"
            )
    # R: a COLLAPSED real corpus must be refused, not reported as clean. This is the one
    # rule the rest of the self-test structurally cannot cover: every other rule runs
    # against a corpus this function builds itself, which is exactly the shape of a walk
    # that has stopped reading the tree.
    with tempfile.TemporaryDirectory() as tmp:
        d = pathlib.Path(tmp)
        (d / "iscleancontrol.py").write_text(
            "def transform(input):\n"
            "    data = input if isinstance(input, dict) else {}\n"
            "    return {'isCleanControl': bool(data.get('x'))}\n"
        )
        saved_s, saved_r = SAFEGUARDS, ROOT
        saved_argv = sys.argv
        SAFEGUARDS, ROOT = d, d
        sys.argv = ["check_fail_closed.py"]
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main()
            said = buf.getvalue()
        finally:
            SAFEGUARDS, ROOT, sys.argv = saved_s, saved_r, saved_argv
        if rc == 0:
            failures.append(
                "a corpus of 1 transform -- a collapsed walk -- exited 0 instead of "
                "being refused"
            )
        elif "REFUSING TO REPORT" not in said:
            failures.append(
                "a collapsed corpus was non-zero but did not say why; it printed: "
                + said.strip().splitlines()[0] if said.strip() else "(nothing)"
            )

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

    smuggled = smuggled_transforms()
    if smuggled:
        print("✗ a file excluded as a pytest module defines a transform, so the "
              "name-based exclusion is dropping something this gate must judge:")
        for rel in smuggled:
            print(f"  {rel}")
        return 1

    result = census()
    if result["judged"] < MIN_JUDGED_TRANSFORMS:
        print(
            f"✗ REFUSING TO REPORT: only {result['judged']} file(s) with a callable "
            f"transform were found under {SAFEGUARDS}, below the floor of "
            f"{MIN_JUDGED_TRANSFORMS}. A clean tree and a tree this checker has stopped "
            "reading both print zero findings, so a collapsed walk is refused rather "
            "than reported as a pass."
        )
        return 1
    findings, unloadable = result["findings"], result["unloadable"]
    allowed = set(load_allowlist().get("instances", []))
    new = sorted(set(findings) - allowed)
    stale = sorted(allowed - set(findings))

    # "examined" is the walk; "judged" is how many of those actually defined a callable
    # transform and were run against the battery. Printing only the first would let a
    # tree full of unjudgeable files read as a clean one.
    print(f"{result['examined']} transform file(s) examined, {result['judged']} judged; "
          f"{len(findings)} assert a satisfaction-style criterion true from a body that "
          f"proves nothing ({len(new)} outside the allowlist)")
    if unloadable:
        print(f"\nUNLOADABLE ({len(unloadable)}) -- cannot be judged, and cannot run in the pipeline either:")
        for rel, why in sorted(unloadable.items()):
            print(f"  {rel}: {why}")
    if stale:
        print(f"\nSTALE allowlist entries ({len(stale)}) -- no longer reproduce; "
              f"remove to let the ratchet shrink:")
        for rel in stale:
            print(f"  {rel}")
    if new:
        print(f"\n✗ {len(new)} transform(s) not on the allowlist assert a control from nothing:")
        for rel in new:
            cases = findings[rel]
            detail = "; ".join(f"{c}->{','.join(ks)}" for c, ks in sorted(cases.items()))
            print(f"  {rel}: {detail}")
        return 1
    if unloadable:
        return 1
    print("\n✓ no unallowlisted transform asserts a control from a body that proves nothing")
    return 0


if __name__ == "__main__":
    sys.exit(main())
