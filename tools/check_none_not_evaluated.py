"""INVARIANT: a criterion a transform leaves as None must reach the evaluator as "not evaluated".

THE RULE. When a `transform()` returns a criterion's value as `None` -- "I could not
measure this" -- the same output must carry `additionalInfo.dataCollection.status ==
"error"`. Token-Service reads that status (`_data_collection_failure_message` in
src/utils/evaluate/evaluate.py) and records the criterion as NOT EVALUATED. Without it the
evaluator compares the `None` against the requirement, the comparison fails, and the result
is stored with `isEvaluated: True` -- a measured FAILED for a control nobody measured.

`create_response` sets that status from `api_errors`: the status is "error" only when
`api_errors` is non-empty. So a transform that returns `{key: None}` with fail reasons but no
api_errors, or a flat `{key: None, "reason": ...}` dict with no `additionalInfo` at all,
ships a false fail. This happened twice in one day in production (an identity provider's
strong-auth check and an XDR vendor's signature and critical-systems checks), each found
only after customers saw red.

WHAT IS JUDGED. Every transform is handed the no-evidence battery from
tools/check_fail_closed.py plus a few empty-collection shapes and one POISONED body -- a dict
whose every read raises -- which drives the transform down its `except` path. The exception
path is where this defect hides most often: `create_response(result={KEY: None},
transformation_errors=[str(e)])` records the error under `transformation`, not under
`dataCollection`, so the evaluator still grades the None.

WHICH KEYS. The criterion is the key named like the file (`isfoo.py` -> `isFoo`), the
repo's naming convention. A file whose name matches none of its output keys (a multi-key
transform such as `asm_transform.py`) has every criterion-shaped key judged: `is`/`are`/
`has`/`confirmed` prefixes and `Count`/`Percentage`/`Rate`/`Score`/`Allowed` suffixes.
Supporting fields (`httpStatus`, `lastSeen`, a percentage beside a boolean criterion) are
not judged when the file's own criterion is present, because the evaluator never compares
them.

THE RATCHET. Known instances live in contracts/none-not-evaluated-allowlist.json and MAY
ONLY SHRINK, exactly as in check_fail_closed.py. A listed file is reported and does not fail
the run; an unlisted one does; a listed entry that no longer reproduces is reported STALE.

Usage:
    python tools/check_none_not_evaluated.py                  # judge the tree
    python tools/check_none_not_evaluated.py --emit-allowlist # regenerate from the live tree
    python tools/check_none_not_evaluated.py --self-test      # prove the checker catches a planted defect
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

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import check_fail_closed as cfc  # noqa: E402  (shares the walk and the no-evidence battery)

ROOT = cfc.ROOT
ALLOWLIST = ROOT / "contracts" / "none-not-evaluated-allowlist.json"
MIN_JUDGED_TRANSFORMS = cfc.MIN_JUDGED_TRANSFORMS

CRITERION_SHAPE = re.compile(r"^(is|are|has|confirmed?)[A-Z]|(Count|Percentage|Rate|Score|Allowed)$")


class PoisonedBody(dict):
    """A non-empty object whose every read raises: it reaches the transform's except path."""

    def __init__(self):
        super().__init__(poisoned=True)

    def _boom(self, *args, **kwargs):
        raise RuntimeError("poisoned read")

    get = __getitem__ = __contains__ = keys = items = values = __iter__ = _boom

    def __len__(self):
        return 1


def battery() -> dict:
    cases = {name: (lambda body=body: json.loads(json.dumps(body)) if body is not None else None)
             for name, body in cfc.NO_EVIDENCE.items()}
    for name, body in {
        "empty_list": [],
        "list_of_empty": [{}],
        "data_empty": {"data": []},
        "items_empty": {"items": []},
        "value_empty": {"value": []},
        "results_empty": {"results": []},
        "response_empty": {"response": {}},
    }.items():
        cases[name] = (lambda body=body: json.loads(json.dumps(body)))
    cases["poisoned"] = PoisonedBody
    return cases


def unmeasured_criteria(path: pathlib.Path, out) -> list[str]:
    """Criterion keys this output leaves None without a dataCollection error."""
    if not isinstance(out, dict):
        return []
    inner = out.get("transformedResponse", out)
    if not isinstance(inner, dict):
        return []
    additional = out.get("additionalInfo")
    collection = additional.get("dataCollection") if isinstance(additional, dict) else None
    if isinstance(collection, dict) and str(collection.get("status") or "").lower() == "error":
        return []
    stem = path.stem.lower()
    named = [k for k in inner if isinstance(k, str) and k.lower() == stem]
    judged = named or [k for k in inner if isinstance(k, str) and CRITERION_SHAPE.search(k)]
    return sorted(k for k in judged if inner[k] is None)


def census(files=None) -> dict:
    warnings.filterwarnings("ignore")
    findings: dict[str, dict[str, list[str]]] = {}
    unloadable: dict[str, str] = {}
    judged = 0
    files = files if files is not None else cfc.transform_files()
    cases = battery()
    for i, path in enumerate(files):
        rel = str(path.relative_to(cfc.ROOT))
        try:
            spec = importlib.util.spec_from_file_location(f"_nne_{i}", path)
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
        for case, make in cases.items():
            try:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    out = module.transform(make())
            except Exception:
                continue  # raising is fail-closed: the pipeline records a transformation error
            keys = unmeasured_criteria(path, out)
            if keys:
                per_case[case] = keys
        if per_case:
            findings[rel] = per_case
    return {"findings": findings, "unloadable": unloadable, "examined": len(files), "judged": judged}


def load_allowlist() -> dict:
    if not ALLOWLIST.is_file():
        return {"instances": []}
    return json.loads(ALLOWLIST.read_text())


def emit_allowlist() -> dict:
    result = census()
    instances = sorted(result["findings"])
    out = {
        "contract": "none-not-evaluated",
        "why": "a criterion returned as None must carry additionalInfo.dataCollection.status "
               "\"error\" so the evaluator records it as not evaluated rather than failed; "
               "this list may only shrink",
        "generated_by": "tools/check_none_not_evaluated.py --emit-allowlist",
        "count": len(instances),
        "instances": instances,
    }
    ALLOWLIST.parent.mkdir(parents=True, exist_ok=True)
    ALLOWLIST.write_text(json.dumps(out, indent=2) + "\n")
    return out


def self_test() -> int:
    import tempfile
    failures = []
    planted = {
        # create_response-style: fail reasons, no api_errors -> dataCollection "success"
        "isplantedenvelope.py": (
            "def transform(input):\n"
            "    return {'transformedResponse': {'isPlantedEnvelope': None},\n"
            "            'additionalInfo': {'dataCollection': {'status': 'success', 'errors': []}}}\n"
        ),
        # flat legacy dict with a reason and nothing the evaluator reads
        "plantedflatcount.py": (
            "def transform(input):\n"
            "    return {'plantedFlatCount': None, 'reason': 'no data'}\n"
        ),
        # correct on the battery, wrong on its except path
        "isplantedexcept.py": (
            "def transform(input):\n"
            "    try:\n"
            "        data = input if isinstance(input, dict) else {}\n"
            "        if not data.get('ok'):\n"
            "            return {'transformedResponse': {'isPlantedExcept': None},\n"
            "                    'additionalInfo': {'dataCollection': {'status': 'error', 'errors': ['x']}}}\n"
            "        return {'transformedResponse': {'isPlantedExcept': True}}\n"
            "    except Exception as e:\n"
            "        return {'transformedResponse': {'isPlantedExcept': None},\n"
            "                'additionalInfo': {'dataCollection': {'status': 'success', 'errors': []},\n"
            "                                   'transformation': {'status': 'error', 'errors': [str(e)]}}}\n"
        ),
        # multi-key transform whose file name matches no key
        "planted_transform.py": (
            "def transform(input):\n"
            "    return {'transformedResponse': {'isPlantedMulti': None, 'note': None}}\n"
        ),
    }
    clean = {
        # None WITH a dataCollection error: exactly what the evaluator needs
        "iscleannone.py": (
            "def transform(input):\n"
            "    return {'transformedResponse': {'isCleanNone': None},\n"
            "            'additionalInfo': {'dataCollection': {'status': 'error', 'errors': ['no data']}}}\n"
        ),
        # a measured criterion beside a None supporting field
        "iscleanaux.py": (
            "def transform(input):\n"
            "    return {'transformedResponse': {'isCleanAux': False, 'httpStatus': None, 'lastSeenCount': None}}\n"
        ),
        # raising is fail-closed
        "iscleanraise.py": (
            "def transform(input):\n"
            "    raise ValueError('unreadable')\n"
        ),
    }
    with tempfile.TemporaryDirectory() as tmp:
        d = pathlib.Path(tmp)
        for name, src in {**planted, **clean}.items():
            (d / name).write_text(src)
        saved = cfc.SAFEGUARDS, cfc.ROOT
        cfc.SAFEGUARDS, cfc.ROOT = d, d
        try:
            found = census()["findings"]
        finally:
            cfc.SAFEGUARDS, cfc.ROOT = saved
    for name in planted:
        if name not in found:
            failures.append(f"planted defect {name} was NOT caught")
    if "isplantedexcept.py" in found and set(found["isplantedexcept.py"]) != {"poisoned"}:
        failures.append(f"isplantedexcept.py should fail only on the poisoned body, got {sorted(found['isplantedexcept.py'])}")
    if "planted_transform.py" in found and any("note" in ks for ks in found["planted_transform.py"].values()):
        failures.append("a non-criterion supporting field was judged on a multi-key transform")
    for name in clean:
        if name in found:
            failures.append(f"clean transform {name} was wrongly flagged: {found[name]}")

    # a collapsed walk must be refused, not reported clean
    with tempfile.TemporaryDirectory() as tmp:
        d = pathlib.Path(tmp)
        (d / "iscleannone.py").write_text(clean["iscleannone.py"])
        saved = cfc.SAFEGUARDS, cfc.ROOT
        saved_argv = sys.argv
        cfc.SAFEGUARDS, cfc.ROOT = d, d
        sys.argv = ["check_none_not_evaluated.py"]
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main()
        finally:
            cfc.SAFEGUARDS, cfc.ROOT = saved
            sys.argv = saved_argv
        if rc == 0 or "REFUSING TO REPORT" not in buf.getvalue():
            failures.append("a corpus of 1 transform -- a collapsed walk -- was not refused")

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
    if result["judged"] < MIN_JUDGED_TRANSFORMS:
        print(f"✗ REFUSING TO REPORT: only {result['judged']} file(s) with a callable transform "
              f"were found, below the floor of {MIN_JUDGED_TRANSFORMS}. A clean tree and a tree "
              "this checker has stopped reading both print zero findings.")
        return 1
    findings, unloadable = result["findings"], result["unloadable"]
    allowed = set(load_allowlist().get("instances", []))
    new = sorted(set(findings) - allowed)
    stale = sorted(allowed - set(findings))
    print(f"{result['examined']} transform file(s) examined, {result['judged']} judged; "
          f"{len(findings)} return a criterion as None without a dataCollection error "
          f"({len(new)} outside the allowlist)")
    if unloadable:
        print(f"\nUNLOADABLE ({len(unloadable)}) -- reported by check_fail_closed.py, not judged here:")
        for rel, why in sorted(unloadable.items()):
            print(f"  {rel}: {why}")
    if stale:
        print(f"\nSTALE allowlist entries ({len(stale)}) -- no longer reproduce; remove to let the ratchet shrink:")
        for rel in stale:
            print(f"  {rel}")
    if new:
        print(f"\n✗ {len(new)} transform(s) not on the allowlist return a criterion as None that "
              "Token-Service will grade as FAILED (give the None path a non-empty api_errors, or "
              "for a flat dict an additionalInfo.dataCollection with status \"error\"):")
        for rel in new:
            detail = "; ".join(f"{c}->{','.join(ks)}" for c, ks in sorted(findings[rel].items()))
            print(f"  {rel}: {detail}")
        return 1
    print("\n✓ every unallowlisted None criterion reaches the evaluator as not evaluated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
