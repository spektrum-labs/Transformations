"""INVARIANT: a criterion may not be read out of the body it is meant to judge.

THE RULE. A transform is handed a vendor's API response and must decide something about it.
If it answers criterion X by reading a field literally named X out of that response, it has
asked the question of the answer. The vendor does not send `isFirewallEnabled`; nothing does.
Whatever such a line evaluates to is a property of our own default, not of the customer's
estate.

WHY THIS IS A DIFFERENT DEFECT FROM THE FOUR EXISTING CONTRACTS, none of which sees it:

  * check_fail_closed asks "does it answer the safe answer from a body proving nothing?" A
    self-answer with `default=False` answers the UNSAFE answer, so it sails through.
  * check_discriminates asks "is there any input making it false?" A self-answer is perfectly
    discriminating against a synthetic body that contains the invented field -- feed it
    `{"isFirewallEnabled": true}` and it says true, feed it `{}` and it says false. It looks
    like a model citizen.
  * check_sandbox_compile and check_none_not_evaluated are about form, not meaning.

That is the general shape and it is worth stating plainly: a checker that builds its own input
cannot detect a transform reading a field no vendor sends, because the checker invents exactly
the field the transform invented. Only the vendor's published schema, or this syntactic rule,
reaches it.

MEASURED 2026-10-06 across production main: 13 live instances. Four answer `isFirewallEnabled`
with `data.get('isFirewallEnabled', False)` -- unconditionally false, so every Fortinet,
Cloudflare and Cisco FMC customer is told their firewall is off, masked only by those
integrations having no category. One, NinjaOne's `isSSOEnabled`, falls back to
`affirmative_signal(data)` instead of False, so it resolves to "the endpoints API returned some
records" -- a false PASS on a verified integration.

WHAT IS NOT A FINDING, and why the allowlist is adjudicated rather than inferred:

  * A line of this shape that is genuinely dead -- OR'd with a real parse that always runs --
    is harmless. Cato Networks is the live example: the expression is there, and it is unioned
    with a real read of both policy layers, so the criterion discriminates correctly. A
    syntactic rule cannot see reachability, so such a file belongs in the allowlist WITH A
    REASON. Rewriting it as a self-answer stub would replace a working transform with a broken
    one.
  * A vendor that really does return a field of that name. None is known, and the claim needs
    the vendor's published schema rather than a sample body -- a body we construct contains
    whatever our code reads, which is the trap above.

USAGE
    python tools/check_no_self_answer.py
    python tools/check_no_self_answer.py --self-test
    python tools/check_no_self_answer.py --emit-allowlist
"""
from __future__ import annotations

import argparse
import ast
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SAFEGUARDS = ROOT / "safeguards"
ALLOWLIST = ROOT / "contracts" / "no-self-answer-allowlist.json"

#: Same floor the sibling checkers use. A walk that has collapsed and a clean tree both print
#: zero findings; refusing a short walk is the difference between them.
MIN_JUDGED_TRANSFORMS = 400

#: Accessors whose first argument is a key name.
_KEY_READERS = ("get", "setdefault", "pop")


#: Verdict-shaped prefixes. A criteria key spelled this way is OUR vocabulary for a
#: conclusion, not a vendor's vocabulary for a value.
_VERDICT_PREFIXES = ("is", "are", "has", "can", "was", "should", "confirmed")


def _is_criteria_key(name: str) -> bool:
    """Verdict-shaped criteria keys only -- isX / areX / hasX, not xCount / xPercentage.

    WHY VALUE-SHAPED KEYS ARE EXCLUDED, which is the difference between a checker people read
    and one they mute. Measured on main: 69 files answer a criterion by reading a field of the
    same name out of the vendor body. 36 are verdict-shaped; 33 are value-shaped, and those are
    mostly legitimate -- `scoreInPercentage` really is what Microsoft Secure Score returns, and
    `wanFirewallRuleCount`, `iosCount` and `allowRuleCount` are all plausible vendor fields.

    The shape is what separates them. A vendor sends you a number and you name it; a vendor does
    not send you `isFirewallEnabled`, because that is the conclusion you were hired to reach.
    So a self-read of a verdict-shaped key is a defect on its face, and a self-read of a
    value-shaped key needs the vendor's published schema to adjudicate -- which this checker
    cannot do and therefore does not pretend to.
    """
    if not name or not name.isidentifier() or "_" in name or len(name) < 5:
        return False
    return name.startswith(_VERDICT_PREFIXES)


def _input_derived_names(tree: ast.AST) -> set[str]:
    """Local names that hold the vendor body, transitively.

    Starts from the `transform(input)` parameter and follows assignments whose right-hand side
    mentions a name already known to be input-derived -- so `data = parse_input(input)` and
    `items = data.get("items")` both join the set.

    THIS DISTINCTION IS THE WHOLE CHECKER. Without it the rule fires on every transform that
    builds a result dict and reads a value back out of it -- `scoreInPercentage`,
    `protectedItemsCount`, `avgWeightedScore` -- which is ordinary plumbing and not a defect.
    Measured: 76 files flagged without this filter, 13 with it. A checker that reports 76 when
    13 are real does not get read.
    """
    derived = {"input"}
    for fn in (n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
        for arg in fn.args.args:
            if arg.arg in ("input", "api_response", "response", "data"):
                derived.add(arg.arg)
    # Two passes: an assignment can precede the one that made its source input-derived.
    for _ in range(2):
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            value = node.value
            if value is None:
                continue
            # A dict/list the transform CONSTRUCTS is not the vendor body, however much
            # input-derived data went into it. Without this, `out = {...data.get("x")...}`
            # makes `out` look like the body and every read-back of a result key is flagged.
            if isinstance(value, (ast.Dict, ast.DictComp, ast.List, ast.ListComp)):
                continue
            mentioned = {n.id for n in ast.walk(value) if isinstance(n, ast.Name)}
            if not (mentioned & derived):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                for sub in ast.walk(t):
                    if isinstance(sub, ast.Name):
                        derived.add(sub.id)
    return derived


def answered_and_read(source: str) -> set[str]:
    """Criteria keys this module both ANSWERS and READS out of the vendor body.

    Answered: the key appears as a literal dict key, a subscript target, or an upper-case module
    constant -- the shapes a transform uses to build its result. Read: the key is the first
    argument to a `.get()`-style accessor **on an input-derived name**. The intersection is the
    defect; either alone is ordinary.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()

    derived = _input_derived_names(tree)
    answered: set[str] = set()
    read: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for k in node.keys:
                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                    answered.add(k.value)
        elif isinstance(node, ast.Subscript):
            s = node.slice
            if isinstance(s, ast.Constant) and isinstance(s.value, str):
                answered.add(s.value)
        elif isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Attribute) and fn.attr in _KEY_READERS and node.args:
                receiver = fn.value
                if isinstance(receiver, ast.Name) and receiver.id not in derived:
                    continue
                if not isinstance(receiver, (ast.Name, ast.Subscript, ast.Call, ast.Attribute)):
                    continue
                if isinstance(receiver, (ast.Subscript, ast.Call, ast.Attribute)):
                    names = {n.id for n in ast.walk(receiver) if isinstance(n, ast.Name)}
                    if not (names & derived):
                        continue
                a0 = node.args[0]
                if isinstance(a0, ast.Constant) and isinstance(a0.value, str):
                    read.add(a0.value)
        elif isinstance(node, ast.Assign):
            # `CRITERIA_KEY = "isFirewallEnabled"` then `{CRITERIA_KEY: ...}` -- the constant
            # is the answer even though the dict key is a Name rather than a literal.
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                for t in node.targets:
                    if isinstance(t, ast.Name) and t.id.isupper():
                        answered.add(node.value.value)

    return {k for k in answered & read if _is_criteria_key(k)}


def census() -> dict:
    findings: dict[str, list[str]] = {}
    files = sorted(
        p for p in SAFEGUARDS.rglob("*.py")
        if "schemas" not in p.parts and not p.name.startswith(("test_", "conftest"))
    )
    judged = 0
    for path in files:
        try:
            source = path.read_text(encoding="utf-8")
        except OSError:
            continue
        judged += 1
        hits = answered_and_read(source)
        if hits:
            findings[str(path.relative_to(ROOT))] = sorted(hits)
    return {"findings": findings, "examined": len(files), "judged": judged}


def load_allowlist() -> dict:
    if not ALLOWLIST.is_file():
        return {"instances": []}
    return json.loads(ALLOWLIST.read_text())


def emit_allowlist() -> dict:
    result = census()
    instances = sorted(result["findings"])
    out = {
        "contract": "no-self-answer",
        "why": "a transform may not answer criterion X by reading a field named X out of the "
               "vendor body it is judging; this list may only shrink",
        "generated_by": "tools/check_no_self_answer.py --emit-allowlist",
        "how_to_exempt": "only when the line is provably unreachable -- OR'd with a real parse "
                         "that always runs -- or when the vendor's PUBLISHED SCHEMA documents a "
                         "field of that name. Record the reason. A body we construct contains "
                         "whatever our own code reads, so a sample body is not evidence.",
        "count": len(instances),
        "instances": instances,
    }
    ALLOWLIST.parent.mkdir(parents=True, exist_ok=True)
    ALLOWLIST.write_text(json.dumps(out, indent=2) + "\n")
    return out


def self_test() -> int:
    """Plant the defect, the correct shape, and the shape that merely looks like the defect.

    The third case is the one that matters. A checker tested only against a defect and a clean
    file passes whatever it was going to pass; asserting what it must NOT flag is what makes
    this a test rather than a snapshot.
    """
    cases = [
        (
            "self-answer is flagged",
            "def transform(input):\n"
            "    data = input if isinstance(input, dict) else {}\n"
            "    return {'isFirewallEnabled': True if data.get('isFirewallEnabled', False) else False}\n",
            {"isFirewallEnabled"},
        ),
        (
            "reading a real vendor field is not flagged",
            "def transform(input):\n"
            "    data = input if isinstance(input, dict) else {}\n"
            "    return {'isFirewallEnabled': bool(data.get('enforcementEnabled'))}\n",
            set(),
        ),
        (
            "answering and reading DIFFERENT keys is not flagged",
            "def transform(input):\n"
            "    data = input if isinstance(input, dict) else {}\n"
            "    return {'isEDRDeployed': bool(data.get('isEPPDeployed'))}\n",
            {"isEDRDeployed", "isEPPDeployed"} & set(),
        ),
        (
            "a value-shaped key of the same name is NOT flagged",
            "def transform(input):\n"
            "    data = input if isinstance(input, dict) else {}\n"
            "    return {'scoreInPercentage': data.get('scoreInPercentage', 0.0)}\n",
            set(),
        ),
        (
            "a result dict read back is NOT flagged",
            "def transform(input):\n"
            "    data = input if isinstance(input, dict) else {}\n"
            "    out = {'isEPPEnabled': bool(data.get('agents'))}\n"
            "    return {'isEPPEnabled': out.get('isEPPEnabled')}\n",
            set(),
        ),
        (
            "a non-criteria key of the same name is not flagged",
            "def transform(input):\n"
            "    data = input if isinstance(input, dict) else {}\n"
            "    return {'items': data.get('items')}\n",
            set(),
        ),
        (
            "the key reached through a module constant is flagged",
            "CRITERIA_KEY = 'isMFAEnabled'\n"
            "def transform(input):\n"
            "    data = input if isinstance(input, dict) else {}\n"
            "    return {CRITERIA_KEY: data.get('isMFAEnabled')}\n",
            {"isMFAEnabled"},
        ),
    ]
    bad = 0
    for name, src, expected in cases:
        got = answered_and_read(src)
        if got != expected:
            print(f"  FAIL self-test: {name} -> {sorted(got)}, expected {sorted(expected)}")
            bad += 1
        else:
            print(f"  ok: {name}")
    if bad:
        print(f"\n✗ {bad} self-test(s) failed -- the checker cannot be trusted")
        return 1
    print("\n✓ self-tests pass")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--emit-allowlist", action="store_true")
    a = ap.parse_args()

    if a.self_test:
        return self_test()
    if a.emit_allowlist:
        out = emit_allowlist()
        print(f"wrote {out['count']} instance(s) to {ALLOWLIST.relative_to(ROOT)}")
        return 0

    result = census()
    if result["judged"] < MIN_JUDGED_TRANSFORMS:
        print(
            f"✗ only {result['judged']} transform(s) judged, below the floor of "
            f"{MIN_JUDGED_TRANSFORMS}. A collapsed walk is refused rather than reported as a "
            "pass, because a clean tree and a tree this checker has stopped reading both print "
            "zero findings."
        )
        return 1

    findings = result["findings"]
    allowed = set(load_allowlist().get("instances", []))
    new = sorted(set(findings) - allowed)
    stale = sorted(allowed - set(findings))

    print(f"{result['examined']} transform file(s) examined, {result['judged']} judged; "
          f"{len(findings)} answer a criterion by reading a field of the same name out of the "
          f"body they judge ({len(new)} outside the allowlist)")

    if stale:
        print(f"\nSTALE allowlist entries ({len(stale)}) -- no longer reproduce; "
              f"remove to let the ratchet shrink:")
        for rel in stale:
            print(f"  {rel}")

    if new:
        print(f"\n✗ {len(new)} transform(s) not on the allowlist read their own answer out "
              f"of their own input:")
        for rel in new:
            print(f"  {rel}: {', '.join(findings[rel])}")
        print("\nThe vendor does not send these fields. Read what the vendor documents, or "
              "return None with api_errors if it documents nothing that evidences the control.")
        return 1

    print("\n✓ no unallowlisted transform answers a criterion out of its own input")
    return 0


if __name__ == "__main__":
    sys.exit(main())
