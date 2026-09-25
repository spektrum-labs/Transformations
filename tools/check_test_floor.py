#!/usr/bin/env python3
"""Run the transformation unit tests, and refuse to pass vacuously.

WHY THIS WRAPPER EXISTS RATHER THAN A BARE `pytest` STEP. A pytest run that
collects fewer tests than it used to is indistinguishable, from the outside,
from a run where everything passed: both print a row of dots and exit 0. Delete
a test file, rename a directory out from under the path argument, or mark the
awkward cases skipped, and the job stays green while proving less. That is the
same defect as a gate that cannot fail -- the failure mode the rest of this
repo's contract checks exist to prevent -- so the count is asserted, not
assumed.

Measured on this branch 2026-09-22, Python 3.11.15, pytest 9.1.1:
`python -m pytest -q safeguards/` -> "71 passed". Same 71 under pytest 8.4.2.
FLOOR was 71. 2026-09-24: 83 passed under pytest 8.4.2 after the 12 Trend
Vision One tests; FLOOR is 83.
2026-09-25: 104 passed after the 21 OpenAI Administration API tests; FLOOR is 104. Raise it when tests are added; lowering it is a claim
that the suite should prove less, and wants a reason in the commit message.
"""

import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

# Measured 2026-09-22 (see module docstring). The suite may grow, never shrink.
FLOOR = 104

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTS_PATH = "safeguards/"

# The 5 sonicwall test files do `from conftest import ...`, which resolves only
# because the `prepend` import mode puts each test file's own directory on
# sys.path. Measured 2026-09-22 with --import-mode=importlib instead: "5 errors
# during collection". It is passed explicitly so that a future change to
# pytest's default cannot quietly decide this for us.
PYTEST_ARGS = [TESTS_PATH, "--import-mode=prepend", "-q"]


def verdict(counts, floor=FLOOR):
    """Return the list of reasons this run must not be called a pass."""
    problems = []
    if counts["errors"]:
        problems.append(
            "%d collection/setup error(s) -- a test that cannot be collected "
            "is not a test that passed" % counts["errors"]
        )
    if counts["failures"]:
        problems.append("%d test(s) failed" % counts["failures"])
    if counts["skipped"]:
        # Without this the count below is satisfiable by skipping everything:
        # junit's `tests` attribute counts skipped tests as collected.
        problems.append(
            "%d test(s) skipped -- a skipped test is not a passing test"
            % counts["skipped"]
        )
    if counts["tests"] < floor:
        problems.append(
            "collected %d test(s), floor is %d -- the suite got smaller, so "
            "this run proves less than the one that set the floor"
            % (counts["tests"], floor)
        )
    return problems


def _counts_from_junit(path):
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else root.findall("testsuite")
    if not suites:
        raise ValueError("no <testsuite> in %s" % path)
    totals = {"tests": 0, "errors": 0, "failures": 0, "skipped": 0}
    for suite in suites:
        for key in totals:
            totals[key] += int(suite.get(key, 0))
    return totals


def self_test():
    """Prove the floor logic still rejects what it is supposed to reject.

    Same reasoning as the self-tests on the other checkers in this directory: a
    guard that has quietly stopped guarding reports a clean tree forever.
    """
    at_floor = {"tests": FLOOR, "errors": 0, "failures": 0, "skipped": 0}
    cases = [
        ("exactly the floor, all green", at_floor, False),
        ("above the floor", dict(at_floor, tests=FLOOR + 3), False),
        ("one test short", dict(at_floor, tests=FLOOR - 1), True),
        ("nothing collected at all", dict(at_floor, tests=0), True),
        ("at the floor but all skipped", dict(at_floor, skipped=FLOOR), True),
        ("at the floor with a collection error", dict(at_floor, errors=1), True),
        ("at the floor with a failure", dict(at_floor, failures=1), True),
    ]
    bad = 0
    for name, counts, should_reject in cases:
        rejected = bool(verdict(counts))
        ok = rejected == should_reject
        bad += not ok
        print("  %-42s %s" % (name, "ok" if ok else "SELF-TEST BROKEN"))
    if bad:
        print("self-test: %d case(s) wrong -- the floor check is not guarding" % bad)
        return 1
    print("self-test: %d/%d cases behave as documented" % (len(cases), len(cases)))
    return 0


def main(argv):
    if "--self-test" in argv:
        return self_test()

    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "junit.xml"
        cmd = [sys.executable, "-m", "pytest"] + PYTEST_ARGS + [
            "--junit-xml=%s" % report
        ]
        print("$ " + " ".join(cmd))
        completed = subprocess.run(cmd, cwd=REPO_ROOT)

        if not report.exists():
            # pytest exits 5 with no report when it collected nothing at all.
            print(
                "\nFAIL: pytest wrote no report (exit %d). Nothing ran, so "
                "nothing was proved." % completed.returncode
            )
            return 1

        counts = _counts_from_junit(report)

    print(
        "\ncollected=%(tests)d failures=%(failures)d errors=%(errors)d "
        "skipped=%(skipped)d" % counts
        + " floor=%d" % FLOOR
    )

    problems = verdict(counts)
    if problems:
        print("\nFAIL:")
        for problem in problems:
            print("  - " + problem)
        return 1

    if completed.returncode != 0:
        # Counts looked fine but pytest still refused; do not paper over it.
        print("\nFAIL: pytest exited %d" % completed.returncode)
        return 1

    print("\nOK: %d tests ran and passed (floor %d)." % (counts["tests"], FLOOR))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
