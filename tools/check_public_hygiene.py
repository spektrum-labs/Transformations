#!/usr/bin/env python3
"""Public-repository hygiene: a change may not ADD lines that carry internal wording.

This repository is public. Wording that only makes sense inside the company (internal
planning labels, nicknames for groups of customers) must not be added to code, tests,
fixtures, comments or documentation. This check reads the unified diff of a change and
looks only at the lines the change ADDS, so wording that is already in the tree, and
removed or untouched lines, never fail it.

A listed word matches at a word or camelCase boundary, case-insensitively:
    standalone, Capitalised, ALL_CAPS, snake_case parts and camelCase parts all match;
    the same letters inside a longer word do not (a name that merely ends in the letters
    of a listed word, or an all-caps word that continues past them, is a different word).
The words are held as fragments below so that this file does not contain them and does
not trip itself.

A short list of existing identifiers that cannot be renamed is exempt, by exact token only.

The failure message names file:line and the matched text, and never prints the line,
because CI logs of a public repository are public too.

Usage:
    python tools/check_public_hygiene.py --base <ref-or-sha>   # diff <base> against HEAD
    python tools/check_public_hygiene.py --self-test

Exit 0: no added line matches. Exit 1: at least one does. Exit 2: the diff could not be read.
"""
import argparse
import os
import re
import subprocess
import sys
import tempfile

# One constant, so the list can change in one place. Fragments, not whole words (see above).
WORD_FRAGMENTS = (
    ("es", "tate"),
    ("tw", "in"),
    ("mi", "ni"),
    ("wa", "ve"),
    ("la", "ne"),
)
WORDS = tuple("".join(parts) for parts in WORD_FRAGMENTS)

# Identifiers that already exist in the tree and cannot be renamed (workflow names and keys
# that other systems read, and helpers that carry them). EXACT tokens only: a token is the whole
# run of letters, digits and underscores around the match, so a longer identifier that merely
# contains one of these, or any other spelling of it, is still flagged. Fragments again, so this
# file does not contain the listed words. Add to this list only for an identifier that is already
# on the base branch and is part of an interface; reword everything else.
_E = "es" + "tate"
_C = "Es" + "tate"
ALLOWED_TOKENS = frozenset((
    "get" + _C + "MFAStatus",
    "get" + _C + "MfaStatus",
    "get" + _C + "SecondFactors",
    _E + "WideLimits",
    _E + "_wide",
    "password_" + _E + "_wide",
    "load_" + _E,
    _E.upper() + "_TARGETS",
))
TOKEN = re.compile(r"[A-Za-z0-9_]+")

HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/~^@{}-]*$")
ZERO_SHA = re.compile(r"^0+$")


def _left_ok(text, i):
    if i == 0:
        return True
    prev = text[i - 1]
    return (not prev.isalpha()) or (prev.islower() and text[i].isupper())


def _right_ok(text, i, j):
    if j >= len(text):
        return True
    nxt = text[j]
    if not nxt.isalpha():
        return True
    if not nxt.isupper():
        return False
    # An upper-case letter follows. For camelCase that starts a new word. For an
    # ALL-CAPS match it only does so when it opens a Capitalised word, not when the capitals continue.
    allcaps = text[i:j].isupper()
    after = text[j + 1] if j + 1 < len(text) else ""
    return (not allcaps) or (not after.isalpha()) or after.islower()


def _token_at(text, i):
    """The whole identifier-like run (letters, digits, underscores) that contains column i."""
    for m in TOKEN.finditer(text):
        if m.start() <= i < m.end():
            return m.group(0)
    return ""


def find_words(text, words=WORDS, allowed=ALLOWED_TOKENS):
    """[(column, matched text)] for every listed word in text at a word or camelCase boundary,
    except where the whole token around the match is an exact entry of the allowed set."""
    low = text.lower()
    found = []
    for word in words:
        start = 0
        while True:
            i = low.find(word, start)
            if i < 0:
                break
            start = i + 1
            j = i + len(word)
            if _left_ok(text, i) and _right_ok(text, i, j) and _token_at(text, i) not in allowed:
                found.append((i, text[i:j]))
    return sorted(found)


def scan_patch(patch):
    """[(path, line number, matched text)] for every ADDED line of a -U0 unified diff."""
    hits = []
    path = None
    lineno = 0
    for raw in patch.splitlines():
        if raw.startswith("+++ "):
            target = raw[4:]
            path = None if target == "/dev/null" else (target[2:] if target.startswith("b/") else target)
            continue
        if raw.startswith("--- ") or raw.startswith("diff ") or raw.startswith("index "):
            continue
        m = HUNK.match(raw)
        if m:
            lineno = int(m.group(1)) - 1
            continue
        if raw.startswith("+") and path is not None:
            lineno += 1
            for _col, matched in find_words(raw[1:]):
                hits.append((path, lineno, matched))
    return hits


def read_patch(base, cwd):
    if not SAFE_REF.match(base):
        raise ValueError("unsafe base ref")
    if ZERO_SHA.match(base):
        base = "HEAD^1"
    cmd = ["git", "-c", "core.quotepath=off", "diff", "--no-color", "--no-ext-diff", "--no-renames",
           "-U0", "--diff-filter=AM", base, "HEAD", "--"]
    done = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, errors="replace")
    if done.returncode != 0:
        raise RuntimeError("git diff failed (is the base commit fetched? use a full-depth checkout): "
                           + done.stderr.strip()[:200])
    return done.stdout


def report(hits, out):
    for path, line, matched in hits:
        out.write("%s:%d: contains \"%s\"; reword this line (internal wording is not allowed in this public "
                  "repository)\n" % (path, line, matched))
    if hits:
        out.write("%d added line(s) need rewording.\n" % len(hits))


def run(base, cwd=None, out=None):
    out = out or sys.stdout
    try:
        patch = read_patch(base, cwd)
    except (ValueError, RuntimeError, OSError) as exc:
        out.write("cannot read the diff: %s\n" % exc)
        return 2
    hits = scan_patch(patch)
    report(hits, out)
    if not hits:
        out.write("ok: no added line carries internal wording\n")
    return 1 if hits else 0


# ---------------------------------------------------------------------------------------------- self-test

def _w(i):
    return WORDS[i]


def _fixtures():
    e, tw, mi, wv, ln = (_w(i) for i in range(5))
    fail = [
        e, e.capitalize(), e.upper(), e + "Wide", e.upper() + "_X", "load_" + e + "_x", "x" + "load_" + e,
        "my" + e.capitalize(), "the whole " + e + " is", e.upper() + "Wide", "x_" + e + "_y", "(" + e + ")", "2" + e,
        "get" + e.capitalize() + "MFAStatusV2", "get" + e.capitalize() + "OtherThing", e + "WideLimitsX",
        tw, tw.capitalize() + " PR", tw.upper() + "_PR", tw + "Branch", "a " + tw + " copy",
        mi, mi.capitalize(), mi.upper() + "_Y", wv, wv.capitalize() + " C status", ln, "the " + ln.capitalize(),
    ]
    ok = [
        "softDeleteState", "managedSoftwareUpdateComplianceState", "DeleteState", "isStateEnabled",
        "min" + "imum", "min" + "imal", "ad" + mi + "strator", "MINIMUM", "MINIMUM_VERSION", "ad" + mi.upper() + "STRATOR",
        "pl" + ln, "pl" + ln + "t", wv + "length", "bra" + wv + "s", e + "s", "real" + e.lower() + "ly",
        tw + "s", tw + "e", "be" + tw + "d",
        "plain text with no listed word", "",
    ]
    # Existing identifiers that cannot be renamed pass when they are the whole token.
    ok += sorted(ALLOWED_TOKENS)
    ok += ["call %s() here" % t for t in sorted(ALLOWED_TOKENS)]
    ok += ["x = {'%s': 1}" % t for t in sorted(ALLOWED_TOKENS)]
    return fail, ok


def _patch(path, start, added, removed=()):
    lines = ["diff --git a/%s b/%s" % (path, path), "--- a/%s" % path, "+++ b/%s" % path,
             "@@ -%d,%d +%d,%d @@" % (start, len(removed), start, len(added))]
    lines += ["-" + r for r in removed] + ["+" + a for a in added]
    return "\n".join(lines) + "\n"


def self_test():
    failures = []
    fail, ok = _fixtures()
    for text in fail:
        if not find_words(text):
            failures.append("not caught: %r" % text)
    for text in ok:
        got = find_words(text)
        if got:
            failures.append("false positive: %r -> %r" % (text, got))

    # Only ADDED lines count, with the right line numbers; removed lines, deleted files and
    # clean added lines do not.
    e = _w(0)
    patch = _patch("a/one.py", 10, ["clean line", "has " + e + " in it", "also clean", "x_" + e.upper()],
                   removed=["old " + e + " line"])
    patch += _patch("b/two.py", 1, ["nothing to see"])
    patch += "diff --git a/gone.py b/gone.py\n--- a/gone.py\n+++ /dev/null\n@@ -1,1 +0,0 @@\n-" + e + "\n"
    want = [("a/one.py", 11, e), ("a/one.py", 13, e.upper())]
    got = scan_patch(patch)
    if got != want:
        failures.append("scan_patch: expected %r, got %r" % (want, got))
    if scan_patch(_patch("c.py", 1, ["clean"], removed=["old " + e])):
        failures.append("removed line was flagged")

    # End to end through git: a word already on the base is not flagged; a word added later is,
    # at the right file and line.
    with tempfile.TemporaryDirectory() as repo:
        env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)

        def git(*args):
            return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                                   "-c", "commit.gpgsign=false"] + list(args), cwd=repo, env=env,
                                  capture_output=True, text=True)

        git("init", "-q")
        with open(os.path.join(repo, "old.txt"), "w") as fh:
            fh.write("already here: " + e + "\nclean\n")
        git("add", "-A")
        git("commit", "-q", "-m", "base")
        base = git("rev-parse", "HEAD").stdout.strip()
        with open(os.path.join(repo, "old.txt"), "a") as fh:
            fh.write("a new clean line\n")
        with open(os.path.join(repo, "new.txt"), "w") as fh:
            fh.write("clean\nsecond line has " + e.capitalize() + "Wide in it\n")
        git("add", "-A")
        git("commit", "-q", "-m", "change")
        sink = _Sink()
        rc = run(base, cwd=repo, out=sink)
        if rc != 1 or "new.txt:2:" not in sink.text or "old.txt" in sink.text:
            failures.append("end to end (dirty change): rc=%r output=%r" % (rc, sink.text))
        if '"' + e.capitalize() + '"' not in sink.text or "second line has" in sink.text:
            failures.append("end to end: output must name the match and must not print the line: %r" % sink.text)
        with open(os.path.join(repo, "new.txt"), "a") as fh:
            fh.write("third line is clean\n")
        git("add", "-A")
        git("commit", "-q", "-m", "clean follow-up")
        head_base = git("rev-parse", "HEAD~1").stdout.strip()
        sink = _Sink()
        rc = run(head_base, cwd=repo, out=sink)
        if rc != 0:
            failures.append("end to end (clean change): rc=%r output=%r" % (rc, sink.text))
        sink = _Sink()
        rc = run("not-a-commit", cwd=repo, out=sink)
        if rc != 2:
            failures.append("an unreadable base must exit 2, got %r" % rc)
        sink = _Sink()
        rc = run("--output=x", cwd=repo, out=sink)
        if rc != 2:
            failures.append("an option-shaped base must be refused, got %r" % rc)

    if failures:
        for line in failures:
            print("SELF-TEST FAIL: " + line)
        return 1
    print("self-test ok: %d catch fixtures, %d pass fixtures, diff scan and git end-to-end" % (len(fail), len(ok)))
    return 0


class _Sink:
    def __init__(self):
        self.text = ""

    def write(self, chunk):
        self.text += chunk


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--base", help="ref or sha to diff against HEAD (all zeros means HEAD^1)")
    parser.add_argument("--self-test", action="store_true", help="run the checker's own fixtures and exit")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if not args.base:
        parser.error("--base is required unless --self-test is given")
    return run(args.base)


if __name__ == "__main__":
    sys.exit(main())
