#!/usr/bin/env python3
"""After a merge to main, tell Token-Service to drop its cached copies of the files that changed.

Token-Service caches transformation code per worker for up to an hour (a commit-pinned URL for ever), so
without this a merged fix takes that long to go live. Its reset route drops the cached copies of exact
repo paths on every worker within about ten seconds; this tool sends it the paths a push changed.

    git diff --name-only <before> <after> | python tools/reset_token_service_cache.py [--dry-run]

Configuration comes only from the environment, never from this file (the repository is public):
    TOKEN_SERVICE_RESET_URL    the Token-Service base URL
    TOKEN_SERVICE_RESET_TOKEN  Token-Service's reset-only token (its TRANSFORM_CACHE_RESET_TOKEN). It can
                               reset this cache and nothing else; never put a service credential here.
Either unset: nothing is sent and the run says so (exit 0), so the workflow can merge before the secrets
exist. No changed path: nothing is sent. More than MAX_PATHS paths, or no usable diff (--all): the whole
cache is reset, and so is any path the server would refuse (git quotes spaces, "+" and non-ASCII). A refusal from Token-Service exits 1 with its status only; no body or secret is printed.
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request

ROUTE = "/admin/cache/transformations/reset"
MAX_PATHS = 200
#: The paths Token-Service accepts. Anything else resets everything rather than failing the whole request.
_PATH_RE = re.compile(r"^[A-Za-z0-9_.\-/]{1,512}$")


def scope_for(paths: list[str], everything: bool = False) -> dict | None:
    """The reset body for these changed paths, or None when there is nothing to reset."""
    if everything:
        return {"all": True}
    clean = []
    for p in paths:
        p = p.strip()
        if p and not p.startswith("/") and ".." not in p.split("/") and p not in clean:
            clean.append(p)
    if not clean:
        return None
    if len(clean) > MAX_PATHS or not all(_PATH_RE.match(p) for p in clean):
        return {"all": True}
    return {"paths": clean}


def build_request(base_url: str, token: str, scope: dict) -> urllib.request.Request:
    return urllib.request.Request(
        base_url.rstrip("/") + ROUTE,
        data=json.dumps(scope).encode(),
        method="POST",
        headers={"Content-Type": "application/json", "X-Transform-Reset-Token": token},
    )


def send(base_url: str, token: str, scope: dict, timeout: float = 20.0) -> int:
    request = build_request(base_url, token, scope)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - https URL from a secret
            return response.status
    except urllib.error.HTTPError as e:
        return e.code


def main(argv: list[str]) -> int:
    dry = "--dry-run" in argv
    everything = "--all" in argv
    paths = [] if everything else sys.stdin.read().splitlines()
    scope = scope_for(paths, everything)
    if scope is None:
        print("No changed paths; nothing to reset.")
        return 0
    described = "all" if scope.get("all") else f"{len(scope['paths'])} path(s)"
    if dry:
        print(f"Would reset: {described}")
        print(json.dumps(scope, indent=1))
        return 0
    base_url = os.environ.get("TOKEN_SERVICE_RESET_URL", "").strip()
    token = os.environ.get("TOKEN_SERVICE_RESET_TOKEN", "").strip()
    if not base_url or not token:
        print("TOKEN_SERVICE_RESET_URL or TOKEN_SERVICE_RESET_TOKEN is not set; nothing sent. "
              "The merged code goes live when Token-Service's cache expires (up to an hour).")
        return 0
    status = send(base_url, token, scope)
    if 200 <= status < 300:
        print(f"Token-Service cache reset recorded ({described}); every worker applies it within about 10 s.")
        return 0
    print(f"Token-Service refused the cache reset: HTTP {status}.")
    return 1


def self_test() -> int:
    assert scope_for([]) is None
    assert scope_for(["", "  "]) is None
    assert scope_for(["safeguards/a/x.py", "safeguards/a/x.py", "docs/y.md"]) == {
        "paths": ["safeguards/a/x.py", "docs/y.md"]}
    assert scope_for(["/etc/passwd", "../up.py", "a/../b.py"]) is None
    assert scope_for([f"p{i}.py" for i in range(MAX_PATHS + 1)]) == {"all": True}
    assert scope_for([f"p{i}.py" for i in range(MAX_PATHS)]) == {"paths": [f"p{i}.py" for i in range(MAX_PATHS)]}
    assert scope_for([], everything=True) == {"all": True}
    # A path the server would refuse (git quotes spaces, "+" and non-ASCII) resets everything rather than
    # failing the whole request.
    assert scope_for(["safeguards/a/x.py", "safeguards/a/with space.py"]) == {"all": True}
    assert scope_for(['"safeguards/a/caf\\303\\251.py"']) == {"all": True}
    assert scope_for(["safeguards/a/x+y.py"]) == {"all": True}

    # Unset configuration sends nothing and does not fail the run.
    saved = {k: os.environ.pop(k, None) for k in ("TOKEN_SERVICE_RESET_URL", "TOKEN_SERVICE_RESET_TOKEN")}
    try:
        import io
        stdin, sys.stdin = sys.stdin, io.StringIO("safeguards/a/x.py\n")
        sent = []
        global send
        real_send, send = send, lambda *a, **k: sent.append(a) or 202
        try:
            assert main([]) == 0 and sent == []
            os.environ["TOKEN_SERVICE_RESET_URL"] = "https://example.invalid"
            os.environ["TOKEN_SERVICE_RESET_TOKEN"] = "t" * 40
            sys.stdin = io.StringIO("safeguards/a/x.py\n")
            assert main([]) == 0 and sent[-1][1] == "t" * 40 and sent[-1][2] == {"paths": ["safeguards/a/x.py"]}
            # The reset-only token goes in its own header; never an Authorization header.
            req = build_request("https://example.invalid/", "t" * 40, {"all": True})
            assert req.get_header("X-transform-reset-token") == "t" * 40
            assert req.get_header("Authorization") is None
            assert req.full_url == "https://example.invalid/admin/cache/transformations/reset"
            send = lambda *a, **k: 403  # noqa: E731
            sys.stdin = io.StringIO("safeguards/a/x.py\n")
            assert main([]) == 1
        finally:
            send = real_send
            sys.stdin = stdin
    finally:
        for k, v in saved.items():
            os.environ.pop(k, None)
            if v is not None:
                os.environ[k] = v
    print("reset_token_service_cache self-test passed")
    return 0


if __name__ == "__main__":
    sys.exit(self_test() if "--self-test" in sys.argv[1:] else main(sys.argv[1:]))
