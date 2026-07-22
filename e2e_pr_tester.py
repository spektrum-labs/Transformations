#!/usr/bin/env python3
"""
End-to-end tester for an Integration-Service definition PR + Transformations PR.

Given the two PR numbers, vendor credentials, and (optionally) a requirement
token JSON, it:
  1. resolves both PR head branches via `gh`
  2. fetches the definition JSON from the Integration-Service PR branch
  3. rewrites the definition's transformationLogic URLs from refs/heads/develop
     to the Transformations PR branch (so pre-merge scripts resolve)
  4. authenticates with the vendor using the definition's oauth block
  5. for every criterion in the definition workflow: calls the real vendor API
     per the method spec (URL template, inputParameters, returnSpec)
  6. feeds each live response through the PR-branch transformation using the
     repo's own local_tester.py pipeline (schemas included, so validation runs)
  7. prints a per-criterion table; compares to expectedValue from the
     requirement token when one is supplied

Credentials come from env vars (preferred, keeps them out of shell history):
  E2E_SERVER_URL, E2E_CLIENT_ID, E2E_CLIENT_SECRET
or a --settings JSON file: {"serverUrl": ..., "clientId": ..., "clientSecret": ...}

Usage:
  export E2E_SERVER_URL=https://api.crowdstrike.com
  export E2E_CLIENT_ID=...
  export E2E_CLIENT_SECRET=...
  python3 e2e_pr_tester.py --is-pr 690 --tx-pr 483 \
      [--requirement-token requirement.json] [--criteria isEPPDeployed,isEDRDeployed]

Needs: python3, requests, pydantic, authenticated `gh` CLI.
"""

import argparse
import base64
import importlib.util
import json
import os
import subprocess
import sys
import tempfile

import requests

IS_REPO = "spektrum-labs/Integration-Service"
TX_REPO = "spektrum-labs/Transformations"
LOCAL_TESTER_URL = "https://raw.githubusercontent.com/{repo}/refs/heads/develop/local_tester.py"


def sh(args):
    r = subprocess.run(args, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"{' '.join(args)}\n{r.stderr.strip()}")
    return r.stdout


def gh_json(args):
    return json.loads(sh(["gh"] + args))


def resolve_pr(repo, number):
    d = gh_json(["pr", "view", str(number), "--repo", repo,
                 "--json", "headRefName,files,state"])
    return d["headRefName"], [f["path"] for f in d["files"]], d["state"]


def fetch_repo_file(repo, path, ref):
    d = gh_json(["api", f"repos/{repo}/contents/{path}?ref={ref}"])
    return base64.b64decode(d["content"]).decode()


def spec_value(v, settings=None):
    """Resolve a ['source.path', 'default_to', default] spec to its default,
    or a settings.<key> lookup when settings are supplied."""
    if isinstance(v, list) and len(v) == 3 and v[1] == "default_to":
        src = v[0]
        if settings and isinstance(src, str) and src.startswith("settings."):
            return settings.get(src.split(".", 1)[1], v[2])
        return v[2]
    return v


def render_url(template, settings):
    out = template
    for k, val in settings.items():
        out = out.replace("{$%s}" % k, str(val).rstrip("/"))
    if "{$" in out:
        raise RuntimeError(f"Unresolved placeholder in URL: {out}")
    return out


def get_oauth_token(definition, settings):
    methods = definition["authentication"]["methods"]
    if isinstance(methods, list) and methods and methods[0] == "$array":
        methods = methods[1]
    oauth = next(m["oauth"] for m in methods if "oauth" in m)
    url = render_url(oauth["url"], settings)
    payload = {k: spec_value(v, settings) for k, v in oauth["payload"].items()}
    resp = requests.post(url, data=payload, timeout=30)  # CrowdStrike: form-encoded
    if resp.status_code >= 400:
        resp = requests.post(url, json=payload, timeout=30)  # fallback for JSON vendors
    resp.raise_for_status()
    tok = resp.json().get("access_token")
    if not tok:
        raise RuntimeError(f"No access_token in auth response: {resp.text[:200]}")
    print(f"  auth OK ({url})")
    return tok


def apply_return_spec(spec, body):
    if not spec:
        return body
    out = {}
    for key, path_spec in spec.items():
        default = None
        path = path_spec
        if isinstance(path_spec, list) and len(path_spec) == 3 and path_spec[1] == "default_to":
            path, _, default = path_spec
        node = body
        for part in str(path).split("."):
            node = node.get(part) if isinstance(node, dict) else None
            if node is None:
                break
        out[key] = node if node is not None else default
    return out


def call_method(definition, name, settings, token, chain_cache):
    spec = definition[name]
    url = render_url(spec["url"], settings)
    headers = {"Authorization": f"Bearer {token}"}
    params = {k: spec_value(v) for k, v in spec.get("inputParameters", {}).items()}
    params = {k: v for k, v in params.items() if v not in ("", None)}
    http_method = spec.get("method", "GET").upper()

    if http_method == "POST":
        # Chained POST (e.g. getDeviceDetails wants ids from queryDevicesScroll).
        # Source ids from the first GET method that returned a resources list of strings.
        body = {}
        for cached in chain_cache.values():
            res = cached.get("resources")
            if isinstance(res, list) and res and all(isinstance(x, str) for x in res):
                body = {"ids": res[:100]}
                break
        if not body:
            scroll = next((m for m in definition.get("workflow", {})
                           .get("isEPPDeployed", [{}])[0].values() if isinstance(m, str)), None)
            if scroll and scroll != name:
                call_method(definition, scroll, settings, token, chain_cache)
                return call_method(definition, name, settings, token, chain_cache)
        resp = requests.post(url, headers=headers, json=body, timeout=60)
    else:
        resp = requests.get(url, headers=headers, params=params, timeout=60)

    try:
        raw = resp.json()
    except ValueError:
        raw = {"raw_text": resp.text[:2000]}
    if resp.status_code >= 400:
        # Mirror ICR's error envelope so transformations exercise their
        # api_errors path instead of seeing a deceptively empty returnSpec shape.
        shaped = {"error": True, "errorType": "http", "status": "Error",
                  "statusCode": resp.status_code,
                  "message": json.dumps(raw)[:500]}
    else:
        shaped = apply_return_spec(spec.get("returnSpec"), raw)
    shaped["_http_status"] = resp.status_code
    chain_cache[name] = shaped
    return shaped


def load_local_tester(tmpdir):
    path = os.path.join(tmpdir, "local_tester.py")
    r = requests.get(LOCAL_TESTER_URL.format(repo=TX_REPO), timeout=30)
    r.raise_for_status()
    open(path, "w").write(r.text)
    return path


def find_expected(token_json, criterion):
    """Best-effort: find an expectedValue for a criterion anywhere in the token."""
    hits = []

    def walk(node):
        if isinstance(node, dict):
            # Spektrum requirement token shape: {"criteriaKey": <name>,
            # "criteriaValue": {"type": "bool", "value": true}, ...}
            if node.get("criteriaKey") == criterion:
                cv = node.get("criteriaValue")
                if isinstance(cv, dict) and "value" in cv:
                    hits.append(cv["value"])
                elif cv is not None:
                    hits.append(cv)
            for k, v in node.items():
                if k == criterion:
                    if isinstance(v, dict):
                        for ek in ("expectedValue", "expected", "value"):
                            if ek in v:
                                hits.append(v[ek])
                    else:
                        hits.append(v)
                walk(v)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(token_json)
    return hits[0] if hits else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--is-pr", required=True, type=int, help="Integration-Service definition PR number")
    ap.add_argument("--tx-pr", required=True, type=int, help="Transformations PR number")
    ap.add_argument("--settings", help="JSON file with serverUrl/clientId/clientSecret (else E2E_* env vars)")
    ap.add_argument("--requirement-token", help="Requirement token JSON file to compare expected values")
    ap.add_argument("--criteria", help="Comma-separated subset of criteria to test")
    args = ap.parse_args()

    if args.settings:
        settings = json.load(open(args.settings))
    else:
        settings = {"serverUrl": os.environ.get("E2E_SERVER_URL", ""),
                    "clientId": os.environ.get("E2E_CLIENT_ID", ""),
                    "clientSecret": os.environ.get("E2E_CLIENT_SECRET", "")}
    if not all(settings.get(k) for k in ("serverUrl", "clientId", "clientSecret")):
        sys.exit("Missing credentials: set E2E_SERVER_URL / E2E_CLIENT_ID / E2E_CLIENT_SECRET or --settings")

    req_token = json.load(open(args.requirement_token)) if args.requirement_token else None

    print(f"[1/5] Resolving PRs…")
    is_branch, is_files, is_state = resolve_pr(IS_REPO, args.is_pr)
    tx_branch, tx_files, tx_state = resolve_pr(TX_REPO, args.tx_pr)
    print(f"  {IS_REPO}#{args.is_pr} ({is_state}) -> {is_branch}")
    print(f"  {TX_REPO}#{args.tx_pr} ({tx_state}) -> {tx_branch}")

    def_paths = [p for p in is_files if p.startswith("integration_configs/") and p.endswith(".json")]
    if not def_paths:
        sys.exit("No integration_configs/*.json in the Integration-Service PR")
    print(f"[2/5] Fetching definition {def_paths[0]} @ {is_branch}")
    definition = json.loads(fetch_repo_file(IS_REPO, def_paths[0], is_branch))

    # Rewrite transformation URLs to the Transformations PR branch
    raw = json.dumps(definition)
    rewritten = raw.replace("refs/heads/develop", f"refs/heads/{tx_branch}")
    n = raw.count("refs/heads/develop")
    definition = json.loads(rewritten)
    print(f"  rewrote {n} transformation URL(s) develop -> {tx_branch}")

    print(f"[3/5] Authenticating against {settings['serverUrl']}…")
    token = get_oauth_token(definition, settings)

    workflow = definition.get("workflow", {})
    criteria = list(workflow.keys())
    if args.criteria:
        wanted = {c.strip() for c in args.criteria.split(",")}
        criteria = [c for c in criteria if c in wanted]

    rta = {}
    for row in definition.get("retrievalTransformationArray", []):
        rta.update(row)

    tmpdir = tempfile.mkdtemp(prefix="e2e_pr_")
    tester = load_local_tester(tmpdir)
    os.makedirs(os.path.join(tmpdir, "schemas"), exist_ok=True)
    open(os.path.join(tmpdir, "schemas", "__init__.py"), "w").write("")

    print(f"[4/5] Running {len(criteria)} criteria live…\n")
    chain_cache, results = {}, []
    for crit in criteria:
        steps = workflow[crit]
        merged = {}
        status = None
        try:
            for step in steps:
                method = step["method"]
                shaped = call_method(definition, method, settings, token, chain_cache)
                status = shaped.pop("_http_status", None)
                merged.update(shaped)
        except Exception as e:
            results.append((crit, status, "API_ERROR", str(e)[:80], None))
            continue

        # Fetch transformation + schema from the tx PR branch into tmpdir
        tx_url = rta.get(crit, [{}])[0].get("transformationLogic", {}).get("url", "")
        tpath = os.path.join(tmpdir, f"{crit}.py")
        try:
            for url, dest in [
                (tx_url, tpath),
                (tx_url.rsplit("/", 1)[0] + f"/schemas/{crit}.py",
                 os.path.join(tmpdir, "schemas", f"{crit}.py")),
            ]:
                r = requests.get(url, timeout=30)
                if url.endswith(f"schemas/{crit}.py") and r.status_code == 404:
                    continue  # schema optional
                r.raise_for_status()
                open(dest, "w").write(r.text)
        except Exception as e:
            results.append((crit, status, "FETCH_ERROR", str(e)[:80], None))
            continue

        fixture = os.path.join(tmpdir, f"{crit}_input.json")
        json.dump({"apiResponse": merged}, open(fixture, "w"))
        run = subprocess.run([sys.executable, tester, tpath, fixture],
                             capture_output=True, text=True, cwd=tmpdir)
        out = run.stdout
        verdict, detail = "TRANSFORM_ERROR", (run.stderr or out)[-120:].replace("\n", " ")
        value = None
        anchor = out.find('"transformedResponse"')
        start = out.rfind("{", 0, anchor) if anchor != -1 else -1
        if start != -1:
            for end in range(len(out), start, -1):
                try:
                    parsed = json.loads(out[start:end])
                    value = parsed.get("transformedResponse", {}).get(crit)
                    verdict = "OK"
                    fails = (parsed.get("additionalInfo", {}).get("evaluation", {})
                             .get("failReasons", []))
                    detail = (fails[0][:80] if fails and value is not True
                              else json.dumps(parsed.get("transformedResponse"))[:80])
                    break
                except ValueError:
                    continue
        expected = find_expected(req_token, crit) if req_token else None
        results.append((crit, status, verdict, detail, (value, expected)))

    print(f"[5/5] Results\n")
    w = max(len(c) for c, *_ in results) + 2
    print(f"{'CRITERION'.ljust(w)}HTTP  RUN              VALUE      EXPECTED  MATCH  DETAIL")
    for crit, status, verdict, detail, vals in results:
        value, expected = vals if vals else (None, None)
        match = "-" if expected is None else ("✓" if value == expected else "✗")
        print(f"{crit.ljust(w)}{str(status or '-').ljust(6)}{verdict.ljust(17)}"
              f"{str(value).ljust(11)}{str(expected if expected is not None else '-').ljust(10)}"
              f"{match.ljust(7)}{detail}")
    print(f"\nWork dir (inputs + scripts kept for inspection): {tmpdir}")


if __name__ == "__main__":
    main()
