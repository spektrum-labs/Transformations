# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This repository contains Python transformation logic that converts third-party API responses into standardized values for the Spektrum security compliance network. Each transformation processes vendor-specific API data and returns JSON that can be evaluated by Third Party Requirements tokens.

## Testing Transformations

Run a transformation locally against sample API response data:
```bash
python local_tester.py <transformation_file_or_url.py> <sample_response.json>
```

Example:
```bash
python local_tester.py safeguards/4BC425FA-0638-4BF1-8194-19E7E4F2F43C/backup_transform.py sample_response.json
```

## Architecture

### Directory Structure
- `safeguards/` - Contains all transformation logic organized by Safeguard Reference Number (SRN)
- Each SRN directory (UUID format) contains transformation files for a specific vendor/integration
- `safeguards/backups/` - Contains backup-related transformations with vendor subdirectories (e.g., `datto/`)

### Transformation Pattern
Every transformation file must implement a `transform(input)` function that:
1. Accepts JSON input (string, bytes, or dict) from a third-party API
2. Handles nested response wrappers (`response`, `result`, `apiResponse`)
3. Returns a dict with boolean flags and/or numeric scores
4. Returns an error dict on failure: `{"criteriaKey": False, "error": str(e)}`

### Common Input Parsing Pattern
Most transformations include this helper to handle various input formats:
```python
def _parse_input(input):
    if isinstance(input, str):
        return json.loads(input)
    if isinstance(input, bytes):
        return json.loads(input.decode("utf-8"))
    if isinstance(input, dict):
        return input
    raise ValueError("Input must be JSON string, bytes, or dict")
```

### Return Value Conventions
- Boolean criteria keys use camelCase: `isMFAEnforcedForUsers`, `isBackupEnabled`, `isBackupEncrypted`
- Scores returned as percentages (0-100): `scoreInPercentage`
- Count metrics: `count` (compliant items), `total` (total items)

### Naming Conventions
- Transformation files are lowercase with underscores: `mfa_transform.py`, `backup_transform.py`
- Criteria check files match the criteria key: `ismfaenforcedforusers.py`, `isbackupenabled.py`
- Each SRN directory typically contains:
  - A main `*_transform.py` file
  - Individual criteria check files (e.g., `confirmedlicensepurchased.py`)

## Team rules

**This repository is PUBLIC.** Everything in a PR title, PR body, commit message, fixture, comment or review thread is world-readable and GitHub keeps edit history, so a later edit does not un-leak it.

- NEVER include customer or company names, customer or company IDs, tenant IDs, passport SRNs or SRN prefixes, domains, per-customer counts, internal hostnames or URLs, or any secret or credential. Not in code, tests, fixtures, comments, commits or PR bodies.
- Fixtures are synthetic: made-up GUIDs and placeholder values, or a vendor's published well-known identifiers. Never paste a real vendor API response; sanitise it fully first.
- Describe replay or test results generically ("no new passes; N checks changed") and say "estate A / estate B" instead of naming anyone. Keep per-customer results in local, private notes.
- Before opening a PR, grep the diff and the PR body for names, IDs and hostnames.

### Run checks locally

- `pip install -r requirements-test.txt` (pytest, pydantic, RestrictedPython), then run what CI runs from the repo root: `python tools/check_fail_closed.py`, `python tools/check_discriminates.py`, `python tools/check_none_not_evaluated.py`, `python tools/check_sandbox_compile.py`, `python tools/check_test_floor.py` (each has a `--self-test`). Do not edit `check_test_floor.py` in a feature PR.
- Try a transform on a sample: `python local_tester.py <transform.py> <sample.json>`.
- Transforms run under RestrictedPython in production: no `re.compile` or `getattr`-style escapes, standard library only. Fail closed: a criterion is only `True` from a body that shows it is satisfied.

### Release rules

- Open PRs against `develop`. `main` is live on merge, so staging -> main merges are release PRs; merge them in order once green with 0 critical/high review findings.
- Hotfixes to `main` need a twin PR into `develop`.
- When resolving a staging -> main (or main -> staging) merge, keep main's version of the six endpoint-rule files changed in PR #693 (`safeguards/epp/ninjaone-endpoint-management/` endpointOperationalStatusUnprotectedCount.py, isEPPConfigured.py, isEPPEnabled.py, isSignatureUpToDate.py, staleSensorCount.py, and `safeguards/epp/sophos/iseppconfigured.py`). A blanket "take staging" silently reverts them.
- Transform code is cached by the evaluation service for up to 1 hour per task. A SHA-pinned URL takes effect at once; a branch URL can lag. Pins must reference a commit reachable from `main`.
- Condition operators in the evaluation service: `greaterThan` and `lessThan` are inclusive (>= and <=) and both sides are truncated to int.

### PR rules

- Every PR body carries an OWASP result: run the `owasp-security` skill on the diff, exploitability first, and say what is reachable and why anything downgraded is not. A reachable High or Critical blocks merge.
- Fix Medium, High and Critical review findings. List Lows in the PR body and leave them.
- Read the review job's "N critical/high finding(s)" count; N > 0 blocks merge. Resolve every review thread; the rulesets block merge on open threads.
- Never log credential values.
