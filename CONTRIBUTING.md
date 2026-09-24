# Contributing Transformations

This guide explains how to create transformation files that are compatible with the Spektrum evaluation system.

## Table of Contents

- [Overview](#overview)
- [The fail-closed rule](#the-fail-closed-rule)
- [Directory Structure](#directory-structure)
- [Creating a Transformation](#creating-a-transformation)
- [Response Schema](#response-schema)
- [Helper Functions](#helper-functions)
- [RestrictedPython Limitations](#restrictedpython-limitations)
- [Schema Validation (Optional)](#schema-validation-optional)
- [Testing](#testing)
- [Examples](#examples)

---

## Overview

Transformations convert third-party API responses into standardized boolean/numeric values that the Spektrum compliance engine can evaluate. Each transformation:

1. Receives JSON input from a vendor API
2. Parses and validates the input
3. Applies business logic to determine pass/fail
4. Returns a standardized response with reasons and recommendations

---

## The fail-closed rule

**A criterion may only be reported satisfied from a body that actually shows it is
satisfied.** If the vendor returned nothing, returned an error, or returned something
this transformation does not recognise, the answer is `False` — not `True`, and not
"True because a response arrived".

This is enforced in CI. `.github/workflows/transform-contract.yml` runs
`tools/check_fail_closed.py` on every pull request and on every push to `develop`,
`staging` and `main`. It hands each `transform()` a set of bodies that contain **no
evidence about any estate** and fails the build if **any** key comes back `True` -- or
any inverted key (below) comes back `False`. Every key is judged, whatever its name: the
gate used to judge only keys shaped `^(confirmed|is|are|has)[A-Z]`, and ten live rubber
stamps (`authTypesAllowed`, `confirmPasswordPolicyEnforced`, `keysHaveExpirationDate`, ...)
passed it for exactly that reason:

<!-- BEGIN no-evidence-battery: checked against tools/check_fail_closed.py NO_EVIDENCE
     by the gate itself. A documented contract that silently diverges from the enforced
     one is the same defect this page is about, so the run fails if these disagree.
     Add a probe in the code, then add its row here. -->

| probe | body |
|---|---|
| `empty_dict` | `{}` |
| `null` | `None` |
| `empty_string` | `"{}"` |
| `auth_error` | `{"error": {"type": "authentication_error", "message": "invalid credentials"}}` |
| `auth_401` | `{"statusCode": 401, "error": "Unauthorized"}` |
| `auth_401_snake` | `{"status_code": 401, "error": "Unauthorized"}` |
| `auth_401_nested` | `{"error": {"statusCode": 401, "message": "Unauthorized"}}` |
| `auth_403` | `{"statusCode": 403, "error": "Forbidden"}` |
| `unrelated_json` | `{"hello": "world"}` |
| `unrelated_nested` | `{"foo": {"bar": [1, 2, 3]}}` |

<!-- END no-evidence-battery -->

Each is fed both as a dict and as a JSON string. A companion contract,
`tools/check_discriminates.py`, additionally fails a criterion that has **no reachable
false** — one that no input at all can make say no.

### What this rules out

These are not hypotheticals. Every one was found in this repository and fixed:

```python
# NO. "Did a response arrive" is not the question the criterion asks.
default_value = data is not None
license_purchased = data.get('licensePurchased', default_value)

# NO. An empty list to loop over produces a count of zero, and zero findings
# then reads as compliant -- from a body that named no findings at all.
vulnerabilities = data.get("vulnerabilities", data.get("value", []))

# NO. Any dict with any key in it is not proof the subscription is active.
elif isinstance(data, dict) and len(data) > 0:
    license_purchased = True

# NO. A bare dict is not one record. `{}` became "one assignment".
if isinstance(data, dict):
    return [data]

# NO. A documented capability is not a measured posture. The endpoint's request
# schema says nothing about THIS tenant, and a 401 means nothing was read.
elif is_error and status_code == 401:
    result_value = True
```

### What to write instead

Require the response to carry a signal the transformation actually reads, and say so:

```python
# The query must be shown to have run before its result can be read as evidence.
if not (isinstance(data, dict) and isinstance(data.get("findings"), list)):
    return create_response(
        result={criteriaKey: False},
        validation=validation,
        api_errors=["no findings collection in the response: the query cannot be "
                    "shown to have run, so a count of zero is not evidence"])
```

A **proven** empty result set is different from silence, and is allowed to pass where
that is the right reading — `{"findings": []}` may legitimately mean "we looked and
there are none". `{}` may not.

### Two exceptions, both narrow

- **Inverted keys.** A few criteria use `True` to denote the *insecure* condition —
  `isPublicStorageBucketExposed`, `localLoginAllowed`,
  `hasIdentifiedServiceAccountsMFAGap`. For these, `True` on unknown input **is**
  fail-closed, and `False` -- "not exposed", "no gap" -- is the rubber stamp, so the gate
  fails an inverted key that answers `False` from no evidence. They are listed explicitly
  in `check_fail_closed.INVERTED`; the set is
  named rather than inferred from the key, because guessing polarity from a name is
  exactly how a correct transformation gets "fixed" into a defect. If you add one,
  establish the polarity from the transformation's own pass/fail reasons, not its name.
- **Raising is fine.** An exception is fail-closed: the pipeline records a
  transformation error. What is never fine is an `except` branch that returns the
  criterion satisfied.

Run both contracts locally before you open a pull request:

```bash
python3 tools/check_fail_closed.py --self-test && python3 tools/check_fail_closed.py
python3 tools/check_discriminates.py --self-test && python3 tools/check_discriminates.py
python3 tools/check_sandbox_compile.py --self-test && python3 tools/check_sandbox_compile.py
```

The third one matters more than it looks. Production compiles every transform with
RestrictedPython, which rejects **any name starting with `_`** (only `_parse_input` and
`_listify` are rewritten first), **`x["k"] += 1`** (write `x["k"] = x["k"] + 1`) and
**`nonlocal`**. Plain Python accepts all three, so a transform can pass the first two
contracts and never run in production -- 80 did, on 2026-09-22.

`docs2/03-writing-a-transform.md` has the long-form anti-pattern gallery, with real
files named. Read it before copying an existing transformation — and read the file you
are copying, because a fair number of them were the reason this rule had to be written
down.

---

## Directory Structure

Transformations are organized by Safeguard Reference Number (SRN) or category:

```
safeguards/
├── 4BC425FA-0638-4BF1-8194-19E7E4F2F43C/    # UUID-based (AWS Backups)
│   ├── isbackupenabled.py                    # Criteria check
│   ├── is_backup_encrypted.py                # Another criteria
│   ├── backup_transform.py                   # Multi-criteria transform
│   ├── confirmedlicensepurchased.py          # License check
│   └── schemas/                              # Optional Pydantic schemas
│       ├── __init__.py
│       ├── isbackupenabled.py
│       └── backup_transform.py
├── 874a78ff-2ca3-4c0e-ab86-19277536ac87/    # UUID-based (Microsoft)
│   ├── ismfaenforcedforusers.py
│   └── isssoenabled.py
├── backups/                                  # Category-based
│   └── datto/                                # Vendor subdirectory
│       ├── isbackupenabled.py
│       └── backup_transform.py
└── common/
    └── response_helper.py                    # Shared helper functions
```

### Naming Conventions

| Type | Convention | Example |
|------|------------|---------|
| Criteria file | Lowercase criteria key | `ismfaenforcedforusers.py` |
| Multi-criteria | Descriptive with underscores | `backup_transform.py` |
| Schema file | Match transformation name | `schemas/ismfaenforcedforusers.py` |

---

## Creating a Transformation

Every transformation file must implement a `transform(input)` function:

```python
"""
Transformation: Is MFA Enforced For Users
Vendor: Okta
Category: Identity

Checks if MFA is enforced for all users in the organization.
"""

import json
from datetime import datetime


def transform(input):
    """
    Main transformation function.

    Args:
        input: JSON string, bytes, or dict from the vendor API

    Returns:
        dict: Standardized response with transformedResponse and additionalInfo
    """
    try:
        # 1. Parse input
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        # 2. Extract data and validation status
        data, validation = extract_input(input)

        # 3. Handle validation failures
        if validation.get("status") == "failed":
            return create_response(
                result={"isMFAEnforcedForUsers": False},
                validation=validation,
                fail_reasons=validation.get("errors", ["Input validation failed"])
            )

        # 4. Apply business logic
        # ... your logic here ...

        # 5. Return standardized response
        return create_response(
            result={"isMFAEnforcedForUsers": is_enforced},
            validation=validation,
            pass_reasons=pass_reasons if is_enforced else [],
            fail_reasons=fail_reasons if not is_enforced else [],
            recommendations=recommendations,
            input_summary={"totalUsers": total, "mfaEnrolled": enrolled},
            metadata={"vendor": "Okta", "category": "Identity"}
        )

    except json.JSONDecodeError as e:
        return create_response(
            result={"isMFAEnforcedForUsers": False},
            validation={"status": "error", "errors": [f"Invalid JSON: {str(e)}"], "warnings": []},
            fail_reasons=["Could not parse input as valid JSON"]
        )
    except Exception as e:
        return create_response(
            result={"isMFAEnforcedForUsers": False},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
```

---

## Response Schema

All transformations must return this standardized structure:

```python
{
    "transformedResponse": {
        "isMFAEnforcedForUsers": True,      # Primary criteria (boolean)
        "totalUsers": 45,                    # Supporting metrics
        "mfaEnrolledUsers": 45
    },
    "additionalInfo": {
        "dataCollection": {
            "status": "success",             # "success" | "error"
            "errors": []                     # API-level errors
        },
        "validation": {
            "status": "passed",              # "passed" | "failed" | "unknown"
            "errors": [],
            "warnings": []
        },
        "transformation": {
            "status": "success",             # "success" | "error"
            "errors": [],
            "inputSummary": {                # What was found in input
                "totalUsers": 45,
                "mfaEnrolledUsers": 45
            }
        },
        "evaluation": {
            "passReasons": [                 # Why it passed (human-readable)
                "All 45 users have MFA enrolled"
            ],
            "failReasons": [],               # Why it failed
            "recommendations": [],           # Actionable improvements
            "additionalFindings": []         # Related metrics
        },
        "metadata": {
            "evaluatedAt": "2026-01-28T12:00:00Z",
            "schemaVersion": "2.0",
            "transformationId": "ismfaenforcedforusers",
            "vendor": "Okta",
            "category": "Identity"
        }
    }
}
```

### Criteria Key Conventions

| Type | Format | Examples |
|------|--------|----------|
| Boolean criteria | camelCase, `is` prefix | `isMFAEnforcedForUsers`, `isBackupEnabled` |
| Percentage scores | camelCase | `scoreInPercentage`, `compliancePercentage` |
| Counts | camelCase | `totalUsers`, `backupCount` |

---

## Helper Functions

Copy these helper functions into your transformation file (required for RestrictedPython compatibility):

### extract_input()

Handles both new enriched format and legacy API responses:

```python
def extract_input(input_data):
    """Extract data and validation from input, handling both formats."""
    # New enriched format: {"data": {...}, "validation": {...}}
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]

    # Legacy format - unwrap common response wrappers
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):  # Max 3 levels of unwrapping
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break

    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"]
    }
    return data, validation
```

### create_response()

Creates the standardized response structure:

```python
def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Create standardized transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}

    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []

    data_collection_status = "error" if api_err_list else "success"
    transformation_status = "error" if transform_err_list else "success"

    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0"
    }
    if metadata:
        response_metadata.update(metadata)

    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": data_collection_status,
                "errors": api_err_list
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": transformation_status,
                "errors": transform_err_list,
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": response_metadata
        }
    }
```

### parse_api_error()

Parse API errors into clean messages:

```python
def parse_api_error(raw_error, source=None):
    """Parse raw API error into clean message with recommendation."""
    raw_lower = raw_error.lower() if raw_error else ''
    src = source or "external service"

    if '401' in raw_error:
        return (f"Authentication failed (HTTP 401)", f"Verify {src} credentials")
    elif '403' in raw_error:
        return (f"Access denied (HTTP 403)", f"Verify {src} permissions")
    elif '404' in raw_error:
        return (f"Resource not found (HTTP 404)", f"Verify {src} configuration")
    elif '429' in raw_error:
        return (f"Rate limited (HTTP 429)", "Retry after waiting")
    elif '500' in raw_error or '502' in raw_error or '503' in raw_error:
        return (f"Service unavailable (HTTP 5xx)", "Retry later")
    elif 'timeout' in raw_lower:
        return (f"Request timed out", "Check network connectivity")
    else:
        clean = raw_error[:80] + "..." if len(raw_error) > 80 else raw_error
        return (clean, f"Check {src} configuration")
```

---

## RestrictedPython Limitations

Transformations run in a RestrictedPython sandbox. These limitations apply:

### Not Allowed

```python
# NO: map() function
users_with_mfa = list(map(lambda u: u["email"], filtered_users))

# NO: datetime.strptime()
date = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S")

# NO: Augmented assignment on dict items
counters["key"] += 1

# NO: External imports (except json, datetime)
import requests  # Not available
```

### Use Instead

```python
# YES: List comprehension
users_with_mfa = [u["email"] for u in filtered_users]

# YES: Manual date parsing
def parse_iso_date(date_str):
    """Parse ISO 8601 date without strptime."""
    try:
        date_str = date_str.replace("Z", "").split(".")[0]
        date_part, time_part = date_str.split("T")
        year, month, day = [int(x) for x in date_part.split("-")]
        hour, minute, second = [int(x) for x in time_part.split(":")]
        return datetime(year, month, day, hour, minute, second)
    except (ValueError, AttributeError, IndexError):
        return None

# YES: Explicit assignment
counters["key"] = counters["key"] + 1

# YES: int() conversion instead of map()
parts = [int(x) for x in date_str.split("-")]
```

---

## Schema Validation (Optional)

Add Pydantic schemas for input validation in `schemas/` subdirectory:

### schemas/ismfaenforcedforusers.py

```python
from pydantic import BaseModel, Field
from typing import Optional, List, Any

class UserMFAStatus(BaseModel):
    userId: str
    email: Optional[str] = None
    mfaEnabled: bool = False

    class Config:
        extra = "allow"

class IsmfaenforcedforusersInput(BaseModel):
    """Expected input schema for MFA enforcement check."""
    users: Optional[List[UserMFAStatus]] = Field(
        default=None,
        description="List of users with MFA status"
    )
    totalCount: Optional[int] = None

    class Config:
        extra = "allow"  # Allow additional fields
```

### schemas/__init__.py

```python
from .ismfaenforcedforusers import IsmfaenforcedforusersInput

__all__ = ["IsmfaenforcedforusersInput"]
```

---

## Testing

Test transformations locally using the local_tester.py:

```bash
# Test with sample API response
python local_tester.py safeguards/86ded564-522a-4c9b-9106-365e4cbdec7d/ismfaenforcedforusers.py sample_response.json

# Test with inline JSON
echo '{"users": [{"userId": "1", "mfaEnabled": true}]}' | python local_tester.py safeguards/.../transform.py -
```

### Test Cases to Cover

Cases 3 to 7 have a **required answer**, not merely required coverage: the criterion
must come back `False` (or `True` for an [inverted key](#the-fail-closed-rule)). Listing
the case without asserting the answer is how the defects in the fail-closed section got
in.

| # | case | input | required answer |
|---|---|---|---|
| 1 | Happy path | valid input, control in place | `True` |
| 2 | Failure case | valid input, control absent | `False` |
| 3 | Empty data | `{}`, `None`, `"{}"` | **`False`** |
| 4 | API error | an error envelope, with and without an HTTP status code | **`False`** |
| 5 | Unrelated payload | `{"hello": "world"}`, `{"foo": {"bar": [1, 2, 3]}}` | **`False`** |
| 6 | Malformed JSON | invalid input format | **`False`** or raise |
| 7 | Legacy format | input without enriched validation | as case 1 or 2 |

Case 5 is easy to skip and was missing from this guide, and from the contract itself,
for longer than it should have been: a transformation whose effective rule is
`len(data) > 0` answers cases 3 and 4 correctly and is still a rubber stamp.

---

## Examples

### Simple Boolean Check

```python
def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)

        data, validation = extract_input(input)

        # Check if MFA is enabled
        mfa_status = data.get("mfaPolicy", {}).get("status", "")
        is_enabled = mfa_status.lower() == "active"

        return create_response(
            result={"isMFAEnforcedForUsers": is_enabled},
            validation=validation,
            pass_reasons=["MFA policy is active"] if is_enabled else [],
            fail_reasons=["MFA policy is not active"] if not is_enabled else [],
            recommendations=[] if is_enabled else ["Enable MFA policy for all users"],
            input_summary={"policyStatus": mfa_status},
            metadata={"vendor": "Okta", "category": "Identity"}
        )
    except Exception as e:
        return create_response(
            result={"isMFAEnforcedForUsers": False},
            transformation_errors=[str(e)],
            fail_reasons=[f"Error: {str(e)}"]
        )
```

### Complex Multi-Source Check

See `safeguards/4BC425FA-0638-4BF1-8194-19E7E4F2F43C/isbackupenabled.py` for a complete example handling:
- Multiple data sources (RDS automated, RDS manual, EBS snapshots)
- Nested AWS API response structures
- Type-safe container unwrapping
- Comprehensive pass/fail reasons

---

## Checklist

Before submitting a transformation:

- [ ] Implements `transform(input)` function
- [ ] Uses `extract_input()` for input parsing
- [ ] Returns `create_response()` with all required fields
- [ ] Handles JSON parse errors gracefully
- [ ] Handles unexpected exceptions gracefully **without returning the criterion satisfied**
- [ ] Returns `False` for an empty body, an error envelope (with and without a status code), and an unrelated payload — see [The fail-closed rule](#the-fail-closed-rule)
- [ ] Has at least one input that makes the criterion return `False`
- [ ] `python3 tools/check_fail_closed.py` and `python3 tools/check_discriminates.py` both exit 0
- [ ] Uses camelCase for criteria keys
- [ ] Avoids RestrictedPython limitations (no `map()`, no `strptime()`)
- [ ] Includes docstring with transformation name, vendor, category
- [ ] Provides meaningful `passReasons` and `failReasons`
- [ ] Includes `recommendations` for failures
- [ ] Tested with `local_tester.py`
