"""
Transformation: restApiTokenExpiryEnforced
Vendor: Palo Alto Networks Cloud NGFW (AWS)  |  Category: Firewalls

Integration-Service method describeProgrammaticAccess:
  GET /v1/mgmt/tokens ("Describe programmatic access")
  -> {"Response": {"Enabled": bool, "MaxExpiryTime": int}, "ResponseStatus": {"ErrorCode": 0}}

Value: True when the tenant states a MaxExpiryTime between 1 and 1440 (the reference's own
ceiling, 24 hours if the unit is minutes; the unit is not stated in the reference) for the
programmatic-access tokens it issues; False when the ceiling is zero, negative or above 1440.
This is the tenant-wide ceiling on token lifetime, not a read of any one token.

Fail closed (Not evaluated, never a pass): a refused (401/403), expired-token, error-shaped,
empty or unrecognised read, a ceiling that is not a whole number, programmatic access reported
disabled (no token is issued, so nothing was measured) is null.

Source: public OpenAPI reference for Cloud NGFW for AWS (pan.dev, ManageAPITokens). Whether this
route accepts the programmatic-access token or needs the AWS SigV4 signature is UNVERIFIED.
"""

import json
from datetime import datetime, timezone

VENDOR = "Palo Alto Networks Cloud NGFW"
CATEGORY = "Firewalls"
WRAPPERS = ("data", "response", "result", "apiResponse", "Output")


def parse(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        value = json.loads(value) if value.strip() else None
    return value


def unwrap(data, keys):
    """The first dict (under the usual Integration-Service wrappers) that carries one of keys."""
    for depth in range(6):
        if not isinstance(data, dict):
            return None
        for key in keys:
            if key in data:
                return data
        nxt = None
        for key in WRAPPERS:
            if isinstance(data.get(key), dict):
                nxt = data[key]
                break
        if nxt is None:
            return None
        data = nxt
    return None


def error_text(body):
    """Why a body is an error, or None."""
    if not isinstance(body, dict):
        return None
    if body.get("error") is True or body.get("errorType"):
        return "Integration-Service error " + str(body.get("statusCode") or "") + ": " + str(
            body.get("message") or body.get("errorMessage") or "")[:200]
    code = body.get("statusCode")
    if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
        return "HTTP " + str(code)
    if body.get("message") and "Response" not in body:
        return "vendor error: " + str(body.get("message"))[:200]
    return None


def response_problem(resp, label):
    """Why one vendor answer cannot be read, or None. Every answer is
    {"Response": {...}, "ResponseStatus": {"ErrorCode": 0}}; any other ErrorCode is a failure."""
    if not isinstance(resp, dict):
        return label + ": the response is not an object"
    text = error_text(resp)
    if text:
        return label + ": " + text
    status = resp.get("ResponseStatus")
    if isinstance(status, dict):
        code = status.get("ErrorCode")
        if code is not None and str(code).strip() not in ("0", ""):
            return label + ": vendor error " + str(code) + " " + str(status.get("Reason") or "")[:120]
    if not isinstance(resp.get("Response"), dict):
        return label + ": no Response object in the answer"
    return None


def build_response(result, pass_reasons=None, fail_reasons=None, errors=None, summary=None,
                   recommendations=None, transform_id=""):
    errors = errors or []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if errors else "success", "errors": errors},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "error" if errors else "success", "errors": errors,
                               "inputSummary": summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.now(timezone.utc).isoformat(), "schemaVersion": "1.0",
                         "transformationId": transform_id, "vendor": VENDOR, "category": CATEGORY},
        },
    }


def text_of(value):
    return value.strip() if isinstance(value, str) else ""


def top_problem(top, label):
    """A cut-off or partly failed fan-out is never a smaller estate."""
    if top.get("iterateTruncated"):
        return label + ": more items exist than were read"
    count = top.get("itemErrors")
    if isinstance(count, int) and not isinstance(count, bool) and count > 0:
        return label + ": " + str(count) + " item read(s) failed"
    return None


def list_problem(listing, label):
    """One page of a vendor list: refused, unreadable, or with a NextToken (more behind it)."""
    problem = response_problem(listing, label)
    if problem:
        return problem
    if listing["Response"].get("NextToken"):
        return label + ": the list has more pages than were read"
    return None


KEY = "restApiTokenExpiryEnforced"
CEILING = 1440


def transform(input):
    try:
        data = parse(input)
        top = unwrap(data, ("Response",))
        if top is None:
            return build_response({KEY: None}, errors=[error_text(data) or "no Response in the answer"],
                                  transform_id=KEY)
        problem = response_problem(top, "programmatic access read")
        if problem:
            return build_response({KEY: None}, errors=[problem], transform_id=KEY)
        body = top["Response"]
        if body.get("Enabled") is not True:
            return build_response({KEY: None}, errors=[
                "programmatic access is not reported enabled, so no token expiry was measured"],
                transform_id=KEY)
        ceiling = body.get("MaxExpiryTime")
        if isinstance(ceiling, bool) or not isinstance(ceiling, int):
            return build_response({KEY: None}, errors=["MaxExpiryTime is missing or not a whole number"],
                                  transform_id=KEY)
        summary = {"maxExpiryTime": ceiling}
        if ceiling < 1 or ceiling > CEILING:
            return build_response({KEY: False}, fail_reasons=[
                "the tenant's token expiry ceiling is " + str(ceiling) + ", outside 1 to " + str(CEILING)],
                summary=summary,
                recommendations=["Lower the programmatic access token expiry ceiling for the tenant."],
                transform_id=KEY)
        return build_response({KEY: True}, pass_reasons=[
            "Programmatic access tokens expire within the tenant ceiling of " + str(ceiling)],
            summary=summary, transform_id=KEY)
    except Exception as error:
        return build_response({KEY: None}, errors=[str(error)[:300]], transform_id=KEY)
