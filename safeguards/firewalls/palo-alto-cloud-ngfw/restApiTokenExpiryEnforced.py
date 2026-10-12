"""
Transformation: restApiTokenExpiryEnforced
Vendor: Palo Alto Networks Cloud NGFW (AWS)  |  Category: Firewalls

Integration-Service method describeProgrammaticAccess:
  GET /v1/mgmt/tokens ("Describe programmatic access")
  -> {"Response": {"Enabled": bool, "MaxExpiryTime": int}, "ResponseStatus": {"ErrorCode": 0}}

NOT WIRED: this key is not in the Integration-Service definition's retrievalTransformationArray, so
it shows as not covered. The file stays as a documented placeholder until a read can show both outcomes.

Value: None (Not evaluated) on every read. The reference bounds the tenant ceiling MaxExpiryTime
to 480 through 1440 (the unit is not stated), so every value the vendor can return is inside that
range and "bounded" would always be True. This is the tenant-wide ceiling on token lifetime, not a
read of any one token. The key answers only after a read that can be both True and False replaces
this one. A refused (401/403), expired-token, error-shaped, empty or unrecognised read, programmatic
access reported disabled (no token is issued), or a ceiling that is not a whole number is null with
the specific reason.

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
REASON = ("the vendor reference bounds MaxExpiryTime to 480 through 1440, so any value it can return is inside "
          "that range and cannot show expiry is not enforced; not evaluated until a read can")


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
        return build_response({KEY: None}, errors=[REASON], summary={"maxExpiryTime": ceiling},
                              transform_id=KEY)
    except Exception as error:
        return build_response({KEY: None}, errors=[str(error)[:300]], transform_id=KEY)
