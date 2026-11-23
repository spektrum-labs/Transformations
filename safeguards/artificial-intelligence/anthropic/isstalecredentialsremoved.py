"""
Transformation: isStaleCredentialsRemoved
Vendor: Anthropic  |  Category: Artificial Intelligence
Product: Claude Developer Platform (Claude API)
Evaluates: Ensures no active organization API key has been in service beyond the maximum permitted age without rotation.
API Source: listApiKeys
"""
import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
    # Decode a JSON string or bytes BEFORE inspecting shape. Without this a str body
    # matches no branch here, stays a str, and every caller's `isinstance(data, dict)`
    # test fails -- so a perfectly good response is read as "nothing came back" and the
    # criterion is answered from an empty shape. CLAUDE.md's `_parse_input` pattern makes
    # str, bytes and dict equivalent everywhere else in this repo; this family did not.
    # A string that is not JSON raises into each transform's existing handler: fail closed.
    if isinstance(input_data, (str, bytes)):
        if isinstance(input_data, bytes):
            input_data = input_data.decode("utf-8")
        input_data = json.loads(input_data)
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
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
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


#: The criterion key Token-Service extracts from this file's transformedResponse. Every
#: result dict below is built with this same name, so the name that carries the answer and
#: the name create_response reads to decide whether there WAS an answer cannot drift apart.
#: That is the whole difference from a separate list of key names, which can be -- and has
#: been -- left behind when a file gains a key.
CRITERION = "isStaleCredentialsRemoved"


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Create the standardized 5-section transformation response."""
    # Value-keyed, never name-keyed. A criterion reported as None was not measured, and
    # Token-Service grades an unmeasured criterion as FAILED unless dataCollection.status is
    # "error" -- which only a non-empty api_errors produces. Deriving that from the criterion's
    # own value covers the branches nobody thought about, transform()'s except included,
    # because the branch never has to remember to say so.
    if not api_errors and isinstance(result, dict) and result.get(CRITERION) is None:
        api_errors = (list(fail_reasons or []) or list(transformation_errors or [])
                      or ["The response could not answer this check, so it was not evaluated."])
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    data_collection_status = "error" if api_err_list else "success"
    transformation_status = "error" if transform_err_list else "success"
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": data_collection_status, "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": transformation_status,
                "errors": transform_err_list,
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": response_metadata,
        },
    }


METADATA = {
    "transformationId": "isStaleCredentialsRemoved",
    "vendor": "Anthropic",
    "category": "Artificial Intelligence",
}


# Unique sentinel. object() is unavailable in the RestrictedPython sandbox
# Token-Service runs transforms in, so a fresh list is used instead: a list
# literal is never interned, which keeps the "is MISSING" identity checks valid.
MISSING = ["__missing__"]

# HTTP status -> why the call was refused. These are NOT posture findings: they mean
# the credential or tenancy cannot reach the endpoint, so the control is UNKNOWN
# rather than absent. Anthropic's compliance org-data endpoints (settings, groups,
# organizations, users) accept only a Compliance Access Key (sk-ant-api01-...)
# created in claude.ai; an Admin API key (sk-ant-admin01-...) gets 403, and a
# standalone Claude Console organization can reach the Activity Feed only.
REFUSAL_REASONS = {
    401: ("the credential was rejected",
          "Confirm the key is an admin-class key and has not been revoked or expired."),
    403: ("this organization's credential is not permitted to call the endpoint",
          "This endpoint requires a Compliance Access Key (sk-ant-api01-...) created in "
          "claude.ai > Organization settings > API with the read:org_audit scope. An Admin "
          "API key (sk-ant-admin01-...) from Claude Console returns 403 here. A standalone "
          "Claude Console organization cannot read these settings at all - treat this "
          "criterion as not applicable for that tenant rather than failed."),
    404: ("the endpoint or organization was not found",
          "Check the Organization ID. The compliance endpoints take a compliance "
          "organization uuid from GET /v1/compliance/organizations, which is a different "
          "value from the Console organization id shown at "
          "platform.claude.com/settings/organization."),
    429: ("the vendor rate-limited the call",
          "Compliance endpoints allow 600 requests/minute per parent organization. Retry."),
}


# Anthropic's documented error body carries no HTTP status of its own: it is
# {"error": {"type": ..., "message": ...}} and the status is on the response. The vendor's
# guidance is "Match on the HTTP status code and error.type, not on the message string"
# (compliance-errors.md), so the type is mapped back to the status REFUSAL_REASONS is keyed
# on. Without this the tailored 403 paragraph -- the one that tells an administrator to swap
# their key class -- never fires on the shape Anthropic actually sends.
ERROR_TYPE_STATUS = {
    "authentication_error": 401,
    "permission_error": 403,
    "not_found_error": 404,
    "rate_limit_error": 429,
}


def detect_refusal(data):
    """Return (status, why, fix) when the payload is an error envelope, else None.

    Three shapes reach a transform: Anthropic's own ({"error": {"type", "message"}}), the
    generic one (error / errorType / status == "Error" alongside statusCode), and
    Integration-Service's vendor relay ({"errorMessage", "vendorStatus": 403, ...}), which is
    what /integration/run returns when the vendor refuses.
    """
    if not isinstance(data, dict):
        return None
    err = data.get("error")
    relay_status = data.get("vendorStatus")
    is_relay = "errorMessage" in data or relay_status is not None
    is_generic = bool(err or data.get("errorType") or data.get("status") == "Error")
    if not (is_relay or is_generic):
        return None
    status = relay_status if relay_status is not None else (data.get("statusCode") or data.get("status_code"))
    try:
        status = int(status)
    except (TypeError, ValueError):
        status = None
    if status is None and isinstance(err, dict):
        status = ERROR_TYPE_STATUS.get(err.get("type"))
    why, fix = REFUSAL_REASONS.get(status, (
        "the vendor call did not succeed",
        "Inspect the integration method response for the underlying error."))
    detail = data.get("errorMessage") or data.get("message") or ""
    if not detail and isinstance(err, dict):
        detail = err.get("message") or ""
    if detail:
        why = why + " (" + str(detail) + ")"
    return status, why, fix


def as_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("true", "yes", "1", "enabled", "on")
    return bool(value)


def settings_map(data):
    """Reduce the effective-settings rows to {name: value}.

    A setting this organization's administrators cannot change is omitted from
    the response entirely, so a missing name means "not controllable here",
    never "off". Callers must distinguish absent from False, which is why this
    returns a plain dict and callers use the _MISSING sentinel.
    """
    rows = None
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict):
        for key in ("data", "settings"):
            if isinstance(data.get(key), list):
                rows = data[key]
                break
    if rows is None:
        rows = []
    out = {}
    for row in rows:
        if isinstance(row, dict) and row.get("name") is not None:
            out[row["name"]] = row.get("value", MISSING)
    return out


from datetime import timezone

MAX_KEY_AGE_DAYS = 365


def parse_ts(value):
    if not isinstance(value, str) or not value:
        return None
    text = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def evaluate(input):
    data, validation = extract_input(input)
    # Token-Service navigates into the response's "data" key (codeexecutor
    # navigation_keys), so this transform usually receives the bare navigated
    # value. Accept that, the returnSpec-mapped dict, and the raw API body so
    # the same file works in the live pipeline and in direct/local testing.
    refusal = detect_refusal(data)
    if refusal:
        refusal_status, refusal_why, refusal_fix = refusal
        return create_response(
            result={"isStaleCredentialsRemoved": None, "endpointReachable": False, "httpStatus": refusal_status},
            validation=validation,
            fail_reasons=[
                "The vendor call did not return data because " + refusal_why +
                ". This is a connectivity or credential-scope result, not a finding about "
                "the organization's configuration - the control's real state is unknown."
            ],
            recommendations=[refusal_fix],
            input_summary={"endpointReachable": False, "httpStatus": refusal_status},
            metadata=METADATA,
        )

    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("data")
        if not isinstance(items, list):
            items = data.get("apiKeys")
    else:
        items = None
    # "No key list came back" and "a key list came back and it was empty" are different
    # facts, and `items = []` used to mean both -- so the pass-on-absence branch below
    # reported isStaleCredentialsRemoved TRUE for a null body and an unrecognised shape
    # alike. Measured 2026-09-21: transform(None) returned True. The branch's own reason,
    # "the organization has no active API keys, so no credential can be stale", is a claim
    # about a list that was READ; it says nothing about a call that returned nothing.
    items_returned = isinstance(items, list)
    if not items_returned:
        items = []

    active = [k for k in items if isinstance(k, dict) and str(k.get("status", "")).lower() == "active"]

    if not items_returned:
        return create_response(
            result={"isStaleCredentialsRemoved": None, "activeKeyCount": 0, "staleKeyCount": 0,
                    "staleKeyNames": [], "maxAgeDays": MAX_KEY_AGE_DAYS},
            validation=validation,
            fail_reasons=[
                "listApiKeys returned no key list at all -- the body was absent, an error "
                "envelope, or a shape this transform does not recognise. Nothing was read, "
                "so credential staleness could be neither confirmed nor refuted. This is "
                "NOT the zero-active-keys pass below: that one requires a list."
            ],
            recommendations=[
                "Confirm the Admin API key is valid and that listApiKeys returned a 2xx with "
                "a `data` or `apiKeys` array before reading this criterion."
            ],
            input_summary={"keyListReturned": False},
            metadata=METADATA,
        )

    # Same guard as the expiry sibling: "no active keys" is only a pass when the objects were
    # readable. A list of objects with no status is an unread list wearing an empty one's
    # clothes, and this branch's pass is asserted from the filter finding nothing.
    if items and not [k for k in items if isinstance(k, dict) and k.get("status") is not None]:
        return create_response(
            result={"isStaleCredentialsRemoved": None, "activeKeyCount": 0, "staleKeyCount": 0,
                    "staleKeyNames": [], "maxAgeDays": MAX_KEY_AGE_DAYS},
            validation=validation,
            fail_reasons=[
                "listApiKeys returned " + str(len(items)) + " object(s) and not one carried a "
                "status, so no key could be classified as active. This is not the zero-active-keys "
                "pass: nothing was read."
            ],
            recommendations=["Inspect the raw listApiKeys response for the status field."],
            input_summary={"keysReturned": len(items), "keysReportingStatus": 0},
            metadata=METADATA,
        )

    if not active:
        return create_response(
            result={"isStaleCredentialsRemoved": True, "activeKeyCount": 0, "staleKeyCount": 0,
                    "staleKeyNames": [], "maxAgeDays": MAX_KEY_AGE_DAYS},
            validation=validation,
            pass_reasons=["The organization has no active API keys, so no credential can be stale."],
            input_summary={"keysReturned": len(items), "activeKeyCount": 0},
            metadata=METADATA,
        )

    now = datetime.now(timezone.utc)
    stale = []
    unparseable = []
    oldest_days = 0
    for key in active:
        created = parse_ts(key.get("created_at"))
        name = str(key.get("name") or key.get("id") or "unnamed")
        if created is None:
            unparseable.append(name)
            continue
        age_days = int((now - created).total_seconds() // 86400)
        if age_days > oldest_days:
            oldest_days = age_days
        if age_days > MAX_KEY_AGE_DAYS:
            stale.append(name + " (" + str(age_days) + "d)")

    result = not stale and not unparseable

    if result:
        pass_reasons = [
            "All " + str(len(active)) + " active API key(s) are within the " + str(MAX_KEY_AGE_DAYS) +
            " day maximum age; the oldest is " + str(oldest_days) + " days old."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = []
        if stale:
            fail_reasons.append(
                str(len(stale)) + " of " + str(len(active)) + " active API key(s) exceed the " +
                str(MAX_KEY_AGE_DAYS) + " day maximum age: " + ", ".join(sorted(stale)) + "."
            )
        if unparseable:
            fail_reasons.append(
                "The created_at timestamp could not be parsed for " + str(len(unparseable)) +
                " active key(s): " + ", ".join(sorted(unparseable)) +
                ". An unreadable age is treated as unproven rather than assumed compliant."
            )
        recommendations = [
            "Rotate keys older than " + str(MAX_KEY_AGE_DAYS) + " days in Claude Console > "
            "Settings > API keys and deactivate the originals."
        ]

    return create_response(
        result={
            "isStaleCredentialsRemoved": result,
            "activeKeyCount": len(active),
            "staleKeyCount": len(stale),
            "staleKeyNames": sorted(stale),
            "unparseableKeyNames": sorted(unparseable),
            "oldestActiveKeyDays": oldest_days,
            "maxAgeDays": MAX_KEY_AGE_DAYS,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"keysReturned": len(items), "activeKeyCount": len(active),
                       "oldestActiveKeyDays": oldest_days},
        metadata=METADATA,
    )


def transform(input):
    try:
        return evaluate(input)
    except Exception as exc:  # never raise into the pipeline
        return create_response(
            result={"isStaleCredentialsRemoved": None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(exc)],
            fail_reasons=["Transformation raised an unexpected error: " + str(exc)],
            recommendations=["Report this to the Spektrum integrations team with the raw API response."],
            metadata=METADATA,
        )
