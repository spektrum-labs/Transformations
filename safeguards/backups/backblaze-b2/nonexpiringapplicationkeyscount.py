"""nonExpiringApplicationKeysCount for Backblaze B2.

Count of application keys with no expiry.

Reads b2_list_keys (native API v4, which lists single-bucket, multi-bucket and all-bucket keys); needs
the listKeys capability. expirationTimestamp absent or null means the key never expires. The account's
master application key is not listed by Backblaze and is not counted. A partial list (more pages
remain), an empty list or an error body is not evaluated.
"""


import json
from datetime import datetime


VENDOR = "Backblaze B2"
WRAPPERS = ("apiResponse", "api_response", "response", "result", "Output", "data", "body")
LISTING_LIMIT = 20
CRITERIA_KEY = "nonExpiringApplicationKeysCount"


def extract_input(input_data):
    """Split the enriched {"data", "validation"} input; a legacy body passes through as data."""
    validation = {"status": "unknown", "errors": [], "warnings": []}
    data = input_data
    if isinstance(data, dict) and "data" in data and "validation" in data:
        if isinstance(data.get("validation"), dict):
            validation = data.get("validation")
        data = data.get("data")
    return data, validation


def as_json(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return json.loads(text)
        except ValueError:
            return None
    return value


def find_body(data, field):
    """The object carrying `field`, found through the response envelopes; None when none does."""
    depth = 0
    while depth < 6:
        depth += 1
        data = as_json(data)
        if not isinstance(data, dict):
            return None
        if field in data:
            return data
        inner = None
        for key in WRAPPERS:
            if key in data and isinstance(data.get(key), (dict, str, bytes)):
                inner = data.get(key)
                break
        if inner is None:
            return None
        data = inner
    return None


def describe_refusal(data):
    """B2's status and error code when the body is an error, never its message text."""
    probe = as_json(data)
    status = None
    code = None
    depth = 0
    while isinstance(probe, dict) and depth < 6:
        depth += 1
        for key in ("status", "statusCode", "status_code"):
            if status is None and isinstance(probe.get(key), (int, str)):
                status = str(probe.get(key))[:40]
        if code is None and isinstance(probe.get("code"), str):
            code = probe.get("code")[:60]
        inner = None
        for key in WRAPPERS:
            if isinstance(probe.get(key), (dict, str)):
                inner = as_json(probe.get(key))
                break
        probe = inner
    if status and code:
        return " (status " + status + ", " + code + ")"
    if status:
        return " (status " + status + ")"
    return ""


def names(items):
    shown = [str(item) for item in items[:LISTING_LIMIT]]
    more = len(items) - len(shown)
    return ", ".join(shown) + (" and " + str(more) + " more" if more > 0 else "")


def read_keys(input_data):
    """(keys, validation, problem) from a b2_list_keys body; a partial page is a problem."""
    data, validation = extract_input(input_data)
    body = find_body(data, "keys")
    if body is None:
        return None, validation, "Backblaze returned no application key list" + describe_refusal(data) + "."
    keys = body.get("keys")
    if not isinstance(keys, list):
        return None, validation, "The Backblaze application key list was not a list."
    if body.get("nextApplicationKeyId"):
        return None, validation, ("The application key list is incomplete (Backblaze reports more pages), "
                                  "so a count from it would be an undercount.")
    keys = [key for key in keys if isinstance(key, dict)]
    if not keys:
        return None, validation, ("Backblaze listed no application keys. The key Spektrum connects with should "
                                  "itself appear, so this list proves nothing.")
    return keys, validation, None


def key_label(key):
    return str(key.get("keyName") or key.get("applicationKeyId") or "unnamed key")


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Create the standardized 5-section transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_err_list else "success", "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": "error" if transform_err_list else "success",
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


def respond(value, validation, problem=None, pass_reasons=None, fail_reasons=None,
            recommendations=None, summary=None):
    """A verdict, or None with the reason it could not be measured."""
    if value is None and not problem:
        problem = "The Backblaze response did not show enough to decide " + CRITERIA_KEY + "."
    return create_response(
        result={CRITERIA_KEY: value},
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=summary,
        api_errors=[problem] if value is None else None,
        metadata={"transformationId": CRITERIA_KEY, "vendor": VENDOR, "category": "backup"},
    )


def evaluate(input):
    keys, validation, problem = read_keys(input)
    if problem:
        return respond(None, validation, problem)
    lasting = [key_label(k) for k in keys if k.get("expirationTimestamp") is None]
    summary = {"totalKeys": len(keys), "nonExpiringKeys": len(lasting)}
    if lasting:
        return respond(len(lasting), validation,
                       fail_reasons=[str(len(lasting)) + " of " + str(len(keys)) + " application key(s) never "
                                     "expire: " + names(lasting) + "."],
                       recommendations=["Replace long-lived keys with keys created with an expiry "
                                        "(validDurationInSeconds), and delete keys no longer in use."],
                       summary=summary)
    return respond(0, validation,
                   pass_reasons=["All " + str(len(keys)) + " application key(s) have an expiry."],
                   summary=summary)


def transform(input):
    try:
        return evaluate(input)
    except Exception as e:
        return create_response(
            result={CRITERIA_KEY: None},
            api_errors=["The Backblaze response could not be read, so " + CRITERIA_KEY + " was not measured."],
            transformation_errors=[str(e)[:200]],
            metadata={"transformationId": CRITERIA_KEY, "vendor": VENDOR, "category": "backup"},
        )
