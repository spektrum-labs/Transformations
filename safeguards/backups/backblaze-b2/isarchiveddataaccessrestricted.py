"""isArchivedDataAccessRestricted for Backblaze B2.

True when no bucket in the account is public.

Reads b2_list_buckets (native API v4). Backblaze lists allPublic, allPrivate and snapshot buckets by
default; allPublic means anyone can download the files. True only when every listed bucket is
allPrivate or snapshot. Any allPublic bucket is False. A bucket type Backblaze does not document as
private, an empty bucket list or an error body is not evaluated.
"""


import json
from datetime import datetime


VENDOR = "Backblaze B2"
WRAPPERS = ("apiResponse", "api_response", "response", "result", "Output", "data", "body")
LISTING_LIMIT = 20
CRITERIA_KEY = "isArchivedDataAccessRestricted"


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


def bucket_label(bucket):
    return str(bucket.get("bucketName") or bucket.get("bucketId") or "unnamed bucket")


def read_buckets(input_data):
    """(buckets, validation, problem) from a b2_list_buckets body."""
    data, validation = extract_input(input_data)
    body = find_body(data, "buckets")
    if body is None:
        return None, validation, "Backblaze returned no bucket list" + describe_refusal(data) + "."
    buckets = body.get("buckets")
    if not isinstance(buckets, list):
        return None, validation, "The Backblaze bucket list was not a list."
    buckets = [bucket for bucket in buckets if isinstance(bucket, dict)]
    if not buckets:
        return None, validation, "The account lists no buckets, so there is nothing to judge."
    return buckets, validation, None


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


PRIVATE_TYPES = ("allPrivate", "snapshot")


def evaluate(input):
    buckets, validation, problem = read_buckets(input)
    if problem:
        return respond(None, validation, problem)
    public = [bucket_label(b) for b in buckets if b.get("bucketType") == "allPublic"]
    unknown = [bucket_label(b) + " (" + str(b.get("bucketType")) + ")" for b in buckets
               if b.get("bucketType") != "allPublic" and b.get("bucketType") not in PRIVATE_TYPES]
    summary = {"totalBuckets": len(buckets), "publicBuckets": len(public), "unrecognisedBuckets": len(unknown)}
    if public:
        return respond(False, validation,
                       fail_reasons=[str(len(public)) + " of " + str(len(buckets)) + " bucket(s) are public "
                                     "(allPublic), so anyone can download their files: " + names(public) + "."],
                       recommendations=["Set these buckets to Private in the Backblaze web console "
                                        "(Buckets > Bucket Settings) unless they are meant to be public."],
                       summary=summary)
    if unknown:
        return respond(None, validation,
                       "Backblaze reported bucket type(s) it does not document as private: " + names(unknown) + ".",
                       summary=summary)
    return respond(True, validation,
                   pass_reasons=["All " + str(len(buckets)) + " bucket(s) are private (allPrivate or snapshot)."],
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
