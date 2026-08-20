"""
Transformation: isStaleCredentialsRemoved
Vendor: Anthropic  |  Category: Artificial Intelligence
Evaluates: Ensures no active organization API key has been in service beyond the maximum permitted age without rotation.
API Source: listApiKeys
"""
import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
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


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Create the standardized 5-section transformation response."""
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


from datetime import timezone

MAX_KEY_AGE_DAYS = 365


def _parse_ts(value):
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


def _evaluate(input):
    data, validation = extract_input(input)
    # Token-Service navigates into the response's "data" key (codeexecutor
    # navigation_keys), so this transform usually receives the bare navigated
    # value. Accept that, the returnSpec-mapped dict, and the raw API body so
    # the same file works in the live pipeline and in direct/local testing.
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("data")
        if not isinstance(items, list):
            items = data.get("apiKeys")
    else:
        items = None
    if not isinstance(items, list):
        items = []

    active = [k for k in items if isinstance(k, dict) and str(k.get("status", "")).lower() == "active"]

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
        created = _parse_ts(key.get("created_at"))
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
        return _evaluate(input)
    except Exception as exc:  # never raise into the pipeline
        return create_response(
            result={"isStaleCredentialsRemoved": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(exc)],
            fail_reasons=["Transformation raised an unexpected error: " + str(exc)],
            recommendations=["Report this to the Spektrum integrations team with the raw API response."],
            metadata=METADATA,
        )
