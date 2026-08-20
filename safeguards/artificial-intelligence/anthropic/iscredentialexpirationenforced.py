"""
Transformation: isCredentialExpirationEnforced
Vendor: Anthropic  |  Category: Artificial Intelligence
Evaluates: Ensures every active organization API key carries an expiration date rather than living indefinitely.
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
    "transformationId": "isCredentialExpirationEnforced",
    "vendor": "Anthropic",
    "category": "Artificial Intelligence",
}


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
            result={"isCredentialExpirationEnforced": True, "activeKeyCount": 0,
                    "keysWithoutExpiry": 0, "nonExpiringKeyNames": []},
            validation=validation,
            pass_reasons=[
                "The organization has no active API keys among the " + str(len(items)) +
                " returned, so no standing non-expiring credential exists. This is the one case "
                "where the criterion passes on absence, and it is recorded explicitly."
            ],
            input_summary={"keysReturned": len(items), "activeKeyCount": 0},
            additional_findings=[
                "A zero active-key result should be corroborated against the customer's expectation; "
                "it can also indicate a scope or pagination problem."
            ],
            metadata=METADATA,
        )

    without_expiry = [k for k in active if not k.get("expires_at")]
    names = sorted(str(k.get("name") or k.get("id") or "unnamed") for k in without_expiry)
    result = not without_expiry

    if result:
        pass_reasons = [
            "All " + str(len(active)) + " active API key(s) carry an expiration date, so no "
            "credential in this organization lives indefinitely."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            str(len(without_expiry)) + " of " + str(len(active)) + " active API key(s) have a null "
            "expires_at and therefore never expire: " + ", ".join(names) + "."
        ]
        recommendations = [
            "Replace the non-expiring keys in Claude Console > Settings > API keys with keys that "
            "carry an expiration, then deactivate the originals."
        ]

    return create_response(
        result={
            "isCredentialExpirationEnforced": result,
            "activeKeyCount": len(active),
            "keysWithoutExpiry": len(without_expiry),
            "nonExpiringKeyNames": names,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"keysReturned": len(items), "activeKeyCount": len(active)},
        metadata=METADATA,
    )


def transform(input):
    try:
        return _evaluate(input)
    except Exception as exc:  # never raise into the pipeline
        return create_response(
            result={"isCredentialExpirationEnforced": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(exc)],
            fail_reasons=["Transformation raised an unexpected error: " + str(exc)],
            recommendations=["Report this to the Spektrum integrations team with the raw API response."],
            metadata=METADATA,
        )
