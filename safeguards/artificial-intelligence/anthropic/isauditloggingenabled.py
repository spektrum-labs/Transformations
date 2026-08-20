"""
Transformation: isAuditLoggingEnabled
Vendor: Anthropic  |  Category: Artificial Intelligence
Evaluates: Ensures the organization's Compliance API Activity Feed is recording and readable, providing a six-year audit trail.
API Source: listComplianceActivities
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
    "transformationId": "isAuditLoggingEnabled",
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
            items = data.get("activities")
    else:
        items = None
    if not isinstance(items, list):
        items = []

    if not items:
        return create_response(
            result={"isAuditLoggingEnabled": False, "activityCount": 0,
                    "mostRecentActivityAt": None, "mostRecentActivityType": None},
            validation=validation,
            fail_reasons=[
                "The Compliance API Activity Feed returned no records, so no audit trail could be "
                "read for this organization. Activities are queryable within one minute of "
                "occurring, so an empty feed on an active tenant indicates the Compliance API is "
                "not enabled or the key lacks the read:compliance_activities scope."
            ],
            recommendations=[
                "Confirm the Compliance API is enabled for the parent organization and that the key "
                "carries read:compliance_activities or read:org_audit."
            ],
            input_summary={"activityCount": 0},
            metadata=METADATA,
        )

    newest = items[0] if isinstance(items[0], dict) else {}
    created_at = newest.get("created_at") or ""
    activity_type = newest.get("type") or ""

    return create_response(
        result={
            "isAuditLoggingEnabled": True,
            "activityCount": len(items),
            "mostRecentActivityAt": created_at,
            "mostRecentActivityType": activity_type,
        },
        validation=validation,
        pass_reasons=[
            "The Compliance API Activity Feed is live and readable; the most recent record is a '" +
            str(activity_type) + "' event at " + str(created_at) +
            ". Activity records are retained for six years."
        ],
        input_summary={"activityCount": len(items), "mostRecentActivityType": activity_type},
        additional_findings=[
            "Only the record count and the newest record's timestamp and type are retained by this "
            "transformation. The actor block (email address, IP address, user agent) present in the "
            "raw response is deliberately discarded."
        ],
        metadata=METADATA,
    )


def transform(input):
    try:
        return _evaluate(input)
    except Exception as exc:  # never raise into the pipeline
        return create_response(
            result={"isAuditLoggingEnabled": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(exc)],
            fail_reasons=["Transformation raised an unexpected error: " + str(exc)],
            recommendations=["Report this to the Spektrum integrations team with the raw API response."],
            metadata=METADATA,
        )
