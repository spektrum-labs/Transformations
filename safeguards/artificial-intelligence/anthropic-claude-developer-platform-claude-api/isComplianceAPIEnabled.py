import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
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


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("data") or []
    else:
        items = []

    if not isinstance(items, list):
        items = []

    record_count = len(items)
    compliance_access_events = [
        r for r in items
        if isinstance(r, dict) and r.get("type") == "compliance_api_accessed"
    ]
    compliance_event_count = len(compliance_access_events)

    is_enabled = record_count > 0

    if is_enabled:
        pass_reasons = [
            f"Compliance API Activity Feed (/v1/compliance/activities) returned HTTP 200 with {record_count} activity records, including {compliance_event_count} 'compliance_api_accessed' events, confirming the org's Admin API key carries the read:compliance_activities scope and the Compliance API is enabled."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            "The Compliance Activity Feed (/v1/compliance/activities) returned zero records for this organization, providing no evidence that the Compliance API is enabled."
        ]
        recommendations = [
            "Enable the Compliance API for this organization and ensure the Admin API key has the read:compliance_activities scope."
        ]

    result = {
        "isComplianceAPIEnabled": is_enabled,
        "totalActivityRecords": record_count,
        "complianceApiAccessedEvents": compliance_event_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalActivityRecords": record_count, "complianceApiAccessedEvents": compliance_event_count},
        metadata={
            "transformationId": "isComplianceAPIEnabled",
            "vendor": "Anthropic Claude Developer Platform Claude API",
            "category": "Artificial Intelligence",
        },
    )
