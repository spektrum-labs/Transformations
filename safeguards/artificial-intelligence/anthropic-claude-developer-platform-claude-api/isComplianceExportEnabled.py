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


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("data") or []
        if not isinstance(items, list):
            items = []
    else:
        items = []

    total_activities = len(items)

    explicit_enabled_flag = False
    explicit_logging_flag = False
    compliance_accessed_count = 0
    explicit_evidence_record_id = None

    for rec in items:
        if not isinstance(rec, dict):
            continue
        if rec.get("compliance_api_enabled") is True:
            explicit_enabled_flag = True
            explicit_evidence_record_id = rec.get("id")
        if rec.get("compliance_api_logging_enabled") is True:
            explicit_logging_flag = True
        if rec.get("type") == "compliance_api_accessed" and rec.get("status_code") == 200:
            compliance_accessed_count = compliance_accessed_count + 1

    is_enabled = explicit_enabled_flag or (compliance_accessed_count > 0)

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if explicit_enabled_flag:
        pass_reasons.append(
            "Compliance activity record %s carries compliance_api_enabled=true, confirming the Enterprise Compliance API entitlement is active." % explicit_evidence_record_id
        )
    if explicit_logging_flag:
        pass_reasons.append(
            "At least one activity record carries compliance_api_logging_enabled=true, indicating compliance logging/export is configured."
        )
    if compliance_accessed_count > 0:
        pass_reasons.append(
            "%d of %d activity records have type=compliance_api_accessed with status_code=200, showing the Compliance API Activity Feed (the export/audit mechanism) was successfully polled by an admin API key." % (compliance_accessed_count, total_activities)
        )

    if not is_enabled:
        fail_reasons.append(
            "No activity record carried compliance_api_enabled=true, no compliance_api_logging_enabled flag was seen, and no compliance_api_accessed events (status_code=200) were found among %d activity records." % total_activities
        )
        recommendations.append(
            "Enable the Enterprise Compliance API entitlement for this organization and confirm an admin API key with read:compliance_activities scope can successfully poll /v1/compliance/activities."
        )

    result = {
        "isComplianceExportEnabled": is_enabled,
        "totalActivitiesEvaluated": total_activities,
        "complianceApiAccessedEventCount": compliance_accessed_count,
        "explicitComplianceApiEnabledFlagFound": explicit_enabled_flag,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalActivities": total_activities,
            "complianceApiAccessedCount": compliance_accessed_count,
        },
        metadata={
            "transformationId": "isComplianceExportEnabled",
            "vendor": "Anthropic Claude Developer Platform Claude API",
            "category": "artificial-intelligence",
        },
    )
