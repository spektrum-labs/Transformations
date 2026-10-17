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


OPEN_LIKE_STATUSES = ["OPEN", "INVESTIGATING", "WAITING"]


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("data") or []
    else:
        items = []

    total_records = len(items)
    open_critical = []
    for inv in items:
        if not isinstance(inv, dict):
            continue
        status = (inv.get("status") or "").upper()
        priority = (inv.get("priority") or "").upper()
        if status in OPEN_LIKE_STATUSES and priority == "CRITICAL":
            open_critical.append(inv)

    count = len(open_critical)

    titles_sample = [i.get("title") for i in open_critical[:5] if i.get("title")]

    if count > 0:
        pass_reasons = [
            f"Found {count} open investigations with priority=CRITICAL out of {total_records} investigations in this page (statuses considered open-like: {', '.join(OPEN_LIKE_STATUSES)}). Examples: {', '.join(titles_sample)}"
        ]
        fail_reasons = []
        recommendations = [
            "Review and triage the open critical-severity investigations promptly to reduce dwell time."
        ]
    else:
        pass_reasons = []
        fail_reasons = [
            f"No open investigations with priority=CRITICAL found among {total_records} investigations inspected in this page."
        ]
        recommendations = []

    result = {
        "openCriticalSeverityIncidentsCount": count,
        "totalInvestigationsInspected": total_records,
    }

    input_summary = {
        "totalInvestigationsInspected": total_records,
        "openCriticalCount": count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "openCriticalSeverityIncidentsCount",
            "vendor": "Rapid7 MDR",
            "category": "mdr",
        },
    )
