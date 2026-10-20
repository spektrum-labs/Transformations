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


OPEN_STATUSES = ("OPEN", "INVESTIGATING")


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        items = data
        total_data = len(items)
    elif isinstance(data, dict):
        items = data.get("data") or []
        if not isinstance(items, list):
            items = []
        metadata = data.get("metadata") or {}
        total_data = metadata.get("total_data") if isinstance(metadata, dict) else None
        if not isinstance(total_data, int):
            total_data = len(items)
    else:
        items = []
        total_data = 0

    open_count = 0
    unassigned_open_count = 0
    sample_titles = []

    for inv in items:
        if not isinstance(inv, dict):
            continue
        status = (inv.get("status") or "").upper()
        if status in OPEN_STATUSES:
            open_count = open_count + 1
            assignee = inv.get("assignee")
            if assignee is None:
                unassigned_open_count = unassigned_open_count + 1
                if len(sample_titles) < 5:
                    sample_titles.append(inv.get("title") or inv.get("rrn") or "untitled")

    if unassigned_open_count > 0:
        pass_reasons = [
            f"Found {unassigned_open_count} open/investigating investigations with assignee=null "
            f"out of {open_count} open-status investigations scanned (page sample of {len(items)} "
            f"records, fleet total_data={total_data}). Examples: {', '.join(sample_titles)}."
        ]
        fail_reasons = []
        recommendations = [
            "Assign an analyst to each unassigned open investigation to ensure timely triage."
        ]
    else:
        pass_reasons = [
            f"No open/investigating investigations with a null assignee were found among "
            f"{open_count} open-status investigations scanned in this page sample "
            f"(of {len(items)} total records, fleet total_data={total_data})."
        ]
        fail_reasons = []
        recommendations = []

    result = {
        "unassignedOpenInvestigationsCount": unassigned_open_count,
        "openInvestigationsScanned": open_count,
        "totalRecordsInPage": len(items),
        "fleetTotalInvestigations": total_data,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalRecordsInPage": len(items),
            "openInvestigationsScanned": open_count,
            "unassignedOpenInvestigationsCount": unassigned_open_count,
            "fleetTotalInvestigations": total_data,
        },
        metadata={
            "transformationId": "unassignedOpenInvestigationsCount",
            "vendor": "Rapid7 MDR",
            "category": "mdr",
        },
    )
