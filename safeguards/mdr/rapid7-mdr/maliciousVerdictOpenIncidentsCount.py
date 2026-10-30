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


OPEN_STATUSES = ["OPEN", "INVESTIGATING", "WAITING"]


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        items = data
        metadata_block = {}
    elif isinstance(data, dict):
        items = data.get("data") or []
        if not isinstance(items, list):
            items = []
        metadata_block = data.get("metadata") or {}
    else:
        items = []
        metadata_block = {}

    total_investigations = len(items)
    open_count = 0
    malicious_open_count = 0
    matched_titles = []

    for inv in items:
        if not isinstance(inv, dict):
            continue
        status = inv.get("status") or ""
        disposition = inv.get("disposition") or ""
        status_u = status.upper()
        disposition_u = disposition.upper()
        if status_u in OPEN_STATUSES:
            open_count = open_count + 1
            if disposition_u == "MALICIOUS":
                malicious_open_count = malicious_open_count + 1
                if len(matched_titles) < 5:
                    matched_titles.append(inv.get("title") or inv.get("rrn") or "unknown")

    total_data = metadata_block.get("total_data")
    if not isinstance(total_data, int):
        total_data = total_investigations

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if malicious_open_count > 0:
        sample = ", ".join(matched_titles)
        pass_reasons.append(
            f"Found {malicious_open_count} open investigations (status in {OPEN_STATUSES}) with disposition=MALICIOUS "
            f"out of {open_count} open investigations examined (page covers {total_investigations} of {total_data} total investigations). "
            f"Examples: {sample}"
        )
    else:
        fail_reasons.append(
            f"No open investigations (status in {OPEN_STATUSES}) with disposition=MALICIOUS were found among "
            f"{open_count} open investigations examined (page covers {total_investigations} of {total_data} total investigations)."
        )
        recommendations.append(
            "Review open investigations for unclassified or UNDECIDED dispositions and ensure analysts triage alerts to set an accurate MALICIOUS/BENIGN disposition."
        )

    result = {
        "maliciousVerdictOpenIncidentsCount": malicious_open_count,
        "openInvestigationsCount": open_count,
        "totalInvestigationsInResponse": total_investigations,
        "totalInvestigationsReportedByVendor": total_data,
    }

    input_summary = {
        "totalInvestigationsInResponse": total_investigations,
        "openInvestigationsCount": open_count,
        "maliciousVerdictOpenIncidentsCount": malicious_open_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "maliciousVerdictOpenIncidentsCount",
            "vendor": "Rapid7 MDR",
            "category": "mdr",
        },
    )
