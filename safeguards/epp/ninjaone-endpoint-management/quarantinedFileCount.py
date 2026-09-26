
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
        threats = data
    elif isinstance(data, dict):
        threats = data.get("results") or data.get("data") or []
        if not isinstance(threats, list):
            threats = []
    else:
        threats = []

    quarantine_statuses = ["QUARANTINE", "QUARANTINED"]
    quarantined = []
    other_statuses = []
    for t in threats:
        if not isinstance(t, dict):
            continue
        status = t.get("status")
        status_upper = status.upper() if isinstance(status, str) else ""
        if any(qs in status_upper for qs in quarantine_statuses):
            quarantined.append(t)
        else:
            other_statuses.append(status)

    quarantined_count = len(quarantined)
    total_threats = len(threats)

    if total_threats == 0:
        pass_reasons = []
        fail_reasons = ["The antivirus threats report (getAntivirusThreats) returned zero threat records for this tenant, so no quarantined files could be identified."]
        recommendations = ["Verify the antivirus product is actively scanning and reporting threats; if the fleet is genuinely clean, no action is needed."]
    else:
        sample_names = [t.get("fileName") or t.get("threatName") for t in quarantined[:5]]
        pass_reasons = [
            f"Found {quarantined_count} of {total_threats} threat records with a quarantine status (e.g. {sample_names})."
        ] if quarantined_count > 0 else []
        fail_reasons = [] if quarantined_count > 0 else [
            f"None of the {total_threats} threat records reported a quarantine status; statuses observed: {list(set(other_statuses))[:10]}."
        ]
        recommendations = []

    input_summary = {
        "totalThreatRecords": total_threats,
        "quarantinedFileCount": quarantined_count,
    }

    return create_response(
        result={
            "quarantinedFileCount": quarantined_count,
            "totalThreatRecords": total_threats,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={"transformationId": "quarantinedFileCount", "vendor": "NinjaOne", "category": "epp"},
    )
