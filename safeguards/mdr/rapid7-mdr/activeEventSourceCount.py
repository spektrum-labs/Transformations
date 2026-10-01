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

    logs = []
    if isinstance(data, dict):
        logs = data.get("logs") or []
    elif isinstance(data, list):
        logs = data

    if not isinstance(logs, list):
        logs = []

    total_logs = len(logs)

    active_logs = 0
    inactive_logs = 0
    for log in logs:
        if not isinstance(log, dict):
            continue
        tokens = log.get("tokens") or []
        structures = log.get("structures") or []
        has_tokens = isinstance(tokens, list) and len(tokens) > 0
        has_structures = isinstance(structures, list) and len(structures) > 0
        if has_tokens or has_structures:
            active_logs = active_logs + 1
        else:
            inactive_logs = inactive_logs + 1

    fail_reasons = []
    pass_reasons = []
    recommendations = []

    if total_logs == 0:
        fail_reasons.append(
            "No Log resources were returned from the Log Search management API "
            "(log_search/management/logs), so no event sources are currently configured."
        )
        recommendations.append(
            "Configure at least one Log resource (event source) in InsightIDR Log Search."
        )
    else:
        pass_reasons.append(
            f"The Log Search management API returned {total_logs} configured Log resources, "
            f"of which {active_logs} carry an active data-feeding token and/or log structure "
            f"binding (tokens/structures non-empty), indicating they are actively ingesting data."
        )
        if inactive_logs > 0:
            pass_reasons.append(
                f"{inactive_logs} of the {total_logs} Log resources have no tokens or structures "
                f"assigned and were excluded from the active count."
            )

    result = {
        "activeEventSourceCount": active_logs if total_logs > 0 else 0,
        "totalConfiguredLogs": total_logs,
        "inactiveLogs": inactive_logs,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalLogs": total_logs, "activeLogs": active_logs, "inactiveLogs": inactive_logs},
        metadata={
            "transformationId": "activeEventSourceCount",
            "vendor": "Rapid7 MDR",
            "category": "mdr",
        },
    )
