
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
        items = data.get("data") or data.get("results") or []
        if isinstance(items, dict):
            items = items.get("data") or []
    else:
        items = []

    if not isinstance(items, list):
        items = []

    critical_open = []
    deactivated_statuses = ["CLOSED", "DEACTIVATED", "RESOLVED", "FIXED", "REMEDIATED"]
    for v in items:
        if not isinstance(v, dict):
            continue
        severity = (v.get("severity") or "").upper()
        status = (v.get("status") or "").upper()
        is_deactivated = status in deactivated_statuses or v.get("isDeactivated") is True
        if severity == "CRITICAL" and not is_deactivated:
            critical_open.append(v)

    count = len(critical_open)
    total = len(items)

    if total == 0:
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if count == 0:
            pass_reasons.append(
                "No vulnerability records were returned by getVulnerabilities; 0 open CRITICAL vulnerabilities found across 0 total records."
            )
    else:
        if count > 0:
            sample_ids = [v.get("id") or v.get("name") or "unknown" for v in critical_open[:5]]
            fail_reasons.append(
                f"Found {count} open (non-deactivated) vulnerabilities with severity CRITICAL out of {total} total vulnerability records. Sample ids: {sample_ids}."
            )
            recommendations.append(
                "Remediate or deactivate the open CRITICAL severity vulnerabilities identified in Vanta's vulnerability feed to reduce exposure."
            )
            pass_reasons = []
        else:
            pass_reasons = [
                f"Reviewed {total} vulnerability records; none are both severity=CRITICAL and in an open (non-deactivated) status."
            ]
            fail_reasons = []
            recommendations = []

    result = {
        "openCriticalVulnerabilitiesCount": count,
        "totalVulnerabilitiesEvaluated": total,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalVulnerabilities": total, "openCriticalVulnerabilities": count},
        metadata={
            "transformationId": "openCriticalVulnerabilitiesCount",
            "vendor": "Vanta Compliance Automation",
            "category": "compliance",
        },
    )
