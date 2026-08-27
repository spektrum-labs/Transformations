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

    # Normalize to an iterable of vulnerability records.
    if isinstance(data, dict):
        # If the dict looks like a single vuln record (has id/title at top
        # level), wrap it. Otherwise treat it as the id -> record map that
        # the Wordfence production feed returns.
        if "id" in data and "title" in data:
            records = [data]
        else:
            records = list(data.values())
    elif isinstance(data, list):
        records = data
    else:
        records = []

    total_records = len(records)
    critical_count = 0
    critical_titles = []
    unparseable = 0

    for rec in records:
        if not isinstance(rec, dict):
            unparseable = unparseable + 1
            continue
        cvss = rec.get("cvss")
        cvss = cvss if isinstance(cvss, dict) else {}
        rating_raw = cvss.get("rating")
        rating = rating_raw.strip().lower() if isinstance(rating_raw, str) else ""
        score = cvss.get("score")
        score_is_critical = False
        if isinstance(score, (int, float)):
            score_is_critical = score >= 9.0
        is_critical = (rating == "critical") or score_is_critical
        if is_critical:
            critical_count = critical_count + 1
            title = rec.get("title")
            if isinstance(title, str) and len(critical_titles) < 5:
                critical_titles.append(title)

    input_summary = {
        "totalRecordsSeen": total_records,
        "criticalCount": critical_count,
        "unparseableRecords": unparseable,
    }

    if total_records == 0:
        pass_reasons = []
        fail_reasons = [
            "No vulnerability records were present in the getProductionVulnerabilityFeed response, so no critical-severity alert count could be derived."
        ]
        recommendations = [
            "Verify the Wordfence Intelligence API token is valid and the production vulnerability feed endpoint is returning data."
        ]
    elif critical_count > 0:
        sample = ", ".join(critical_titles) if critical_titles else "none captured"
        pass_reasons = [
            f"Scanned {total_records} vulnerability records from getProductionVulnerabilityFeed and found {critical_count} with cvss.rating='Critical' or cvss.score>=9.0. Examples: {sample}."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = [
            f"Scanned {total_records} vulnerability records from getProductionVulnerabilityFeed; none carried a Critical CVSS rating (>=9.0)."
        ]
        fail_reasons = []
        recommendations = []

    result = {
        "openCriticalSeverityAlertsCount": critical_count,
        "totalVulnerabilityRecords": total_records,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "openCriticalSeverityAlertsCount",
            "vendor": "Wordfence Intelligence",
            "category": "Threat Intelligence",
        },
    )
