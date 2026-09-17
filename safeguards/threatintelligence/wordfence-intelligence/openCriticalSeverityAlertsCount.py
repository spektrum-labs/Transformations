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

    records = []
    if isinstance(data, dict):
        for key, value in data.items():
            if key in ("_omitted_keys", "_truncated"):
                continue
            if isinstance(value, dict):
                records.append(value)
    elif isinstance(data, list):
        records = [r for r in data if isinstance(r, dict)]

    total_records = len(records)
    critical_count = 0
    sample_titles = []

    for rec in records:
        cvss = rec.get("cvss")
        rating = None
        if isinstance(cvss, dict):
            rating = cvss.get("rating")
        if isinstance(rating, str) and rating.strip().lower() == "critical":
            critical_count = critical_count + 1
            if len(sample_titles) < 5:
                title = rec.get("title") or rec.get("id") or "unknown"
                sample_titles.append(title)

    if total_records == 0:
        fail_reasons = ["No vulnerability records were returned by the Production Feed; unable to determine open critical-severity alert count."]
        pass_reasons = []
        recommendations = ["Verify the Wordfence Intelligence API token has access to the Production Feed and that the feed is returning data."]
    else:
        pass_reasons = [
            f"Scanned {total_records} vulnerability records from the Wordfence Intelligence Production Feed; "
            f"found {critical_count} with cvss.rating == 'Critical' (examples: {', '.join([str(t) for t in sample_titles])})."
        ]
        fail_reasons = []
        recommendations = []
        if critical_count > 0:
            recommendations = [
                "Review and prioritize remediation for the identified Critical-severity vulnerabilities affecting monitored WordPress assets."
            ]

    result = {
        "openCriticalSeverityAlertsCount": critical_count,
        "totalVulnerabilityRecords": total_records,
    }

    input_summary = {
        "totalVulnerabilityRecords": total_records,
        "criticalCount": critical_count,
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
            "category": "threatintelligence",
        },
    )
