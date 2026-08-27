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

    transformation_errors = []
    records = []

    if isinstance(data, list):
        records = [r for r in data if isinstance(r, dict)]
    elif isinstance(data, dict):
        keys = list(data.keys())
        looks_columnar = False
        if keys:
            vals = list(data.values())
            if all(isinstance(v, list) for v in vals) and ("id" in data or "cvss" in data):
                looks_columnar = True
        if looks_columnar:
            ids = data.get("id") or []
            cvss_list = data.get("cvss") or []
            software_list = data.get("software") or []
            n = len(ids)
            i = 0
            while i < n:
                rec = {
                    "id": ids[i] if i < len(ids) else None,
                    "cvss": cvss_list[i] if i < len(cvss_list) else {},
                    "software": software_list[i] if i < len(software_list) else [],
                }
                records.append(rec)
                i = i + 1
        else:
            for v in data.values():
                if isinstance(v, dict):
                    records.append(v)

    total_records = len(records)
    total_critical = 0
    open_critical = 0
    sample_open_ids = []

    for rec in records:
        cvss = rec.get("cvss") if isinstance(rec.get("cvss"), dict) else {}
        rating = cvss.get("rating") or ""
        score = cvss.get("score")
        is_critical = False
        if isinstance(rating, str) and rating.strip().lower() == "critical":
            is_critical = True
        if not is_critical:
            try:
                if score is not None and float(score) >= 9.0:
                    is_critical = True
            except (TypeError, ValueError):
                pass

        if not is_critical:
            continue

        total_critical = total_critical + 1

        software = rec.get("software") if isinstance(rec.get("software"), list) else []
        unpatched = False
        for s in software:
            if isinstance(s, dict) and s.get("patched") is False:
                unpatched = True
                break

        if unpatched:
            open_critical = open_critical + 1
            if len(sample_open_ids) < 5:
                sample_open_ids.append(rec.get("id"))

    if total_records == 0:
        pass_reasons = []
        fail_reasons = ["Wordfence Production Vulnerability Feed returned no records to evaluate; openCriticalSeverityAlertsCount computed as 0 with no data present."]
        recommendations = ["Verify the API token has access to the Production Vulnerability Feed and that the feed is not empty."]
    elif open_critical > 0:
        pass_reasons = [
            f"Found {open_critical} open (unpatched) Critical-severity (cvss.rating='Critical' or score>=9.0) vulnerability records out of {total_critical} total Critical-rated records and {total_records} total feed records. Sample affected record ids: {sample_open_ids}."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = [
            f"No open (unpatched) Critical-severity vulnerabilities found among {total_critical} Critical-rated records out of {total_records} total feed records."
        ]
        fail_reasons = []
        recommendations = []

    result = {
        "openCriticalSeverityAlertsCount": open_critical,
        "totalCriticalRecords": total_critical,
        "totalFeedRecords": total_records,
    }

    input_summary = {
        "totalFeedRecords": total_records,
        "totalCriticalRecords": total_critical,
        "openCriticalSeverityAlertsCount": open_critical,
    }

    metadata = {
        "transformationId": "openCriticalSeverityAlertsCount",
        "vendor": "Wordfence Intelligence",
        "category": "threatintelligence",
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata=metadata,
        transformation_errors=transformation_errors,
    )
