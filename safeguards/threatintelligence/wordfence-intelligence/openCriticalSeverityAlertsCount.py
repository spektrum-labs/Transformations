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


KNOWN_COLUMNS = ["id", "title", "software", "description", "references", "cwe", "cvss", "informational"]


def get_cvss_score(rec):
    cvss = rec.get("cvss") if isinstance(rec, dict) else None
    score = None
    if isinstance(cvss, dict):
        score = cvss.get("score")
    elif isinstance(cvss, (int, float, str)):
        score = cvss
    try:
        if score is None:
            return None
        return float(score)
    except (TypeError, ValueError):
        return None


def extract_records(data):
    records = []
    if isinstance(data, list):
        records = data
    elif isinstance(data, dict):
        present_cols = [k for k in KNOWN_COLUMNS if k in data]
        is_columnar = len(present_cols) > 0 and all(isinstance(data.get(k), list) for k in present_cols)
        if is_columnar:
            length = 0
            for k in present_cols:
                v = data.get(k)
                if isinstance(v, list) and len(v) > length:
                    length = len(v)
            i = 0
            while i < length:
                rec = {}
                for k in KNOWN_COLUMNS:
                    v = data.get(k)
                    if isinstance(v, list) and i < len(v):
                        rec[k] = v[i]
                    else:
                        rec[k] = None
                records.append(rec)
                i = i + 1
        else:
            possible_list = data.get("data")
            if isinstance(possible_list, list):
                records = possible_list
            else:
                values = list(data.values())
                if len(values) > 0 and all(isinstance(v, dict) for v in values):
                    records = values
                else:
                    records = []
    return records


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    records = extract_records(data)
    total_records = len(records)

    critical_count = 0
    sample_titles = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        if rec.get("informational"):
            continue
        score = get_cvss_score(rec)
        if score is not None and score >= 9.0:
            critical_count = critical_count + 1
            if len(sample_titles) < 5:
                sample_titles.append(rec.get("title") or rec.get("id") or "unknown")

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_records == 0:
        pass_reasons.append(
            "Wordfence Intelligence production vulnerability feed returned 0 records; "
            "no Critical-severity (CVSS >= 9.0) vulnerabilities are currently tracked, "
            "so openCriticalSeverityAlertsCount is 0."
        )
    elif critical_count == 0:
        pass_reasons.append(
            f"Inspected {total_records} vulnerability records from the Wordfence Intelligence "
            "production feed; none carried a cvss.score >= 9.0, so openCriticalSeverityAlertsCount is 0."
        )
    else:
        fail_reasons.append(
            f"Found {critical_count} Critical-severity (CVSS >= 9.0) vulnerability records out of "
            f"{total_records} inspected in the Wordfence Intelligence production feed. "
            f"Examples: {', '.join([str(t) for t in sample_titles])}."
        )
        recommendations.append(
            "Review and remediate the affected WordPress plugins/themes flagged with Critical "
            "severity vulnerabilities in the Wordfence Intelligence production feed as soon as possible."
        )

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
        input_summary={"totalRecords": total_records, "criticalCount": critical_count},
        metadata={
            "transformationId": "openCriticalSeverityAlertsCount",
            "vendor": "Wordfence Intelligence",
            "category": "threatintelligence",
        },
    )
