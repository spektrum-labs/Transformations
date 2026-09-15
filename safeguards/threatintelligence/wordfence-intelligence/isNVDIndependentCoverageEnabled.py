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
            if isinstance(value, dict):
                records.append(value)
    elif isinstance(data, list):
        for value in data:
            if isinstance(value, dict):
                records.append(value)

    total_records = len(records)

    non_cve_records = []
    cve_records = []
    for rec in records:
        cve_val = rec.get("cve")
        cve_link_val = rec.get("cve_link")
        has_cve = bool(cve_val) or bool(cve_link_val)
        rec_id = rec.get("id") or "unknown"
        if has_cve:
            cve_records.append(rec_id)
        else:
            non_cve_records.append(rec_id)

    non_cve_count = len(non_cve_records)
    cve_count = len(cve_records)

    is_enabled = total_records > 0 and non_cve_count > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_records == 0:
        fail_reasons.append(
            "The Production Feed response contained no vulnerability records to evaluate, "
            "so independent (non-NVD/CVE) coverage could not be confirmed."
        )
        recommendations.append(
            "Verify the getVulnerabilityProductionFeed API call is authenticating correctly "
            "and returning the tenant's vulnerability records."
        )
    elif is_enabled:
        sample_ids = ", ".join(non_cve_records[:3])
        pass_reasons.append(
            f"Of {total_records} vulnerability records sampled from the Production Feed, "
            f"{non_cve_count} carry a Wordfence-assigned id with no populated 'cve'/'cve_link' field "
            f"(e.g. record ids: {sample_ids}), confirming coverage of vulnerabilities independent of "
            f"official CVE/NVD assignment. {cve_count} records also carry CVE identifiers."
        )
    else:
        fail_reasons.append(
            f"All {total_records} sampled Production Feed records carry a populated 'cve' or 'cve_link' "
            f"field; no Wordfence-only (non-CVE) records were found in this sample."
        )
        recommendations.append(
            "Confirm with Wordfence that the Production Feed includes records without NVD/CVE assignment "
            "for this tenant's plan tier."
        )

    result = {
        "isNVDIndependentCoverageEnabled": is_enabled,
        "totalRecords": total_records,
        "recordsWithoutCve": non_cve_count,
        "recordsWithCve": cve_count,
    }

    input_summary = {
        "totalRecords": total_records,
        "recordsWithoutCve": non_cve_count,
        "recordsWithCve": cve_count,
    }

    metadata = {
        "transformationId": "isNVDIndependentCoverageEnabled",
        "vendor": "Wordfence Intelligence",
        "category": "Threat Intelligence",
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata=metadata,
    )
