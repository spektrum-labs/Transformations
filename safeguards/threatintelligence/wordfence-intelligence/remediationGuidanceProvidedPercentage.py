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
            if isinstance(value, dict) and ("id" in value or "title" in value):
                records.append(value)
    elif isinstance(data, list):
        for value in data:
            if isinstance(value, dict):
                records.append(value)

    total_records = len(records)
    records_with_guidance = 0
    records_missing_guidance_titles = []

    for rec in records:
        software_list = rec.get("software") or []
        has_guidance = False
        if isinstance(software_list, list):
            for sw in software_list:
                if not isinstance(sw, dict):
                    continue
                remediation = sw.get("remediation")
                patched_versions = sw.get("patched_versions") or []
                if isinstance(remediation, str) and len(remediation.strip()) > 0:
                    has_guidance = True
                    break
                if isinstance(patched_versions, list) and len(patched_versions) > 0:
                    has_guidance = True
                    break
        if has_guidance:
            records_with_guidance = records_with_guidance + 1
        else:
            title = rec.get("title") or rec.get("id") or "unknown"
            if len(records_missing_guidance_titles) < 5:
                records_missing_guidance_titles.append(title)

    if total_records == 0:
        percentage = 0
    else:
        percentage = round((records_with_guidance / float(total_records)) * 100, 2)

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_records == 0:
        fail_reasons.append("No vulnerability records were present in the production feed response to evaluate remediation guidance coverage.")
        recommendations.append("Verify the Wordfence Intelligence production feed is returning records for this tenant.")
    elif percentage >= 100:
        pass_reasons.append(
            f"All {total_records} vulnerability records include explicit remediation guidance "
            f"(non-empty 'remediation' text or non-empty 'patched_versions' in the software array)."
        )
    elif percentage > 0:
        pass_reasons.append(
            f"{records_with_guidance} of {total_records} vulnerability records "
            f"({percentage} percent) include explicit remediation guidance via the software[].remediation "
            f"or software[].patched_versions fields."
        )
        fail_reasons.append(
            f"{total_records - records_with_guidance} of {total_records} records lack explicit remediation "
            f"guidance (no non-empty 'remediation' text and no 'patched_versions'). "
            f"Examples: {records_missing_guidance_titles}"
        )
        recommendations.append(
            "Investigate records missing remediation text (e.g. those without a populated 'software' array) "
            "and confirm whether upstream vendor data omits patch guidance for those vulnerabilities."
        )
    else:
        fail_reasons.append(
            f"0 of {total_records} vulnerability records include explicit remediation guidance in the "
            f"software[].remediation or software[].patched_versions fields."
        )
        recommendations.append(
            "Confirm the production feed integration is returning full, non-truncated software records with "
            "remediation guidance rather than partial records."
        )

    result = {
        "remediationGuidanceProvidedPercentage": percentage,
        "totalVulnerabilityRecords": total_records,
        "recordsWithRemediationGuidance": records_with_guidance,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalVulnerabilityRecords": total_records,
            "recordsWithRemediationGuidance": records_with_guidance,
        },
        metadata={
            "transformationId": "remediationGuidanceProvidedPercentage",
            "vendor": "Wordfence Intelligence",
            "category": "threatintelligence",
        },
    )
