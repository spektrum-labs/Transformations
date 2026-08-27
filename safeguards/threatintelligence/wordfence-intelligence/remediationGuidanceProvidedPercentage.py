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
            if isinstance(value, dict) and "id" in value:
                records.append(value)
    elif isinstance(data, list):
        for value in data:
            if isinstance(value, dict):
                records.append(value)

    total = len(records)
    with_guidance = 0
    sample_titles = []

    for rec in records:
        software_entries = rec.get("software") or []
        has_remediation = False
        if isinstance(software_entries, list):
            for sw in software_entries:
                if isinstance(sw, dict):
                    remediation = sw.get("remediation")
                    if isinstance(remediation, str) and remediation.strip() != "":
                        has_remediation = True
                        break
        if has_remediation:
            with_guidance = with_guidance + 1
            if len(sample_titles) < 3:
                title = rec.get("title") or rec.get("id") or "unknown"
                sample_titles.append(title)

    if total == 0:
        percentage = 0.0
    else:
        percentage = round((with_guidance / total) * 100.0, 2)

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total == 0:
        fail_reasons.append(
            "No vulnerability records were returned by getProductionVulnerabilityFeed; remediation guidance coverage could not be assessed."
        )
        recommendations.append(
            "Verify the Wordfence Intelligence API token has access to the Production Vulnerability Feed and that the feed returns records."
        )
    elif with_guidance == total:
        pass_reasons.append(
            f"All {total} vulnerability records include a non-empty software[].remediation string (e.g. {sample_titles})."
        )
    elif with_guidance > 0:
        pass_reasons.append(
            f"{with_guidance} of {total} vulnerability records ({percentage}%) include a non-empty software[].remediation field, e.g. {sample_titles}."
        )
        fail_reasons.append(
            f"{total - with_guidance} of {total} vulnerability records lack a non-empty software[].remediation field."
        )
        recommendations.append(
            "Review records missing remediation text and confirm whether they are informational-only or awaiting vendor patch guidance."
        )
    else:
        fail_reasons.append(
            f"None of the {total} vulnerability records examined include a non-empty software[].remediation field."
        )
        recommendations.append(
            "Investigate why remediation guidance is absent across the fetched feed records; contact Wordfence support if this persists."
        )

    result = {
        "remediationGuidanceProvidedPercentage": percentage,
        "totalRecords": total,
        "recordsWithGuidance": with_guidance,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalRecords": total, "recordsWithGuidance": with_guidance},
        metadata={
            "transformationId": "remediationGuidanceProvidedPercentage",
            "vendor": "Wordfence Intelligence",
            "category": "Threat Intelligence",
        },
    )
