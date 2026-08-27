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

    # Normalize records into a list regardless of dict-of-records or list-of-records shape
    records = []
    if isinstance(data, dict):
        for key in data.keys():
            if key == "_truncated":
                continue
            value = data.get(key)
            if isinstance(value, dict):
                records.append(value)
    elif isinstance(data, list):
        records = [r for r in data if isinstance(r, dict)]

    total_records = len(records)
    non_cve_records = 0
    cve_records = 0
    sample_non_cve_titles = []

    for record in records:
        references = record.get("references")
        if not isinstance(references, list):
            references = []
        has_cve_reference = False
        for ref in references:
            ref_str = ref if isinstance(ref, str) else ""
            if "CVE-" in ref_str or "cve.mitre.org" in ref_str or "nvd.nist.gov" in ref_str:
                has_cve_reference = True
                break
        if has_cve_reference:
            cve_records = cve_records + 1
        else:
            non_cve_records = non_cve_records + 1
            if len(sample_non_cve_titles) < 5:
                title = record.get("title")
                if isinstance(title, str):
                    sample_non_cve_titles.append(title)

    is_enabled = total_records > 0 and non_cve_records > 0

    input_summary = {
        "totalRecords": total_records,
        "recordsWithCveReference": cve_records,
        "recordsWithoutCveReference": non_cve_records,
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_enabled:
        pass_reasons.append(
            "Of %d vulnerability records inspected in the Production Feed, %d carry no CVE/NVD reference URL in their references[] array (e.g. %s), each still tracked with a vendor-assigned UUID id -- confirming independent (non-NVD) coverage is present."
            % (total_records, non_cve_records, ", ".join(sample_non_cve_titles) if sample_non_cve_titles else "n/a")
        )
    else:
        if total_records == 0:
            fail_reasons.append("No vulnerability records were returned by the Production Feed, so independent (non-NVD) coverage could not be confirmed.")
            recommendations.append("Verify the API token has access to the Wordfence Intelligence Production Vulnerability Feed and retry.")
        else:
            fail_reasons.append(
                "All %d inspected vulnerability records include a CVE/NVD reference in references[]; no independently-tracked, non-CVE-assigned vulnerabilities were found in this sample."
                % total_records
            )
            recommendations.append("Confirm with the vendor whether the Production Feed includes pre-CVE-assignment vulnerabilities, or check the Scanner Feed for early-warning coverage.")

    result = {
        "isNVDIndependentCoverageEnabled": is_enabled,
        "totalRecords": total_records,
        "recordsWithoutCveReference": non_cve_records,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isNVDIndependentCoverageEnabled",
            "vendor": "Wordfence Intelligence",
            "category": "threatintelligence",
        },
    )
