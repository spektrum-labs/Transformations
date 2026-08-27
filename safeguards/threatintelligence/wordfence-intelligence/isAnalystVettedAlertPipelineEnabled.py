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

    # Normalize into a list of vulnerability records regardless of root shape.
    records = []
    if isinstance(data, dict):
        # Root could be the vulnerabilities keyed-by-uuid dict (post-unwrap of apiResponse),
        # or still wrapped under a nested key if extract_input did not unwrap it.
        candidate = data.get("apiResponse") if isinstance(data.get("apiResponse"), dict) else None
        source_dict = candidate if candidate is not None else data
        for key, value in source_dict.items():
            if key == "_truncated":
                continue
            if isinstance(value, dict):
                records.append(value)
    elif isinstance(data, list):
        for value in data:
            if isinstance(value, dict):
                records.append(value)

    total = len(records)

    analyzed_count = 0
    informational_field_count = 0
    remediation_count = 0

    for r in records:
        has_cwe = r.get("cwe") is not None
        cvss_val = r.get("cvss")
        has_cvss = isinstance(cvss_val, dict) and len(cvss_val) > 0
        has_description = bool(r.get("description"))
        software_list = r.get("software") or []
        has_remediation = False
        if isinstance(software_list, list):
            for sw in software_list:
                if isinstance(sw, dict) and sw.get("remediation"):
                    has_remediation = True
                    break
        if has_remediation:
            remediation_count = remediation_count + 1
        if r.get("informational") is not None:
            informational_field_count = informational_field_count + 1
        if has_cwe or has_cvss or has_description or has_remediation:
            analyzed_count = analyzed_count + 1

    is_enabled = total > 0 and analyzed_count > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_enabled:
        pass_reasons.append(
            f"Production Feed returned {total} vulnerability records; {analyzed_count} of them carry fully-analyzed fields (cwe, cvss, description, or software[].remediation), and {remediation_count} include explicit remediation guidance, evidencing human-analyst vetting distinct from raw detections."
        )
        if informational_field_count > 0:
            pass_reasons.append(
                f"{informational_field_count} records carry an explicit 'informational' classification flag, indicating analysts triage and label records rather than surfacing raw unvetted detections."
            )
    else:
        fail_reasons.append(
            f"Production Feed returned {total} records, but none exposed the fully-analyzed fields (cwe, cvss, description, software[].remediation) expected of an analyst-vetted record."
        )
        recommendations.append(
            "Verify the Wordfence Intelligence API token has access to the Production Vulnerability Feed (not only the Scanner Feed) so fully-analyzed records with cwe/cvss/remediation fields are returned."
        )

    result = {
        "isAnalystVettedAlertPipelineEnabled": is_enabled,
        "totalRecordsSampled": total,
        "fullyAnalyzedRecordCount": analyzed_count,
        "remediationProvidedCount": remediation_count,
    }

    input_summary = {
        "totalRecordsSampled": total,
        "fullyAnalyzedRecordCount": analyzed_count,
        "remediationProvidedCount": remediation_count,
        "informationalFlagCount": informational_field_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isAnalystVettedAlertPipelineEnabled",
            "vendor": "Wordfence Intelligence",
            "category": "Threat Intelligence",
        },
    )
