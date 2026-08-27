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


def software_has_remediation(sw_entry):
    """Return True if a software entry carries non-empty remediation guidance text."""
    if not isinstance(sw_entry, dict):
        return False
    for key in ("remediation", "patched_versions", "patched_version", "fixed_in", "recommendation"):
        val = sw_entry.get(key)
        if isinstance(val, str) and val.strip():
            return True
        if isinstance(val, list) and len(val) > 0:
            return True
    return False


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    transformation_errors = []
    records = []

    if isinstance(data, list):
        # array-root: one dict per vulnerability record
        records = data
    elif isinstance(data, dict):
        # columnar / parallel-array shape observed in captured response:
        # {"id": [...], "software": [...], ...} where each top-level key
        # holds a list aligned by index across all vulnerability records.
        ids = data.get("id")
        software_col = data.get("software")
        if isinstance(ids, list) and isinstance(software_col, list):
            total_n = len(ids)
            for i in range(total_n):
                sw = software_col[i] if i < len(software_col) else None
                records.append({"software": sw})
        else:
            # fallback: maybe data has a "data" or "results" list of records
            fallback = data.get("data") or data.get("results") or []
            if isinstance(fallback, list):
                records = fallback

    total = len(records)
    with_guidance = 0

    for rec in records:
        if not isinstance(rec, dict):
            continue
        sw = rec.get("software")
        has_guidance = False
        if isinstance(sw, list):
            for entry in sw:
                if software_has_remediation(entry):
                    has_guidance = True
                    break
        elif isinstance(sw, dict):
            has_guidance = software_has_remediation(sw)
        if has_guidance:
            with_guidance = with_guidance + 1

    if total == 0:
        percentage = 0
        pass_reasons = []
        fail_reasons = ["The production feed returned zero vulnerability records to evaluate; remediation guidance coverage cannot be confirmed."]
        recommendations = ["Verify the API key has access to the production feed and that the feed is not empty for this tenant."]
    else:
        percentage = round((with_guidance / total) * 100, 2)
        if with_guidance == total:
            pass_reasons = [f"All {total} vulnerability records include a non-empty remediation field in their software entries."]
            fail_reasons = []
            recommendations = []
        elif with_guidance > 0:
            pass_reasons = [f"{with_guidance} of {total} vulnerability records ({percentage}%) include non-empty remediation guidance in their software entries."]
            fail_reasons = [f"{total - with_guidance} of {total} vulnerability records lack remediation guidance text in their software entries."]
            recommendations = ["Investigate vulnerability records missing remediation/patched_version fields and request Wordfence to backfill guidance where feasible."]
        else:
            pass_reasons = []
            fail_reasons = [f"None of the {total} vulnerability records examined include a non-empty remediation field in their software entries."]
            recommendations = ["Escalate to Wordfence Intelligence support: production feed records are missing remediation guidance text entirely."]

    input_summary = {"totalRecords": total, "recordsWithGuidance": with_guidance}

    return create_response(
        result={
            "remediationGuidanceProvidedPercentage": percentage,
            "totalVulnerabilityRecords": total,
            "recordsWithGuidance": with_guidance,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "remediationGuidanceProvidedPercentage",
            "vendor": "Wordfence Intelligence",
            "category": "threatintelligence",
        },
        transformation_errors=transformation_errors,
    )
