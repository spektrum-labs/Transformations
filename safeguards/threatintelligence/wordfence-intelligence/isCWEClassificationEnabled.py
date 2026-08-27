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

    # The Wordfence production feed response is a dict keyed by vulnerability
    # UUID -> vulnerability record. It may also arrive already unwrapped as
    # {"apiResponse": {...}} in legacy shapes, or as a plain list of records.
    records = []
    if isinstance(data, dict):
        container = data.get("apiResponse")
        if isinstance(container, dict):
            records = list(container.values())
        elif isinstance(container, list):
            records = container
        else:
            # data itself might already be the uuid->record mapping
            values = list(data.values())
            if values and all(isinstance(v, dict) for v in values):
                records = values
    elif isinstance(data, list):
        records = data

    total = len(records)
    with_cwe = 0
    without_cwe_examples = []
    sample_with_cwe = None

    for rec in records:
        if not isinstance(rec, dict):
            continue
        cwe = rec.get("cwe")
        informational = rec.get("informational")
        has_cwe = isinstance(cwe, dict) and bool(cwe.get("id"))
        if has_cwe:
            with_cwe = with_cwe + 1
            if sample_with_cwe is None:
                sample_with_cwe = (rec.get("id"), cwe.get("id"), cwe.get("name"))
        else:
            if informational is not True and len(without_cwe_examples) < 5:
                without_cwe_examples.append(rec.get("id") or rec.get("title") or "unknown")

    if total == 0:
        coverage_pct = 0.0
    else:
        coverage_pct = round((with_cwe / total) * 100.0, 2)

    is_enabled = total > 0 and coverage_pct >= 95.0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total == 0:
        fail_reasons.append("No vulnerability records were present in the getProductionVulnerabilityFeed response, so CWE classification coverage could not be confirmed.")
        recommendations.append("Verify the Wordfence Intelligence API token has access to the production vulnerability feed and that records are returned.")
    elif is_enabled:
        sample_txt = ""
        if sample_with_cwe:
            sample_txt = f" For example, record {sample_with_cwe[0]} is tagged with cwe.id={sample_with_cwe[1]} ({sample_with_cwe[2]})."
        pass_reasons.append(
            f"{with_cwe} of {total} vulnerability records ({coverage_pct}%) sampled from getProductionVulnerabilityFeed carry a populated cwe object with a non-empty id." + sample_txt
        )
    else:
        fail_reasons.append(
            f"Only {with_cwe} of {total} vulnerability records ({coverage_pct}%) sampled from getProductionVulnerabilityFeed carry a populated cwe object; the remainder lack CWE classification."
        )
        if without_cwe_examples:
            fail_reasons.append("Examples of records missing cwe: " + ", ".join([str(x) for x in without_cwe_examples]))
        recommendations.append("Confirm with Wordfence why some non-informational vulnerability records lack a CWE classification, or check if this is expected for informational-only entries.")

    result = {
        "isCWEClassificationEnabled": is_enabled,
        "totalRecords": total,
        "recordsWithCWE": with_cwe,
        "cweCoveragePercentage": coverage_pct,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalRecords": total, "recordsWithCWE": with_cwe, "cweCoveragePercentage": coverage_pct},
        metadata={
            "transformationId": "isCWEClassificationEnabled",
            "vendor": "Wordfence Intelligence",
            "category": "threatintelligence",
        },
    )
