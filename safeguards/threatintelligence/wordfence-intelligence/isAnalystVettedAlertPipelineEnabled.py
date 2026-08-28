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
    if isinstance(data, dict):
        for key, value in data.items():
            if key in ("_omitted_keys", "_truncated"):
                continue
            if isinstance(value, dict) and "id" in value:
                records.append(value)
    elif isinstance(data, list):
        for value in data:
            if isinstance(value, dict):
                records.append(value)

    total_records = len(records)

    vetted_records = []
    for rec in records:
        researchers = rec.get("researchers")
        if isinstance(researchers, list) and len(researchers) > 0:
            vetted_records.append(rec)

    vetted_count = len(vetted_records)

    if total_records == 0:
        is_enabled = False
        vetted_percentage = 0.0
        fail_reasons = [
            "No vulnerability records were returned by the Production Feed, so analyst-vetting "
            "(researchers array presence) could not be confirmed."
        ]
        pass_reasons = []
        recommendations = [
            "Verify the Wordfence Intelligence apiToken has access to the Production Feed "
            "(GET /api/intelligence/v3/vulnerabilities/production) and that it returns records."
        ]
    else:
        vetted_percentage = (float(vetted_count) / float(total_records)) * 100.0
        is_enabled = vetted_count > 0
        if is_enabled:
            sample_titles = [r.get("title") for r in vetted_records[:3] if r.get("title")]
            pass_reasons = [
                (
                    f"{vetted_count} of {total_records} Production Feed records inspected carry a "
                    f"non-empty 'researchers' array, confirming human analyst review "
                    f"(e.g. {sample_titles})." if sample_titles else
                    f"{vetted_count} of {total_records} Production Feed records carry a non-empty "
                    f"'researchers' array, confirming human analyst review."
                )
            ]
            fail_reasons = []
            recommendations = []
        else:
            pass_reasons = []
            fail_reasons = [
                (
                    f"None of the {total_records} Production Feed records inspected carry a "
                    f"populated 'researchers' array, so analyst vetting could not be confirmed."
                )
            ]
            recommendations = [
                "Confirm the Production Feed (not the unvetted Scanner Feed) is being queried, "
                "since only Production Feed records carry the 'researchers' vetting field."
            ]

    result = {
        "isAnalystVettedAlertPipelineEnabled": is_enabled,
        "totalRecords": total_records,
        "vettedRecords": vetted_count,
        "vettedPercentage": round(vetted_percentage, 2),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalRecords": total_records, "vettedRecords": vetted_count},
        metadata={
            "transformationId": "isAnalystVettedAlertPipelineEnabled",
            "vendor": "Wordfence Intelligence",
            "category": "Threat Intelligence",
        },
        transformation_errors=transformation_errors,
    )
