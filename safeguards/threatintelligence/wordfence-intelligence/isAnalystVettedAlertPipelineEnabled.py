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
    if not isinstance(data, (dict, list)):
        data = {}
    if isinstance(data, list):
        data = {}

    ids = data.get("id") or []
    researchers_list = data.get("researchers") or []
    informational_list = data.get("informational") or []

    has_researchers_field = "researchers" in data
    total = len(ids)
    if total == 0:
        total = len(researchers_list)

    vetted_count = 0
    for r in researchers_list:
        if r:
            vetted_count = vetted_count + 1

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total > 0:
        coverage = float(vetted_count) / float(total)
        is_enabled = coverage >= 0.9
        if is_enabled:
            pass_reasons.append(
                f"Production Feed returned {total} vulnerability records; {vetted_count} of them "
                f"({coverage * 100:.1f}%) carry a populated 'researchers' attribution array, "
                f"confirming these entries were reviewed by Wordfence analysts before publication."
            )
        else:
            fail_reasons.append(
                f"Only {vetted_count} of {total} Production Feed records "
                f"({coverage * 100:.1f}%) carry a populated 'researchers' attribution array, "
                f"which falls below the expected analyst-vetting threshold of 90%."
            )
            recommendations.append(
                "Investigate why some Production Feed vulnerability records lack researcher "
                "attribution and confirm with Wordfence that all Production Feed entries are "
                "fully analyst-reviewed prior to publication."
            )
    else:
        is_enabled = has_researchers_field
        if is_enabled:
            pass_reasons.append(
                "Production Feed returned zero current vulnerability records, but the response "
                "schema includes the 'researchers' attribution field used by Wordfence to mark "
                "entries as analyst-reviewed, confirming the analyst-vetted pipeline structure is enabled."
            )
        else:
            fail_reasons.append(
                "Production Feed response did not include a 'researchers' field, so the "
                "analyst-vetting attribution mechanism could not be confirmed."
            )
            recommendations.append(
                "Verify API token permissions and confirm the Production Feed endpoint returns "
                "the documented schema including the 'researchers' field."
            )

    result = {
        "isAnalystVettedAlertPipelineEnabled": bool(is_enabled),
        "totalRecords": total,
        "vettedRecords": vetted_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalRecords": total,
            "vettedRecords": vetted_count,
            "informationalCount": len(informational_list),
        },
        metadata={
            "transformationId": "isAnalystVettedAlertPipelineEnabled",
            "vendor": "Wordfence Intelligence",
            "category": "threatintelligence",
        },
    )
