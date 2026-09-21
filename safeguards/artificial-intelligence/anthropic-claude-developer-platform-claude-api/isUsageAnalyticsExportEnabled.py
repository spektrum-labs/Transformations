"""Transformation: isUsageAnalyticsExportEnabled"""
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

    if isinstance(data, list):
        buckets = data
    elif isinstance(data, dict):
        buckets = data.get("data") or []
    else:
        buckets = []

    bucket_count = len(buckets) if isinstance(buckets, list) else 0

    valid_bucket_count = 0
    if isinstance(buckets, list):
        for b in buckets:
            if isinstance(b, dict) and "starting_at" in b and "ending_at" in b and "results" in b:
                valid_bucket_count = valid_bucket_count + 1

    has_valid_structure = valid_bucket_count > 0

    api_errors = []

    is_enabled = bool(has_valid_structure)

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_enabled:
        pass_reasons.append(
            f"GET /v1/organizations/usage_report/messages with group_by[]=model returned HTTP 200 with "
            f"{bucket_count} time-bucketed rows (each carrying starting_at, ending_at, results), confirming the "
            f"org's Usage & Cost Admin API export surface for granular per-model usage is reachable and enabled."
        )
    else:
        fail_reasons.append(
            f"The usage_report/messages endpoint response did not contain any time-bucketed rows with the "
            f"expected starting_at/ending_at/results fields (bucket_count={bucket_count}); could not confirm the "
            f"Usage & Cost Admin API export is enabled."
        )
        recommendations.append(
            "Verify the Admin API key has the required scope and that the organization has the Usage & Cost "
            "Admin API enabled; retry the usage_report/messages call."
        )

    result = {
        "isUsageAnalyticsExportEnabled": is_enabled,
        "bucketCount": bucket_count,
        "validBucketCount": valid_bucket_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"bucketCount": bucket_count, "validBucketCount": valid_bucket_count},
        metadata={
            "transformationId": "isUsageAnalyticsExportEnabled",
            "vendor": "Anthropic Claude Developer Platform Claude API",
            "category": "artificial-intelligence",
        },
        api_errors=api_errors,
    )
