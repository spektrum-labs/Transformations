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
        if not isinstance(buckets, list):
            buckets = []
    else:
        buckets = []

    total_buckets = len(buckets)
    models_seen = {}
    buckets_with_results = 0
    malformed_buckets = 0

    for bucket in buckets:
        if not isinstance(bucket, dict):
            malformed_buckets = malformed_buckets + 1
            continue
        results = bucket.get("results")
        if not isinstance(results, list):
            results = []
        if len(results) > 0:
            buckets_with_results = buckets_with_results + 1
        for row in results:
            if not isinstance(row, dict):
                continue
            model_id = row.get("model")
            if model_id:
                models_seen[model_id] = (models_seen.get(model_id) or 0) + 1

    has_model_grouping_shape = total_buckets > 0
    distinct_model_count = len(models_seen)

    is_enforced = has_model_grouping_shape

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_enforced:
        if distinct_model_count > 0:
            model_list = ", ".join(sorted(models_seen.keys()))
            pass_reasons.append(
                f"Usage & Cost Admin API (getUsageReportByModel, group_by[]=model) returned "
                f"{total_buckets} time buckets and identified {distinct_model_count} distinct "
                f"model id(s) actually consumed across the org: {model_list}."
            )
        else:
            pass_reasons.append(
                f"Usage & Cost Admin API responded successfully with {total_buckets} time buckets "
                f"grouped by model (group_by[]=model), confirming the org can enumerate model "
                f"consumption via this endpoint even though no usage rows were populated in the "
                f"queried window (all {total_buckets} buckets had empty results)."
            )
    else:
        fail_reasons.append(
            "Usage & Cost Admin API (usage_report/messages grouped by model) returned no time "
            "buckets, so no model inventory could be enumerated from this response."
        )
        recommendations.append(
            "Verify the Admin API key has access to the Usage & Cost Admin API and that the "
            "organization has message usage data to enumerate model consumption from."
        )

    input_summary = {
        "totalBuckets": total_buckets,
        "bucketsWithResults": buckets_with_results,
        "distinctModelsSeen": distinct_model_count,
        "malformedBuckets": malformed_buckets,
    }

    result = {
        "isModelInventoryTrackingEnforced": is_enforced,
        "distinctModelCount": distinct_model_count,
        "totalBucketsEvaluated": total_buckets,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isModelInventoryTrackingEnforced",
            "vendor": "Anthropic Claude Developer Platform Claude API",
            "category": "Artificial Intelligence",
        },
    )
