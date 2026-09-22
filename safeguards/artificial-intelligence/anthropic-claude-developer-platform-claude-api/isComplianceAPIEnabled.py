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
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
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
    data = data if isinstance(data, dict) else {}

    has_data_key = "data" in data
    items = data.get("data") if isinstance(data.get("data"), list) else []
    has_more = data.get("has_more")
    first_id = data.get("first_id")
    last_id = data.get("last_id")

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    # A successful 200 response from the Compliance Activities endpoint
    # containing the paginated envelope keys (data/has_more) is direct
    # evidence the Compliance API is enabled for this org. A 403/404
    # (which surfaces upstream as an empty/error response with no
    # envelope keys) indicates it is not enabled.
    envelope_present = has_data_key and ("has_more" in data or "first_id" in data or "last_id" in data)

    is_enabled = bool(envelope_present)

    accessed_events = [
        i for i in items
        if isinstance(i, dict) and i.get("type") == "compliance_api_accessed"
    ]

    if is_enabled:
        sample_count = len(items)
        pass_reasons.append(
            f"GET /v1/compliance/activities returned HTTP 200 with a valid paginated envelope "
            f"(data list of {sample_count} sampled activity records, has_more={has_more}), "
            f"confirming the Compliance API is enabled and accessible for this organization."
        )
        if accessed_events:
            pass_reasons.append(
                f"Found {len(accessed_events)} 'compliance_api_accessed' activity record(s) in the "
                f"sample, direct evidence of live programmatic access to the activity feed."
            )
    else:
        fail_reasons.append(
            "GET /v1/compliance/activities did not return a valid data/has_more envelope, "
            "consistent with the Compliance API not being enabled for the parent organization "
            "(the endpoint 404s/403s when the settings/activities endpoints are not yet enabled)."
        )
        recommendations.append(
            "Enable the Compliance API for the organization in the Anthropic Console and provision "
            "a Compliance Access Key (or Admin API Key) with read:compliance_activities scope."
        )

    result = {
        "isComplianceAPIEnabled": is_enabled,
        "sampledActivityCount": len(items),
        "hasMore": bool(has_more) if has_more is not None else False,
    }

    input_summary = {
        "hasDataKey": has_data_key,
        "itemCount": len(items),
        "firstId": first_id,
        "lastId": last_id,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isComplianceAPIEnabled",
            "vendor": "Anthropic Claude Developer Platform Claude API",
            "category": "artificial-intelligence",
        },
    )
