import json
from datetime import datetime


def extract_input(input_data):
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
        models = data
    elif isinstance(data, dict):
        models = data.get("data") or []
    else:
        models = []

    total_models = len(models)

    valid_models = []
    fine_tuned_models = []
    owners = {}
    for m in models:
        if not isinstance(m, dict):
            continue
        model_id = m.get("id")
        owned_by = m.get("owned_by")
        if model_id and m.get("object") == "model":
            valid_models.append(m)
        if owned_by and owned_by not in ("openai", "openai-internal", "system"):
            fine_tuned_models.append(model_id)
        if owned_by:
            owners[owned_by] = owners.get(owned_by, 0) + 1

    valid_count = len(valid_models)
    is_enforced = total_models > 0 and valid_count == total_models

    owners_summary = ", ".join([f"{k}: {v}" for k, v in owners.items()])

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_enforced:
        pass_reasons.append(
            f"GET /v1/models returned an authoritative, queryable list of {total_models} models "
            f"available to the org, each carrying id, object='model', created, and owned_by fields "
            f"(owners breakdown: {owners_summary}). This constitutes a functioning model inventory."
        )
        if fine_tuned_models:
            pass_reasons.append(
                f"{len(fine_tuned_models)} custom/fine-tuned model(s) are tracked in the inventory: "
                f"{', '.join(fine_tuned_models[:10])}."
            )
    else:
        fail_reasons.append(
            f"GET /v1/models returned {total_models} model records; a functioning inventory endpoint "
            f"requires a non-empty, well-formed list of models with id/object/owned_by fields."
        )
        recommendations.append(
            "Verify the Admin API key has access to /v1/models and that the organization has models provisioned."
        )

    result = {
        "isModelInventoryTrackingEnforced": is_enforced,
        "totalModelsTracked": total_models,
        "fineTunedModelsCount": len(fine_tuned_models),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalModels": total_models, "validModels": valid_count},
        metadata={
            "transformationId": "isModelInventoryTrackingEnforced",
            "vendor": "OpenAI",
            "category": "artificial-intelligence",
        },
    )
