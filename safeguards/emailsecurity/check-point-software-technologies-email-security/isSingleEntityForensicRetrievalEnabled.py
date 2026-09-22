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

    api_errors = []
    fail_reasons = []
    pass_reasons = []
    recommendations = []

    # Detect an explicit vendor error envelope (auth failure, etc.)
    is_error = bool(data.get("error")) or data.get("status") == "Error" or data.get("statusCode") == 401

    if is_error:
        error_message = data.get("errorMessage") or data.get("message") or "Unknown error"
        api_errors.append(f"Vendor API returned an error: {error_message}")
        fail_reasons.append(
            f"getEntityById call did not return usable entity data (vendor error: '{error_message}'); "
            "cannot confirm single-entity forensic retrieval capability from this response."
        )
        recommendations.append(
            "Verify API credentials (clientId/accessKey) and confirm the entity/search endpoint "
            "is reachable, then re-run the scan to validate single-entity forensic retrieval."
        )
        result = {
            "isSingleEntityForensicRetrievalEnabled": False,
            "entityId": None,
            "hasEntityPayload": False,
        }
        return create_response(
            result=result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"error": True, "errorMessage": error_message},
            api_errors=api_errors,
            metadata={
                "transformationId": "isSingleEntityForensicRetrievalEnabled",
                "vendor": "Check Point Software Technologies Email Security",
                "category": "emailsecurity",
            },
        )

    # Response envelope may wrap the entity under responseData, or the entity fields
    # may be present directly at the top level.
    response_data = data.get("responseData")
    if isinstance(response_data, list):
        entity = response_data[0] if response_data else {}
    elif isinstance(response_data, dict):
        entity = response_data
    else:
        entity = data

    entity = entity if isinstance(entity, dict) else {}

    entity_id = entity.get("entityId")
    entity_payload = entity.get("entityPayload")
    saas = entity.get("saas")
    has_payload = bool(entity_payload)

    enabled = bool(entity_id) and has_payload

    if enabled:
        pass_reasons.append(
            f"GET /search/entity/{{entityId}} returned a single-entity forensic record for "
            f"entityId='{entity_id}' (saas='{saas}') including a populated entityPayload "
            "with full forensic detail, confirming dedicated single-entity retrieval by ID works."
        )
    else:
        if not entity_id:
            fail_reasons.append(
                "Response from getEntityById did not include an entityId field, so a "
                "dedicated single-entity forensic retrieval by ID could not be confirmed."
            )
        elif not has_payload:
            fail_reasons.append(
                f"Entity '{entity_id}' was retrieved but entityPayload was empty, so full "
                "forensic detail for the entity is not confirmed as retrievable via this call."
            )
        recommendations.append(
            "Confirm the search/entity/{entityId} endpoint returns a populated entityPayload "
            "for a known entityId to validate single-entity forensic retrieval."
        )

    result = {
        "isSingleEntityForensicRetrievalEnabled": enabled,
        "entityId": entity_id,
        "hasEntityPayload": has_payload,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"entityId": entity_id, "saas": saas, "hasEntityPayload": has_payload},
        metadata={
            "transformationId": "isSingleEntityForensicRetrievalEnabled",
            "vendor": "Check Point Software Technologies Email Security",
            "category": "emailsecurity",
        },
    )
