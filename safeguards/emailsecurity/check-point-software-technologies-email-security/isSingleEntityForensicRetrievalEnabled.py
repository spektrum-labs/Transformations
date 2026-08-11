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

    is_error = bool(data.get("error")) or data.get("status") == "Error"
    status_code = data.get("statusCode")

    entity = data.get("responseData") or {}
    if not isinstance(entity, dict):
        entity = {}

    entity_id = entity.get("entityId")
    message_id = entity.get("messageId")

    forensic_fields = ["messageId", "size", "links", "attachments", "recipients",
                        "sender", "senderDomain", "senderDisplayName", "spfResult"]
    present_fields = [f for f in forensic_fields if entity.get(f) is not None]

    is_enabled = False

    if is_error:
        api_errors.append(
            f"searchEntityById returned an error: statusCode={status_code}, "
            f"message={data.get('message') or data.get('errorMessage')}"
        )
        fail_reasons.append(
            f"Could not confirm single-entity forensic retrieval because the "
            f"searchEntityById call returned an authentication/API error "
            f"(statusCode={status_code}). No entity record with entityId/messageId "
            f"and forensic detail fields was returned."
        )
        recommendations.append(
            "Verify the API client credentials (clientId/clientSecret) have valid "
            "permissions to call /search/entity/{entityId} and retry with a valid "
            "entity ID to confirm forensic retrieval works."
        )
    elif entity_id or message_id:
        is_enabled = True
        pass_reasons.append(
            f"searchEntityById returned a full entity record for entityId={entity_id or 'n/a'} "
            f"with forensic fields present: {present_fields}. This confirms a single dedicated "
            f"API call (/search/entity/{{entityId}}) can retrieve the full forensic detail "
            f"record for one specific entity/message by ID."
        )
    else:
        fail_reasons.append(
            "searchEntityById responded without error, but responseData did not "
            "contain an entityId or messageId, so a full forensic record could not "
            "be confirmed for a single entity."
        )
        recommendations.append(
            "Query searchEntityById with a known, valid entityId and confirm the "
            "response includes messageId, sender, recipients, attachments, and links."
        )

    result = {
        "isSingleEntityForensicRetrievalEnabled": is_enabled,
        "entityId": entity_id,
        "forensicFieldsPresent": present_fields,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"entityId": entity_id, "isError": is_error, "statusCode": status_code},
        api_errors=api_errors,
        metadata={
            "transformationId": "isSingleEntityForensicRetrievalEnabled",
            "vendor": "Check Point Software Technologies Email Security",
            "category": "emailsecurity",
        },
    )
