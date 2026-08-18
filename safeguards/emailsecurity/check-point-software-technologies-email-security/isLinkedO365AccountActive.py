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

    metadata = {
        "transformationId": "isLinkedO365AccountActive",
        "vendor": "Check Point Software Technologies Email Security",
        "category": "emailsecurity",
    }

    api_errors = []
    if data.get("error") is True or data.get("statusCode") == 401 or data.get("errorType") == "authentication":
        api_errors.append(
            "API returned authentication/error response: %s" % data.get("message", data.get("errorMessage", "unknown error"))
        )
        return create_response(
            result={"isLinkedO365AccountActive": False},
            validation=validation,
            fail_reasons=[
                "Could not retrieve secured entity data because the API call failed (%s)." % data.get("message", "unknown error")
            ],
            recommendations=[
                "Verify the clientId/accessKey credentials and re-run the O365 entity search once authentication succeeds."
            ],
            input_summary={"apiError": True},
            metadata=metadata,
            api_errors=api_errors,
        )

    # This endpoint may return either a single entity object (responseData as dict)
    # or a list-shaped responseData depending on the call context. Normalize both.
    items = data.get("responseData")
    if isinstance(items, dict):
        items = [items]
    elif not isinstance(items, list):
        items = []

    # Also support the case where the entity fields are at the top level
    # (single-entity GET by ID returns entity fields directly under responseData
    # or, in some captures, merged into the top-level body).
    if not items and data.get("entityId") is not None:
        items = [data]

    envelope = data.get("responseEnvelope") or {}
    total_records = envelope.get("totalRecordsNumber") if isinstance(envelope, dict) else None

    o365_entities = [
        item for item in items
        if isinstance(item, dict) and item.get("saas") == "office365_emails"
    ]

    has_active_link = len(o365_entities) > 0

    input_summary = {
        "totalItems": len(items),
        "o365EntityCount": len(o365_entities),
        "totalRecordsNumber": total_records,
    }

    if has_active_link:
        sample = o365_entities[0]
        pass_reasons = [
            (
                "Found %d secured entit(y/ies) with saas='office365_emails' in the search results "
                "(sample entityId=%s, entityCreated=%s), confirming the Microsoft 365 tenant is actively "
                "linked and streaming entities to Check Point."
            ) % (
                len(o365_entities),
                sample.get("entityId", "unknown"),
                sample.get("entityCreated", "unknown"),
            )
        ]
        return create_response(
            result={"isLinkedO365AccountActive": True},
            validation=validation,
            pass_reasons=pass_reasons,
            input_summary=input_summary,
            metadata=metadata,
        )
    else:
        fail_reasons = [
            (
                "No secured entities with saas='office365_emails' were returned by the entity search "
                "(responseData contained %d items, totalRecordsNumber=%s), indicating no actively linked "
                "and streaming Microsoft 365 tenant was found."
            ) % (len(items), total_records)
        ]
        recommendations = [
            "Confirm the Microsoft 365 tenant connector is authorized and actively syncing in the Check Point Harmony portal."
        ]
        return create_response(
            result={"isLinkedO365AccountActive": False},
            validation=validation,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=input_summary,
            metadata=metadata,
        )
