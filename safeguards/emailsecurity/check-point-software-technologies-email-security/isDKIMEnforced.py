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


def get_dkim_status(entity_payload):
    """Attempt to locate a DKIM authentication verdict inside an entity payload,
    checking several documented/likely field name variants defensively."""
    if not isinstance(entity_payload, dict):
        return None

    direct_keys = ["dkim", "dkimResult", "dkimCheckResult", "dkimStatus", "dkimAuthResult"]
    for k in direct_keys:
        v = entity_payload.get(k)
        if isinstance(v, str) and v:
            return v

    auth_results = entity_payload.get("authResults") or entity_payload.get("authenticationResults")
    if isinstance(auth_results, dict):
        for k in ["dkim", "dkimResult", "dkimStatus"]:
            v = auth_results.get(k)
            if isinstance(v, str) and v:
                return v

    return None


def is_pass_value(value):
    if not isinstance(value, str):
        return False
    v = value.strip().lower()
    return v in ("pass", "passed", "valid", "signed", "true", "enforced")


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    api_errors = []
    if data.get("error") or data.get("errorType") == "authentication":
        api_errors.append(str(data.get("errorMessage") or data.get("message") or "API error"))

    items = data.get("responseData")
    if not isinstance(items, list):
        items = []

    total_entities = len(items)
    checked = 0
    passed = 0
    unknown = 0

    for entity in items:
        if not isinstance(entity, dict):
            continue
        payload = entity.get("entityPayload")
        status = get_dkim_status(payload)
        if status is None:
            unknown = unknown + 1
            continue
        checked = checked + 1
        if is_pass_value(status):
            passed = passed + 1

    input_summary = {
        "totalEntities": total_entities,
        "checkedForDkim": checked,
        "dkimPassCount": passed,
        "dkimUnknownCount": unknown,
        "apiErrors": api_errors,
    }

    if api_errors:
        return create_response(
            result={"isDKIMEnforced": False},
            validation=validation,
            fail_reasons=[
                f"Unable to evaluate DKIM enforcement: API returned an error ({'; '.join(api_errors)})."
            ],
            recommendations=[
                "Verify the API credentials (clientId/accessKey) and re-run the DKIM enforcement check."
            ],
            input_summary=input_summary,
            api_errors=api_errors,
            metadata={
                "transformationId": "isDKIMEnforced",
                "vendor": "Check Point Software Technologies Email Security",
                "category": "Email Security",
            },
        )

    if total_entities == 0 or checked == 0:
        return create_response(
            result={"isDKIMEnforced": False},
            validation=validation,
            fail_reasons=[
                f"No email entities with a resolvable DKIM authentication verdict were found among {total_entities} entities returned by /search/query."
            ],
            recommendations=[
                "Ensure the search query targets office365_emails/google_mail entities and that entityPayload includes DKIM authentication result fields."
            ],
            input_summary=input_summary,
            metadata={
                "transformationId": "isDKIMEnforced",
                "vendor": "Check Point Software Technologies Email Security",
                "category": "Email Security",
            },
        )

    is_enforced = passed == checked

    if is_enforced:
        return create_response(
            result={"isDKIMEnforced": True},
            validation=validation,
            pass_reasons=[
                f"All {checked} email entities with a DKIM verdict report a passing DKIM signature (entityPayload DKIM result = pass) out of {total_entities} entities inspected."
            ],
            input_summary=input_summary,
            metadata={
                "transformationId": "isDKIMEnforced",
                "vendor": "Check Point Software Technologies Email Security",
                "category": "Email Security",
            },
        )
    else:
        failed = checked - passed
        return create_response(
            result={"isDKIMEnforced": False},
            validation=validation,
            fail_reasons=[
                f"{failed} of {checked} email entities with a DKIM verdict failed DKIM validation (entityPayload DKIM result != pass), out of {total_entities} entities inspected."
            ],
            recommendations=[
                "Enable or correct Check Point's managed DKIM signing configuration for the affected domains so all outbound mail passes DKIM validation."
            ],
            input_summary=input_summary,
            metadata={
                "transformationId": "isDKIMEnforced",
                "vendor": "Check Point Software Technologies Email Security",
                "category": "Email Security",
            },
        )
