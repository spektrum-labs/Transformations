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
    if data.get("error") is True or data.get("statusCode") == 401:
        api_errors.append(str(data.get("errorMessage") or data.get("message") or "API error"))

    items = data.get("responseData") or data.get("data") or []
    if not isinstance(items, list):
        items = []

    total_entities = len(items)
    dmarc_field_found = 0
    dmarc_pass_count = 0
    dmarc_fail_count = 0
    sample_fields = []

    for entity in items:
        if not isinstance(entity, dict):
            continue
        payload = entity.get("entityPayload")
        if not isinstance(payload, dict):
            continue
        for key, value in payload.items():
            key_lower = str(key).lower()
            if "dmarc" in key_lower:
                dmarc_field_found = dmarc_field_found + 1
                value_str = str(value).lower()
                if len(sample_fields) < 3:
                    sample_fields.append(f"{key}={value}")
                if "pass" in value_str or value_str == "true":
                    dmarc_pass_count = dmarc_pass_count + 1
                elif "fail" in value_str or value_str == "false" or "none" in value_str:
                    dmarc_fail_count = dmarc_fail_count + 1

    is_honored = False
    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if api_errors:
        fail_reasons.append(
            f"searchEntities API call failed with error(s): {', '.join(api_errors)}; unable to confirm DMARC monitoring."
        )
        recommendations.append(
            "Verify Check Point Harmony API credentials (clientId/accessKey) have permission to call /search/query."
        )
    elif total_entities == 0:
        fail_reasons.append(
            "searchEntities returned zero entities in responseData; no DMARC authentication-result data available to confirm active monitoring."
        )
        recommendations.append(
            "Confirm the O365/Gmail SaaS connector is linked and that entities are being ingested and scanned by Harmony Email Security."
        )
    elif dmarc_field_found == 0:
        fail_reasons.append(
            f"Scanned {total_entities} entities via searchEntities but found no entityPayload field containing 'dmarc'; DMARC evaluation results are not present in queryable security events."
        )
        recommendations.append(
            "Enable DMARC authentication-result capture in the Harmony Email Security policy so violations are recorded as queryable events."
        )
    else:
        is_honored = dmarc_fail_count > 0 or dmarc_pass_count > 0
        if is_honored:
            pass_reasons.append(
                f"Found {dmarc_field_found} DMARC-related field(s) across {total_entities} entities via searchEntities "
                f"(pass={dmarc_pass_count}, fail={dmarc_fail_count}); sample values: {', '.join(sample_fields)}. "
                "DMARC evaluation results are captured and queryable, confirming active DMARC monitoring/alerting."
            )
        else:
            fail_reasons.append(
                f"DMARC field(s) present ({dmarc_field_found}) but no discernible pass/fail verdicts across {total_entities} entities."
            )
            recommendations.append(
                "Review DMARC policy enforcement configuration to ensure pass/fail verdicts are recorded on scanned entities."
            )

    result = {
        "isDMARCPolicyHonored": is_honored,
        "totalEntitiesScanned": total_entities,
        "dmarcFieldsFound": dmarc_field_found,
        "dmarcPassCount": dmarc_pass_count,
        "dmarcFailCount": dmarc_fail_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalEntitiesScanned": total_entities,
            "dmarcFieldsFound": dmarc_field_found,
        },
        api_errors=api_errors,
        metadata={
            "transformationId": "isDMARCPolicyHonored",
            "vendor": "Check Point Software Technologies Email Security",
            "category": "emailsecurity",
        },
    )
