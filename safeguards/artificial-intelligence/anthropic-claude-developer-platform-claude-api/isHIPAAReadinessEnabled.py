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

    settings = []
    if isinstance(data, dict):
        settings = data.get("settings") or []
    elif isinstance(data, list):
        settings = data

    hipaa_row = None
    for row in settings:
        if isinstance(row, dict) and row.get("name") == "hipaa_compliance_enabled":
            hipaa_row = row
            break

    transformation_errors = []
    if hipaa_row is None:
        is_hipaa_enabled = False
        transformation_errors.append(
            "Setting row 'hipaa_compliance_enabled' not found in effective_organization_settings.settings array"
        )
    else:
        is_hipaa_enabled = bool(hipaa_row.get("value"))

    input_summary = {
        "totalSettingsReturned": len(settings),
        "hipaaSettingFound": hipaa_row is not None,
        "hipaaComplianceEnabledValue": hipaa_row.get("value") if hipaa_row else None,
    }

    if hipaa_row is not None and is_hipaa_enabled:
        pass_reasons = [
            "Setting row name='hipaa_compliance_enabled', type='boolean' has value=true in the "
            "organization's effective_organization_settings, indicating HIPAA-readiness data-handling "
            "mode is active and the API will reject non-HIPAA-eligible feature requests."
        ]
        fail_reasons = []
        recommendations = []
    elif hipaa_row is not None and not is_hipaa_enabled:
        pass_reasons = []
        fail_reasons = [
            "Setting row name='hipaa_compliance_enabled' in effective_organization_settings has "
            "value=false, meaning HIPAA-readiness mode is not active and the API will not reject "
            "non-HIPAA-eligible feature usage."
        ]
        recommendations = [
            "Enable HIPAA compliance mode for this organization via the compliance settings so that "
            "requests using features ineligible under HIPAA are rejected with a 400 error."
        ]
    else:
        pass_reasons = []
        fail_reasons = [
            "No 'hipaa_compliance_enabled' setting row was present in the "
            f"{len(settings)} settings returned by the effective organization settings endpoint."
        ]
        recommendations = [
            "Verify the compliance API key has access to organization settings and that HIPAA "
            "compliance has been configured for this organization."
        ]

    result = {
        "isHIPAAReadinessEnabled": is_hipaa_enabled,
        "totalSettingsReturned": len(settings),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        transformation_errors=transformation_errors,
        metadata={
            "transformationId": "isHIPAAReadinessEnabled",
            "vendor": "Anthropic Claude Developer Platform Claude API",
            "category": "artificial-intelligence",
        },
    )
