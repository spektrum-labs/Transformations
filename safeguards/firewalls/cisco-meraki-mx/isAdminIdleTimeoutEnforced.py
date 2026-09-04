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

    enforce_idle_timeout = data.get("enforceIdleTimeout")
    if not isinstance(enforce_idle_timeout, bool):
        enforce_idle_timeout = False

    idle_timeout_minutes_raw = data.get("idleTimeoutMinutes")
    idle_timeout_minutes = None
    if isinstance(idle_timeout_minutes_raw, (int, float)) and not isinstance(idle_timeout_minutes_raw, bool):
        idle_timeout_minutes = idle_timeout_minutes_raw

    transformation_errors = []
    if not data:
        transformation_errors.append("Empty or missing loginSecurity response payload.")

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if enforce_idle_timeout:
        if idle_timeout_minutes is not None:
            pass_reasons.append(
                f"Organization login security setting enforceIdleTimeout=true with idleTimeoutMinutes={idle_timeout_minutes}, "
                f"confirming automatic Dashboard session termination after inactivity."
            )
        else:
            pass_reasons.append(
                "Organization login security setting enforceIdleTimeout=true, confirming automatic Dashboard "
                "session termination after admin inactivity is enforced."
            )
    else:
        fail_reasons.append(
            f"Organization login security setting enforceIdleTimeout={enforce_idle_timeout} "
            f"(idleTimeoutMinutes={idle_timeout_minutes_raw}), indicating admin Dashboard sessions do not "
            f"automatically time out after inactivity."
        )
        recommendations.append(
            "Enable 'Idle timeout' under Organization > Configure > Login attempts / Security settings in the "
            "Meraki Dashboard and set an appropriate idleTimeoutMinutes value (e.g. 30 minutes)."
        )

    result = {
        "isAdminIdleTimeoutEnforced": enforce_idle_timeout,
        "idleTimeoutMinutes": idle_timeout_minutes,
    }

    input_summary = {
        "enforceIdleTimeout": enforce_idle_timeout,
        "idleTimeoutMinutes": idle_timeout_minutes_raw,
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
            "transformationId": "isAdminIdleTimeoutEnforced",
            "vendor": "Cisco Meraki MX",
            "category": "firewalls",
        },
    )
