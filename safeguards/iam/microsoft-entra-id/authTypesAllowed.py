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
        policy = {}
    elif isinstance(data, dict):
        policy = data
    else:
        policy = {}

    configs = policy.get("authenticationMethodConfigurations") or []
    if not isinstance(configs, list):
        configs = []

    enabled_methods = []
    disabled_methods = []
    for cfg in configs:
        if not isinstance(cfg, dict):
            continue
        method_id = cfg.get("id") or "unknown"
        state = cfg.get("state") or "unknown"
        if state == "enabled":
            enabled_methods.append(method_id)
        elif state == "disabled":
            disabled_methods.append(method_id)

    total_configs = len(configs)

    if total_configs == 0:
        result = {
            "authTypesAllowed": [],
            "enabledMethodCount": 0,
            "totalMethodCount": 0,
        }
        return create_response(
            result=result,
            validation=validation,
            fail_reasons=["No authenticationMethodConfigurations were found in the authenticationMethodsPolicy response."],
            recommendations=["Verify the authenticationMethodsPolicy resource returns authenticationMethodConfigurations for this tenant."],
            input_summary={"totalMethodCount": 0, "enabledMethodCount": 0},
            metadata={"transformationId": "authTypesAllowed", "vendor": "Microsoft Entra ID", "category": "Multifactor Authentication"},
        )

    result = {
        "authTypesAllowed": enabled_methods,
        "enabledMethodCount": len(enabled_methods),
        "totalMethodCount": total_configs,
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if enabled_methods:
        pass_reasons.append(
            "authenticationMethodsPolicy reports %d of %d authentication method configurations with state=enabled: %s."
            % (len(enabled_methods), total_configs, ", ".join(enabled_methods))
        )
    else:
        fail_reasons.append(
            "No authentication method configurations report state=enabled among %d configured methods (%s)."
            % (total_configs, ", ".join(disabled_methods))
        )
        recommendations.append(
            "Enable at least one strong authentication method (e.g. Fido2 or MicrosoftAuthenticator) in the tenant's authenticationMethodsPolicy."
        )

    if disabled_methods:
        pass_reasons.append(
            "The following methods are explicitly disabled: %s." % ", ".join(disabled_methods)
        )

    weak_enabled = [m for m in enabled_methods if m in ("Sms", "Voice", "Email")]
    if weak_enabled:
        recommendations.append(
            "Consider disabling weaker authentication methods still enabled: %s, in favor of phishing-resistant methods (Fido2, X509Certificate, MicrosoftAuthenticator)."
            % ", ".join(weak_enabled)
        )

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalMethodCount": total_configs, "enabledMethodCount": len(enabled_methods)},
        metadata={"transformationId": "authTypesAllowed", "vendor": "Microsoft Entra ID", "category": "Multifactor Authentication"},
    )
