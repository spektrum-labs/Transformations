"""
Transformation: isSSOEnabled
Vendor: Sophos  |  Category: epp
Evaluates: Checks whether an Identity Provider (SSO/SAML) is configured and enabled in Sophos
           Central by inspecting the items[] array returned from the getIdentityProvider endpoint.
           At least one active IDP entry must be present for the check to pass.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isSSOEnabled", "vendor": "Sophos", "category": "epp"}
        }
    }


def is_active_idp(idp_item):
    if not isinstance(idp_item, dict):
        return False
    enabled_flag = idp_item.get("enabled", None)
    if enabled_flag is True:
        return True
    status = str(idp_item.get("status", "")).lower()
    if status in ("active", "enabled", "configured"):
        return True
    if enabled_flag is None and "id" in idp_item:
        return True
    return False


def evaluate(data):
    try:
        items = data.get("items", [])
        if not isinstance(items, list):
            items = []
        total_providers = len(items)
        active_providers = 0
        provider_names = []
        for idp in items:
            if is_active_idp(idp):
                active_providers = active_providers + 1
                name = idp.get("name", idp.get("type", "Unknown"))
                provider_names.append(str(name))
        sso_enabled = active_providers > 0
        return {
            "isSSOEnabled": sso_enabled,
            "totalIdentityProviders": total_providers,
            "activeIdentityProviders": active_providers,
            "providerNames": provider_names
        }
    except Exception as e:
        return {"isSSOEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isSSOEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        if result_value:
            active = extra_fields.get("activeIdentityProviders", 0)
            names = extra_fields.get("providerNames", [])
            pass_reasons.append(str(active) + " active Identity Provider(s) configured in Sophos Central")
            if names:
                additional_findings.append("Configured providers: " + ", ".join(names))
        else:
            total = extra_fields.get("totalIdentityProviders", 0)
            if total == 0:
                fail_reasons.append("No Identity Providers found in Sophos Central IDP settings")
            else:
                fail_reasons.append(str(total) + " Identity Provider(s) found but none are active/enabled")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Configure an Identity Provider (SAML/SSO) in Sophos Central under Global Settings > Identity Provider")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={criteriaKey: result_value, "totalIdentityProviders": extra_fields.get("totalIdentityProviders", 0)})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
