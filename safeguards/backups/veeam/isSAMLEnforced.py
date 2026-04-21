"""
Transformation: isSAMLEnforced
Vendor: Veeam  |  Category: Backup
Evaluates: Whether a SAML 2.0 identity provider is configured in Veeam Backup & Replication,
           confirming SAML-based SSO authentication has been set up, based on
           GET /api/v1/security/identityProviders response.
"""
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isSAMLEnforced", "vendor": "Veeam", "category": "Backup"}
        }
    }


def evaluate(data):
    try:
        providers = data.get("data", [])
        if not isinstance(providers, list):
            providers = []
        total_providers = len(providers)
        is_saml_enforced = total_providers > 0
        provider_names = []
        provider_types = []
        for provider in providers:
            name = provider.get("name", provider.get("id", "Unnamed"))
            provider_type = provider.get("type", provider.get("protocol", "SAML"))
            provider_names.append(str(name))
            type_str = str(provider_type)
            if type_str not in provider_types:
                provider_types.append(type_str)
        return {
            "isSAMLEnforced": is_saml_enforced,
            "totalIdentityProviders": total_providers,
            "providerNames": provider_names,
            "providerTypes": provider_types
        }
    except Exception as e:
        return {"isSAMLEnforced": False, "error": str(e)}


def transform(input):
    criteriaKey = "isSAMLEnforced"
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
        total_providers = eval_result.get("totalIdentityProviders", 0)
        provider_names = eval_result.get("providerNames", [])
        provider_types = eval_result.get("providerTypes", [])
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        if result_value:
            pass_reasons.append(str(total_providers) + " SAML identity provider(s) configured in Veeam Backup and Replication")
            if provider_names:
                additional_findings.append("Configured providers: " + ", ".join(provider_names))
            if provider_types:
                additional_findings.append("Provider types detected: " + ", ".join(provider_types))
        else:
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            else:
                fail_reasons.append("No SAML identity providers are configured in Veeam Backup and Replication")
                recommendations.append("Configure a SAML 2.0 identity provider in VBR via Configuration > Security > Identity Providers")
                recommendations.append("Enforce SSO authentication to improve access control and meet security requirements")
        return create_response(
            result={criteriaKey: result_value, "totalIdentityProviders": total_providers, "providerTypes": provider_types},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalIdentityProviders": total_providers})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
