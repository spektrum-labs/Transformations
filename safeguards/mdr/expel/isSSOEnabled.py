"""
Transformation: isSSOEnabled
Vendor: Expel  |  Category: mdr
Evaluates: Check if at least one SAML identity provider record is present in the
response data array, indicating that Single Sign-On (SSO) has been configured for
the Expel Workbench organization.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for i in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isSSOEnabled", "vendor": "Expel", "category": "mdr"}
        }
    }


def evaluate(data):
    try:
        providers = data.get("data", [])
        if not isinstance(providers, list):
            providers = []

        total_providers = len(providers)
        provider_details = []

        for provider in providers:
            if not isinstance(provider, dict):
                continue
            attributes = provider.get("attributes", {})
            if not isinstance(attributes, dict):
                attributes = {}

            name = attributes.get("name", provider.get("id", "unknown"))
            issuer = attributes.get("issuer", attributes.get("entity_id", "unknown"))
            enabled = attributes.get("enabled", True)
            sso_url = attributes.get("sso_url", attributes.get("idp_sso_url", ""))

            provider_details.append({
                "name": str(name),
                "issuer": str(issuer),
                "enabled": enabled,
                "ssoUrl": str(sso_url)
            })

        sso_enabled = total_providers > 0

        return {
            "isSSOEnabled": sso_enabled,
            "totalSamlProviders": total_providers,
            "samlProviders": provider_details
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

        total_providers = eval_result.get("totalSamlProviders", 0)
        provider_details = eval_result.get("samlProviders", [])

        if result_value:
            pass_reasons.append("SSO is enabled: " + str(total_providers) + " SAML identity provider(s) configured in Expel Workbench.")
            for p in provider_details:
                detail = "Provider: " + str(p.get("name", "unknown"))
                issuer = str(p.get("issuer", ""))
                if issuer and issuer != "unknown":
                    detail = detail + " (issuer: " + issuer + ")"
                additional_findings.append(detail)
        else:
            fail_reasons.append("SSO is not configured. No SAML identity providers found in Expel Workbench.")
            recommendations.append("Configure a SAML identity provider in Expel Workbench to enable Single Sign-On for your organization. Navigate to Organization Settings > Authentication in Workbench.")

        if "error" in eval_result:
            fail_reasons.append("Evaluation error: " + eval_result["error"])

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalSamlProviders": total_providers}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
