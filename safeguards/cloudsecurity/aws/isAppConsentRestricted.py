"""
Transformation: isAppConsentRestricted
Vendor: AWS  |  Category: cloudsecurity
Evaluates: Whether third-party application consent is restricted in the AWS account.
Inspects the OIDC provider list from ListOpenIDConnectProviders to determine whether
unauthorized or unmanaged OIDC/OAuth providers are present, indicating whether app
consent is controlled and limited to approved identity providers.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isAppConsentRestricted", "vendor": "AWS", "category": "cloudsecurity"}
        }
    }


def extract_arn(provider_entry):
    if isinstance(provider_entry, dict):
        return provider_entry.get("Arn", provider_entry.get("arn", ""))
    if isinstance(provider_entry, str):
        return provider_entry
    return ""


def evaluate(data):
    try:
        oidc_providers = data.get("OpenIDConnectProviderList", [])
        if not isinstance(oidc_providers, list):
            oidc_providers = []

        provider_count = len(oidc_providers)
        provider_arns = [extract_arn(p) for p in oidc_providers if extract_arn(p)]

        known_safe_domains = ["oidc.eks.amazonaws.com", "token.actions.githubusercontent.com", "cognito-identity.amazonaws.com"]
        unknown_providers = []
        known_providers = []

        for arn in provider_arns:
            arn_lower = arn.lower()
            is_known = False
            for domain in known_safe_domains:
                if domain in arn_lower:
                    is_known = True
                    break
            if is_known:
                known_providers.append(arn)
            else:
                unknown_providers.append(arn)

        unknown_provider_count = len(unknown_providers)
        known_provider_count = len(known_providers)

        no_unmanaged_providers = unknown_provider_count == 0
        is_restricted = no_unmanaged_providers

        return {
            "isAppConsentRestricted": is_restricted,
            "totalOidcProviders": provider_count,
            "unknownProviderCount": unknown_provider_count,
            "knownProviderCount": known_provider_count,
            "noUnmanagedProviders": no_unmanaged_providers,
            "unknownProviderArns": unknown_providers,
            "knownProviderArns": known_providers
        }
    except Exception as e:
        return {"isAppConsentRestricted": False, "error": str(e)}


def transform(input):
    criteriaKey = "isAppConsentRestricted"
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
            if extra_fields.get("totalOidcProviders", 0) == 0:
                pass_reasons.append("No OIDC/OAuth identity providers are registered — third-party app consent is fully restricted")
            else:
                pass_reasons.append("All registered OIDC providers are from known/approved sources — app consent is controlled")
                pass_reasons.append("Known providers count: " + str(extra_fields.get("knownProviderCount", 0)))
        else:
            unknown_arns = extra_fields.get("unknownProviderArns", [])
            fail_reasons.append("Unmanaged or unrecognized OIDC/OAuth providers detected: " + str(extra_fields.get("unknownProviderCount", 0)))
            for arn in unknown_arns:
                fail_reasons.append("Unrecognized provider: " + arn)
            recommendations.append("Review all registered OIDC identity providers in IAM and remove any that are not explicitly approved")
            recommendations.append("Use AWS Organizations SCPs to restrict creation of OIDC providers to authorized principals only")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
        additional_findings.append("Total OIDC providers registered: " + str(extra_fields.get("totalOidcProviders", 0)))
        known_arns = extra_fields.get("knownProviderArns", [])
        if known_arns:
            additional_findings.append("Known/approved providers: " + ", ".join(known_arns))
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={criteriaKey: result_value, "totalOidcProviders": extra_fields.get("totalOidcProviders", 0), "unknownProviderCount": extra_fields.get("unknownProviderCount", 0)}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
