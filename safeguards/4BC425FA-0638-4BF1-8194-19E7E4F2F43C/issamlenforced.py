"""
Transformation: isSAMLEnforced
Vendor: AWS
Category: Identity / SSO

Evaluates the SAML enforcement status of the AWS account.
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
                    recommendations=None, input_summary=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "validationStatus": validation.get("status", "unknown"),
            "validationErrors": validation.get("errors", []),
            "validationWarnings": validation.get("warnings", []),
            "passReasons": pass_reasons or [],
            "failReasons": fail_reasons or [],
            "recommendations": recommendations or [],
            "inputSummary": input_summary or {},
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isSAMLEnforced",
                "vendor": "AWS",
                "category": "Identity"
            }
        }
    }


def transform(input):
    criteriaKey = "isSAMLEnforced"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # Extract SAML providers
        saml_response = data.get("ListSAMLProvidersResponse", {}) if isinstance(data, dict) else {}
        saml_result = saml_response.get("ListSAMLProvidersResult", {})
        saml_provider_list = saml_result.get("SAMLProviderList", {})
        saml_providers = saml_provider_list.get("member", [])

        if isinstance(saml_providers, dict):
            saml_providers = [saml_providers]

        is_saml_enforced = False
        valid_providers = []
        expired_providers = []

        for provider in saml_providers:
            valid_until = provider.get("ValidUntil", "")
            provider_arn = provider.get("Arn", "unknown")
            if valid_until:
                try:
                    valid_until_date = datetime.strptime(valid_until, "%Y-%m-%dT%H:%M:%SZ")
                    if valid_until_date > datetime.utcnow():
                        is_saml_enforced = True
                        valid_providers.append(provider_arn)
                    else:
                        expired_providers.append(provider_arn)
                except ValueError:
                    pass

        if is_saml_enforced:
            pass_reasons.append(f"SAML is enforced with {len(valid_providers)} valid provider(s)")
        else:
            if expired_providers:
                fail_reasons.append(f"All SAML providers have expired ({len(expired_providers)} expired)")
            else:
                fail_reasons.append("No valid SAML providers configured")
            recommendations.append("Configure and enable SAML identity provider for federated access")

        return create_response(
            result={criteriaKey: is_saml_enforced},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "totalProviders": len(saml_providers),
                "validProviders": len(valid_providers),
                "expiredProviders": len(expired_providers)
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [str(e)], "warnings": []},
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
