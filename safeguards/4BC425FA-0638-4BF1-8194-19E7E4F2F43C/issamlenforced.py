"""
Transformation: isSAMLEnforced
Vendor: AWS
Category: Identity / SSO

Evaluates the SAML enforcement status of the AWS account.
"""

import json
from datetime import datetime

#: The criterion this file answers; a None value is reported as not measured.
CRITERIA_KEY = "isSAMLEnforced"


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
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    # Not measured is read off the criterion's value, so every path that leaves it None -- the
    # except branch included -- reaches Token-Service as not evaluated rather than as a gap.
    measured = result.get(CRITERIA_KEY) is not None
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "success" if measured else "error",
                "errors": [] if measured else (api_errors or fail_reasons or transformation_errors
                                               or ["The response could not answer this check, so it was not evaluated."])
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
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
    criteriaKey = CRITERIA_KEY

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: None},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # Extract SAML providers. Only a ListSAMLProviders response is a reading; an account with no
        # provider returns an empty <SAMLProviderList/>, which parses to None and is a measured "none".
        saml_response = data.get("ListSAMLProvidersResponse") if isinstance(data, dict) else None
        saml_result = saml_response.get("ListSAMLProvidersResult") if isinstance(saml_response, dict) else None
        if not isinstance(saml_result, dict):
            return create_response(
                result={criteriaKey: None},
                validation=validation,
                api_errors=["Response has no ListSAMLProvidersResult; the IAM SAML providers were not read"],
                fail_reasons=["Not measured: " + "Response has no ListSAMLProvidersResult; the IAM SAML providers were not read"],
                recommendations=["Confirm the AWS credential can call the describe APIs and that each returned a 2xx body."]
            )

        saml_provider_list = saml_result.get("SAMLProviderList") or {}
        saml_providers = saml_provider_list.get("member", []) if isinstance(saml_provider_list, dict) else saml_provider_list
        if saml_providers is None:
            saml_providers = []

        if isinstance(saml_providers, dict):
            saml_providers = [saml_providers]

        is_saml_enforced = False
        valid_providers = []
        expired_providers = []

        def parse_iso_date(date_str):
            """Parse ISO 8601 date without using strptime or map (not available in RestrictedPython)."""
            try:
                # Format: "2026-01-26T11:26:33Z" or "2026-01-26T11:26:33.123Z"
                date_str = date_str.replace("Z", "").split(".")[0]  # Remove Z and microseconds
                date_part, time_part = date_str.split("T")
                date_parts = date_part.split("-")
                time_parts = time_part.split(":")
                year, month, day = int(date_parts[0]), int(date_parts[1]), int(date_parts[2])
                hour, minute, second = int(time_parts[0]), int(time_parts[1]), int(time_parts[2])
                return datetime(year, month, day, hour, minute, second)
            except (ValueError, AttributeError, IndexError):
                return None

        for provider in saml_providers:
            valid_until = provider.get("ValidUntil", "")
            provider_arn = provider.get("Arn", "unknown")
            if valid_until:
                valid_until_date = parse_iso_date(valid_until)
                if valid_until_date:
                    if valid_until_date > datetime.utcnow():
                        is_saml_enforced = True
                        valid_providers.append(provider_arn)
                    else:
                        expired_providers.append(provider_arn)

        if is_saml_enforced:
            pass_reasons.append(f"SAML is enforced with {len(valid_providers)} valid providers")
        else:
            if expired_providers:
                fail_reasons.append(f"All SAML providers have expired ({len(expired_providers)} expired)")
            else:
                fail_reasons.append("No SAML identity providers configured")
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
            result={criteriaKey: None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
