"""
Transformation: isIDPEnabled
Vendor: MDR / Managed Detection and Response
Category: Identity / Authentication

Evaluates if SSO/IDP is enabled for the MDR platform.
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
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
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
                "transformationId": "isIDPEnabled",
                "vendor": "MDR Provider",
                "category": "Identity"
            }
        }
    }


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={"isSSOEnabled": False, "isSSOEnabledMDR": False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # Default to True if data is present (indicates active integration)
        default_value = data is not None

        is_sso_enabled = False
        is_sso_enabled_mdr = False

        if isinstance(data, dict):
            is_sso_enabled = data.get('isSSOEnabled', default_value)
            is_sso_enabled_mdr = data.get('isSSOEnabledMDR', default_value)
        else:
            is_sso_enabled = default_value
            is_sso_enabled_mdr = default_value

        additional_findings = []

        # Primary criteria: isSSOEnabled
        if is_sso_enabled:
            pass_reasons.append("Single Sign-On (SSO) enabled for MDR platform")
        else:
            fail_reasons.append("SSO is not enabled")
            recommendations.append("Enable SSO for centralized identity management")

        # Additional finding: isSSOEnabledMDR
        if is_sso_enabled_mdr:
            additional_findings.append({
                "metric": "isSSOEnabledMDR",
                "status": "pass",
                "reason": "Single Sign-On (SSO) enabled for MDR services"
            })
        else:
            additional_findings.append({
                "metric": "isSSOEnabledMDR",
                "status": "fail",
                "reason": "SSO is not enabled for MDR services",
                "recommendation": "Enable SSO for MDR services"
            })

        return create_response(
            result={
                "isSSOEnabled": is_sso_enabled,
                "isSSOEnabledMDR": is_sso_enabled_mdr
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "ssoEnabled": is_sso_enabled,
                "ssoEnabledMDR": is_sso_enabled_mdr
            }
        )

    except Exception as e:
        return create_response(
            result={"isSSOEnabled": False, "isSSOEnabledMDR": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
