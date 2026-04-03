"""
Transformation: isEmailLoggingEnabled
Vendor: Mimecast
Category: Email Security / Logging

Ensures email security logs are integrated with SIEM.
Evaluates anti-spoofing bypass policies from the Mimecast API to determine
if email logging and monitoring policies are active.
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
                "transformationId": "isEmailLoggingEnabled",
                "vendor": "Mimecast",
                "category": "Email Security"
            }
        }
    }


def transform(input):
    criteriaKey = "isEmailLoggingEnabled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed" and not isinstance(data, list):
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        logging_enabled = False
        total_policies = 0
        enabled_policies = 0
        additional_findings = []

        policies = []
        if isinstance(data, list):
            policies = data
        elif isinstance(data, dict):
            policies = data.get("data", [])

        if isinstance(policies, list):
            total_policies = len(policies)
            for policy_entry in policies:
                if not isinstance(policy_entry, dict):
                    continue
                policy = policy_entry.get("policy", {})
                if not isinstance(policy, dict):
                    continue
                is_enabled = policy.get("enabled", False)
                if is_enabled:
                    enabled_policies += 1
                    description = policy.get("description", "Unnamed policy")
                    additional_findings.append(f"Enabled policy: {description}")

            logging_enabled = enabled_policies > 0

        if logging_enabled:
            pass_reasons.append(
                f"Email logging is enabled ({enabled_policies} of {total_policies} "
                f"anti-spoofing bypass {'policy' if total_policies == 1 else 'policies'} enabled)"
            )
        else:
            if total_policies > 0:
                fail_reasons.append(
                    f"No enabled anti-spoofing bypass policies found ({total_policies} "
                    f"{'policy' if total_policies == 1 else 'policies'} configured but none enabled)"
                )
            else:
                fail_reasons.append("No anti-spoofing bypass policies found")
            recommendations.append("Enable anti-spoofing bypass policies in Mimecast to ensure email logging and SIEM integration")

        return create_response(
            result={
                criteriaKey: logging_enabled,
                "totalPolicies": total_policies,
                "enabledPolicies": enabled_policies
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "totalPolicies": total_policies,
                "enabledPolicies": enabled_policies
            },
            additional_findings=additional_findings
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
