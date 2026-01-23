"""
Transformation: areAntiPhishingPoliciesConfigured
Vendor: Microsoft
Category: Email Security / Anti-Phishing

Evaluates if anti-phishing policies are properly configured with all required settings.
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
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "validationStatus": validation.get("status", "unknown"),
            "validationErrors": validation.get("errors", []),
            "validationWarnings": validation.get("warnings", []),
            "transformationErrors": transformation_errors or [],

            "apiErrors": api_errors or [],
            "passReasons": pass_reasons or [],

            "failReasons": fail_reasons or [],
            "recommendations": recommendations or [],
            "inputSummary": input_summary or {},
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "areAntiPhishingPoliciesConfigured",
                "vendor": "Microsoft",
                "category": "Email Security"
            }
        }
    }


def transform(input):
    criteriaKey = "areAntiPhishingPoliciesConfigured"

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

        # Check for PowerShell error
        if 'PSError' in data:
            return create_response(
                result={criteriaKey: False},
                validation={"status": "skipped", "errors": [], "warnings": ["API returned error"]},
                api_errors=[data.get('PSError', 'PowerShell error')],
                fail_reasons=["PowerShell execution error"],
                recommendations=["Check API credentials and permissions"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        policies = data.get('policies', [])
        if not isinstance(policies, list):
            policies = [policies] if policies else []

        # Find policies that meet all required settings
        matching_policies = [
            policy for policy in policies
            if (policy.get("Enabled") is True and
                policy.get("EnableMailboxIntelligence") is True and
                policy.get("EnableMailboxIntelligenceProtection") is True and
                policy.get("TargetedDomainProtectionAction") in ("Quarantine", "MoveToJmf") and
                policy.get("EnableSpoofIntelligence") is True and
                policy.get("EnableUnauthenticatedSender") is True and
                policy.get("AuthenticationFailAction") in ("Quarantine", "MoveToJmf") and
                policy.get("EnableFirstContactSafetyTips") is True and
                policy.get("EnableSimilarUsersSafetyTips") is True and
                policy.get("EnableSimilarDomainsSafetyTips") is True and
                policy.get("EnableUnusualCharactersSafetyTips") is True and
                policy.get("EnableViaTag") is True and
                (policy.get("PhishThresholdLevel") or 0) > 1)
        ]

        is_configured = len(matching_policies) > 0

        if is_configured:
            policy_names = [p.get('Name', 'unnamed') for p in matching_policies[:3]]
            pass_reasons.append(f"Anti-phishing policies properly configured: {', '.join(policy_names)}")
        else:
            if len(policies) > 0:
                fail_reasons.append(f"Found {len(policies)} policy(ies) but none meet all security requirements")
            else:
                fail_reasons.append("No anti-phishing policies found")
            recommendations.append("Configure anti-phishing policies with mailbox intelligence, spoof intelligence, and safety tips enabled")

        return create_response(
            result={criteriaKey: is_configured, "totalPolicies": len(policies), "compliantPolicies": len(matching_policies)},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalPolicies": len(policies), "compliantPolicies": len(matching_policies)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
