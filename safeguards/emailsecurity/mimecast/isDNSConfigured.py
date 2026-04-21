"""
Transformation: isDNSConfigured
Vendor: Mimecast  |  Category: emailsecurity
Evaluates: Ensure that DMARC, DKIM and SPF records are set up properly
           by verifying at least one active DNS Authentication Outbound policy exists.
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
                "transformationId": "isDNSConfigured",
                "vendor": "Mimecast",
                "category": "emailsecurity"
            }
        }
    }


def get_policy_list(data):
    """
    Extract the list of DNS auth outbound policies from the API response.
    Mimecast /api/gateway/policies/dns-auth-outbound returns:
      { "data": [ { "id": "...", "policy": { ... }, "option": { ... } }, ... ] }
    The returnSpec maps data -> data, so by the time we receive it the top-level
    key is already 'data'.
    """
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ["data", "policies", "items", "results"]:
            val = data.get(key)
            if isinstance(val, list):
                return val
    return []


def is_policy_enabled(policy_entry):
    """Return True if a policy entry is considered active/enabled."""
    if isinstance(policy_entry, dict):
        # Direct enabled flag
        if "enabled" in policy_entry:
            return bool(policy_entry.get("enabled"))
        # Nested under 'policy' key
        nested = policy_entry.get("policy")
        if isinstance(nested, dict) and "enabled" in nested:
            return bool(nested.get("enabled"))
        # If there is no explicit enabled flag, treat existence as enabled
        return True
    return False


def evaluate(data):
    """
    Core evaluation logic for isDNSConfigured.

    Criteria: At least one DNS Authentication Outbound policy must exist
    and be enabled, indicating that DKIM/SPF/DMARC outbound signing or
    verification is configured in Mimecast.
    """
    try:
        policies = get_policy_list(data)
        total_policies = len(policies)

        if total_policies == 0:
            return {
                "isDNSConfigured": False,
                "totalPolicies": 0,
                "enabledPolicies": 0,
                "error": "No DNS Authentication Outbound policies found"
            }

        enabled_count = 0
        for policy in policies:
            if is_policy_enabled(policy):
                enabled_count = enabled_count + 1

        is_configured = enabled_count > 0

        return {
            "isDNSConfigured": is_configured,
            "totalPolicies": total_policies,
            "enabledPolicies": enabled_count
        }

    except Exception as e:
        return {"isDNSConfigured": False, "error": str(e)}


def transform(input):
    criteriaKey = "isDNSConfigured"
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

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        total = eval_result.get("totalPolicies", 0)
        enabled = eval_result.get("enabledPolicies", 0)

        if result_value:
            pass_reasons.append(
                "DNS Authentication Outbound policies are configured: "
                + str(enabled) + " of " + str(total) + " policy(s) are enabled"
            )
            pass_reasons.append(
                "DKIM/SPF/DMARC outbound configuration is active in Mimecast"
            )
        else:
            if total == 0:
                fail_reasons.append(
                    "No DNS Authentication Outbound policies found in Mimecast"
                )
                recommendations.append(
                    "Create at least one DNS Authentication Outbound policy in the Mimecast "
                    "Administration Console under Gateway | Policies | DNS Authentication Outbound"
                )
            else:
                fail_reasons.append(
                    str(total) + " DNS Authentication Outbound policy(s) exist but none are enabled"
                )
                recommendations.append(
                    "Enable at least one DNS Authentication Outbound policy in Mimecast to ensure "
                    "DKIM signing and DMARC/SPF verification are active"
                )
            recommendations.append(
                "Ensure DMARC, DKIM, and SPF DNS records are published and that Mimecast "
                "DNS Authentication policies reference the correct signing profile"
            )

            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])

        additional_findings.append(
            "Total DNS Auth Outbound policies: " + str(total)
        )
        additional_findings.append(
            "Enabled DNS Auth Outbound policies: " + str(enabled)
        )

        full_result = {criteriaKey: result_value}
        for k, v in extra_fields.items():
            full_result[k] = v

        return create_response(
            result=full_result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                criteriaKey: result_value,
                "totalPolicies": total,
                "enabledPolicies": enabled
            },
            additional_findings=additional_findings
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
