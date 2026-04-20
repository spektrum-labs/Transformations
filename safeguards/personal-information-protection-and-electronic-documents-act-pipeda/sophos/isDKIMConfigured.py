"""
Transformation: isDKIMConfigured
Vendor: Sophos  |  Category: personal-information-protection-and-electronic-documents-act-pipeda
Evaluates: Whether DKIM signing and verification is configured in Sophos Email policies for outbound and inbound email.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for idx in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isDKIMConfigured", "vendor": "Sophos", "category": "personal-information-protection-and-electronic-documents-act-pipeda"}
        }
    }


def find_dkim_in_policy(policy):
    settings = policy.get("settings", {})

    sender_auth = settings.get("senderAuthentication", {})
    dkim_verify = sender_auth.get("dkimVerification", {})
    dkim_signing = sender_auth.get("dkimSigning", {})

    verify_enabled = dkim_verify.get("enabled", False) or dkim_verify.get("action", "") not in ["", "none", "disabled"]
    signing_enabled = dkim_signing.get("enabled", False)

    inbound = settings.get("inbound", {})
    inbound_auth = inbound.get("senderAuthentication", {})
    inbound_dkim = inbound_auth.get("dkim", {})
    inbound_enabled = inbound_dkim.get("enabled", False) or inbound_dkim.get("check", False)

    outbound = settings.get("outbound", {})
    outbound_auth = outbound.get("senderAuthentication", {})
    outbound_dkim = outbound_auth.get("dkim", {})
    outbound_signing = outbound_dkim.get("enabled", False) or outbound_dkim.get("sign", False)

    anti_spoofing = settings.get("antiSpoofing", {})
    dkim_check = anti_spoofing.get("dkimCheck", False) or anti_spoofing.get("dkim", False)

    return verify_enabled or signing_enabled or inbound_enabled or outbound_signing or dkim_check


def evaluate(data):
    try:
        items = data.get("items", [])
        if not items:
            return {"isDKIMConfigured": False, "error": "No email policy items found in response"}

        base_policy_dkim = False
        custom_policy_dkim = False
        policies_checked = 0

        for policy in items:
            policy_type = policy.get("type", "").lower()
            is_base = policy_type in ["base", "default"] or policy.get("isDefault", False) or policy.get("name", "").lower() in ["base policy", "default"]

            dkim_found = find_dkim_in_policy(policy)
            policies_checked = policies_checked + 1

            if is_base and dkim_found:
                base_policy_dkim = True
            if not is_base and dkim_found:
                custom_policy_dkim = True

        dkim_configured = base_policy_dkim or custom_policy_dkim

        return {
            "isDKIMConfigured": dkim_configured,
            "basePolicyDKIMEnabled": base_policy_dkim,
            "customPolicyDKIMEnabled": custom_policy_dkim,
            "totalPoliciesChecked": policies_checked
        }
    except Exception as e:
        return {"isDKIMConfigured": False, "error": str(e)}


def transform(input):
    criteriaKey = "isDKIMConfigured"
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
        if result_value:
            pass_reasons.append("DKIM signing and/or verification is configured in Sophos Email policies")
            if extra_fields.get("basePolicyDKIMEnabled", False):
                pass_reasons.append("DKIM is configured in the base/default policy")
            if extra_fields.get("customPolicyDKIMEnabled", False):
                pass_reasons.append("DKIM is configured in one or more custom policies")
        else:
            fail_reasons.append("DKIM is not configured in any Sophos Email policy")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable DKIM verification in Sophos Email base policy sender authentication settings")
            recommendations.append("Configure DKIM signing for outbound email in Sophos Email policies")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
