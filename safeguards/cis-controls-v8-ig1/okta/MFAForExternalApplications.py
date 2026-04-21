"""
Transformation: MFAForExternalApplications
Vendor: Okta  |  Category: cis-controls-v8-ig1
Evaluates: Whether at least one active ACCESS_POLICY (app sign-in policy) contains a rule
           that enforces MFA (factorMode=2FA or equivalent) for external application access.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "MFAForExternalApplications", "vendor": "Okta", "category": "cis-controls-v8-ig1"}
        }
    }


def get_policies_by_type(data, policy_type):
    policies = []
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and item.get("type") == policy_type:
                policies.append(item)
    return policies


def rule_enforces_mfa(rule):
    if not isinstance(rule, dict):
        return False
    actions = rule.get("actions", {})
    app_sign_on = actions.get("appSignOn", {})
    verification = app_sign_on.get("verificationMethod", {})
    factor_mode = verification.get("factorMode", "")
    if factor_mode == "2FA":
        return True
    return False


def evaluate(data):
    try:
        access_policies = get_policies_by_type(data, "ACCESS_POLICY")
        active_policies = [p for p in access_policies if p.get("status") == "ACTIVE"]
        total_policies = len(access_policies)
        active_count = len(active_policies)

        mfa_enforcing_policies = []
        non_mfa_policies = []

        for policy in active_policies:
            name = policy.get("name", "Unnamed")
            rules = policy.get("rules", [])
            if not isinstance(rules, list):
                rules = []
            policy_has_mfa = False
            for rule in rules:
                if rule.get("status", "ACTIVE") != "INACTIVE" and rule_enforces_mfa(rule):
                    policy_has_mfa = True
                    break
            if policy_has_mfa:
                mfa_enforcing_policies.append(name)
            else:
                non_mfa_policies.append(name)

        passes = len(mfa_enforcing_policies) > 0

        return {
            "MFAForExternalApplications": passes,
            "totalAccessPolicies": total_policies,
            "activeAccessPoliciesCount": active_count,
            "policiesEnforcingMFA": len(mfa_enforcing_policies),
            "mfaEnforcingPolicyNames": mfa_enforcing_policies,
            "nonMFAPolicyNames": non_mfa_policies
        }
    except Exception as e:
        return {"MFAForExternalApplications": False, "error": str(e)}


def transform(input):
    criteriaKey = "MFAForExternalApplications"
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
            pass_reasons.append("At least one active ACCESS_POLICY enforces MFA (2FA) for external application access.")
            for name in extra_fields.get("mfaEnforcingPolicyNames", []):
                pass_reasons.append("MFA-enforcing policy: " + name)
        else:
            fail_reasons.append("No active ACCESS_POLICY rule enforces MFA for external applications.")
            for name in extra_fields.get("nonMFAPolicyNames", []):
                additional_findings.append("Policy without MFA enforcement: " + name)
            recommendations.append("Configure at least one app sign-in policy rule with factorMode=2FA to enforce MFA for external application access in Okta.")
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalAccessPolicies": extra_fields.get("totalAccessPolicies", 0),
                "activeAccessPoliciesCount": extra_fields.get("activeAccessPoliciesCount", 0),
                "policiesEnforcingMFA": extra_fields.get("policiesEnforcingMFA", 0)
            }
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
