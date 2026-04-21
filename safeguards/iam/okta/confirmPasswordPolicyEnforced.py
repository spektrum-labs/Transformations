"""
Transformation: confirmPasswordPolicyEnforced
Vendor: Okta  |  Category: iam
Evaluates: Retrieves PASSWORD type policies and verifies that at least one active policy
with complexity and age constraints exists, confirming a password policy is enforced.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for loop_iter in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmPasswordPolicyEnforced", "vendor": "Okta", "category": "iam"}
        }
    }


def get_policies_list(data):
    """Extract the list of password policies from the data regardless of shape."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ["getPasswordPolicies", "passwordPolicies", "policies"]:
            if key in data and isinstance(data[key], list):
                return data[key]
        for key in data:
            val = data[key]
            if isinstance(val, list) and len(val) > 0:
                first = val[0]
                if isinstance(first, dict) and first.get("type") == "PASSWORD":
                    return val
    return []


def has_complexity(policy):
    """Return True if policy has at least basic complexity settings configured."""
    try:
        settings = policy.get("settings", {})
        pwd_settings = settings.get("password", {})
        complexity = pwd_settings.get("complexity", {})
        min_length = complexity.get("minLength", 0)
        return min_length > 0
    except Exception:
        return False


def has_age_constraint(policy):
    """Return True if policy has age / history constraints configured."""
    try:
        settings = policy.get("settings", {})
        pwd_settings = settings.get("password", {})
        age = pwd_settings.get("age", {})
        history_count = age.get("historyCount", 0)
        max_age_days = age.get("maxAgeDays", 0)
        return history_count > 0 or max_age_days > 0
    except Exception:
        return False


def evaluate(data):
    """Check that at least one active PASSWORD policy with complexity + age constraints exists."""
    try:
        policies = get_policies_list(data)
        total_policies = len(policies)
        active_policies = [p for p in policies if p.get("status", "") == "ACTIVE"]
        enforced_policies = [p for p in active_policies if has_complexity(p)]
        constrained_policies = [p for p in enforced_policies if has_age_constraint(p)]

        policy_names = [p.get("name", "unnamed") for p in enforced_policies]
        is_enforced = len(enforced_policies) > 0

        return {
            "confirmPasswordPolicyEnforced": is_enforced,
            "totalPolicies": total_policies,
            "activePoliciesCount": len(active_policies),
            "enforcedPoliciesCount": len(enforced_policies),
            "constrainedPoliciesCount": len(constrained_policies),
            "activePolicyNames": policy_names
        }
    except Exception as e:
        return {"confirmPasswordPolicyEnforced": False, "error": str(e)}


def transform(input):
    criteriaKey = "confirmPasswordPolicyEnforced"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation,
                                   fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        if result_value:
            pass_reasons.append("At least one active PASSWORD policy with complexity constraints is enforced.")
            names = extra_fields.get("activePolicyNames", [])
            if names:
                pass_reasons.append("Enforced policy names: " + ", ".join(names))
            if extra_fields.get("constrainedPoliciesCount", 0) > 0:
                pass_reasons.append("Password age/history constraints are also configured.")
        else:
            fail_reasons.append("No active PASSWORD policy with complexity constraints was found.")
            if "error" in eval_result:
                fail_reasons.append("Error: " + eval_result["error"])
            recommendations.append("Create or activate a PASSWORD policy in Okta with complexity (minLength > 0) and age/history constraints.")
        additional_findings.append("Total password policies found: " + str(extra_fields.get("totalPolicies", 0)))
        additional_findings.append("Active policies: " + str(extra_fields.get("activePoliciesCount", 0)))
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={criteriaKey: result_value, **extra_fields})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
