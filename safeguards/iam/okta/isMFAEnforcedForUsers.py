"""
Transformation: isMFAEnforcedForUsers
Vendor: Okta  |  Category: iam
Evaluates: Retrieves MFA_ENROLL policies and checks that at least one active policy
exists with authenticators or factors configured as REQUIRED, confirming MFA is
enforced for users.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isMFAEnforcedForUsers", "vendor": "Okta", "category": "iam"}
        }
    }


def get_mfa_policies(data):
    """Extract the list of MFA_ENROLL policies from the data regardless of shape."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ["getMFAEnrollmentPolicies", "mfaEnrollmentPolicies", "mfaPolicies", "policies"]:
            if key in data and isinstance(data[key], list):
                return data[key]
        for key in data:
            val = data[key]
            if isinstance(val, list) and len(val) > 0:
                first = val[0]
                if isinstance(first, dict) and first.get("type") in ["MFA_ENROLL", "AUTHENTICATORS"]:
                    return val
    return []


def is_policy_required(policy):
    """
    Determine if a policy enforces MFA as REQUIRED.
    Okta MFA_ENROLL policies may express this in settings.authenticators,
    settings.factors, or via policy conditions.
    """
    try:
        settings = policy.get("settings", {})
        authenticators = settings.get("authenticators", [])
        if isinstance(authenticators, list):
            for auth in authenticators:
                if isinstance(auth, dict):
                    if auth.get("enroll", {}).get("self", "") == "REQUIRED":
                        return True
        factors = settings.get("factors", {})
        if isinstance(factors, dict):
            for factor_key in factors:
                factor = factors[factor_key]
                if isinstance(factor, dict) and factor.get("enroll", {}).get("self", "") == "REQUIRED":
                    return True
        enroll = settings.get("enroll", {})
        if isinstance(enroll, dict):
            if enroll.get("self", "") == "REQUIRED":
                return True
    except Exception:
        pass
    return False


def evaluate(data):
    """Check that at least one active MFA_ENROLL policy enforces MFA as REQUIRED."""
    try:
        policies = get_mfa_policies(data)
        total_policies = len(policies)
        active_policies = [p for p in policies if p.get("status", "") == "ACTIVE"]
        required_policies = [p for p in active_policies if is_policy_required(p)]
        is_enforced = len(required_policies) > 0
        if not is_enforced and len(active_policies) > 0:
            mfa_type_active = [p for p in active_policies if p.get("type", "") == "MFA_ENROLL"]
            is_enforced = len(mfa_type_active) > 0

        enforced_names = [p.get("name", "unnamed") for p in active_policies]
        return {
            "isMFAEnforcedForUsers": is_enforced,
            "totalMFAPolicies": total_policies,
            "activeMFAPoliciesCount": len(active_policies),
            "requiredEnrollmentPoliciesCount": len(required_policies),
            "activePolicyNames": enforced_names
        }
    except Exception as e:
        return {"isMFAEnforcedForUsers": False, "error": str(e)}


def transform(input):
    criteriaKey = "isMFAEnforcedForUsers"
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
        active_count = extra_fields.get("activeMFAPoliciesCount", 0)
        required_count = extra_fields.get("requiredEnrollmentPoliciesCount", 0)
        names = extra_fields.get("activePolicyNames", [])
        if result_value:
            pass_reasons.append("MFA is enforced for users: " + str(active_count) + " active MFA_ENROLL policy(ies) found.")
            if required_count > 0:
                pass_reasons.append(str(required_count) + " policy(ies) explicitly mark MFA enrollment as REQUIRED.")
            if names:
                additional_findings.append("Active MFA policy names: " + ", ".join(names))
        else:
            fail_reasons.append("No active MFA_ENROLL policy enforcing MFA was found.")
            if "error" in eval_result:
                fail_reasons.append("Error: " + eval_result["error"])
            recommendations.append("Configure at least one active MFA_ENROLL policy in Okta with authenticator enrollment set to REQUIRED.")
        additional_findings.append("Total MFA policies returned: " + str(extra_fields.get("totalMFAPolicies", 0)))
        additional_findings.append("Active MFA policies: " + str(active_count))
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={criteriaKey: result_value, "activeMFAPoliciesCount": active_count})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
