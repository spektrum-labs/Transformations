"""
Transformation: MFAForAdminAccess
Vendor: Okta  |  Category: cis-controls-v8-ig1
Evaluates: Whether at least one active MFA_ENROLL (authenticator enrollment policy) mandates
           factor enrollment (REQUIRED) for users, particularly admin or privileged groups.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "MFAForAdminAccess", "vendor": "Okta", "category": "cis-controls-v8-ig1"}
        }
    }


def get_policies_by_type(data, policy_type):
    policies = []
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and item.get("type") == policy_type:
                policies.append(item)
    return policies


def policy_has_required_factor(policy):
    settings = policy.get("settings", {})
    authenticators = settings.get("authenticators", [])
    if isinstance(authenticators, list):
        for auth in authenticators:
            if isinstance(auth, dict):
                enroll = auth.get("enroll", {})
                if enroll.get("self", "") == "REQUIRED":
                    return True
    factors = settings.get("factors", {})
    if isinstance(factors, dict):
        for factor_key in factors:
            factor_val = factors[factor_key]
            if isinstance(factor_val, dict):
                enroll = factor_val.get("enroll", {})
                if enroll.get("self", "") == "REQUIRED":
                    return True
    return False


def describe_required_factors(policy):
    found = []
    settings = policy.get("settings", {})
    authenticators = settings.get("authenticators", [])
    if isinstance(authenticators, list):
        for auth in authenticators:
            if isinstance(auth, dict):
                enroll = auth.get("enroll", {})
                if enroll.get("self", "") == "REQUIRED":
                    found.append("authenticator:" + auth.get("key", "unknown"))
    factors = settings.get("factors", {})
    if isinstance(factors, dict):
        for factor_key in factors:
            factor_val = factors[factor_key]
            if isinstance(factor_val, dict):
                enroll = factor_val.get("enroll", {})
                if enroll.get("self", "") == "REQUIRED":
                    found.append("factor:" + factor_key)
    return found


def evaluate(data):
    try:
        mfa_policies = get_policies_by_type(data, "MFA_ENROLL")
        active_policies = [p for p in mfa_policies if p.get("status") == "ACTIVE"]
        total_policies = len(mfa_policies)
        active_count = len(active_policies)

        policies_with_required = []
        policies_without_required = []

        for policy in active_policies:
            name = policy.get("name", "Unnamed")
            if policy_has_required_factor(policy):
                required_factors = describe_required_factors(policy)
                policies_with_required.append(name + " (" + ", ".join(required_factors) + ")")
            else:
                policies_without_required.append(name)

        passes = len(policies_with_required) > 0

        return {
            "MFAForAdminAccess": passes,
            "totalMFAEnrollPolicies": total_policies,
            "activeMFAEnrollPoliciesCount": active_count,
            "policiesWithRequiredFactorCount": len(policies_with_required),
            "policiesWithRequiredFactor": policies_with_required,
            "policiesWithoutRequiredFactor": policies_without_required
        }
    except Exception as e:
        return {"MFAForAdminAccess": False, "error": str(e)}


def transform(input):
    criteriaKey = "MFAForAdminAccess"
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
            pass_reasons.append("At least one active MFA_ENROLL policy mandates factor enrollment (REQUIRED).")
            for desc in extra_fields.get("policiesWithRequiredFactor", []):
                pass_reasons.append("Policy with required factor(s): " + desc)
        else:
            fail_reasons.append("No active MFA_ENROLL policy mandates factor enrollment as REQUIRED. Admin accounts may not be protected by MFA.")
            for name in extra_fields.get("policiesWithoutRequiredFactor", []):
                additional_findings.append("MFA enroll policy with no required factor: " + name)
            recommendations.append("Set at least one authenticator or factor to REQUIRED enrollment status in an active MFA_ENROLL policy in Okta, particularly scoped to admin/privileged groups.")
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
                "totalMFAEnrollPolicies": extra_fields.get("totalMFAEnrollPolicies", 0),
                "activeMFAEnrollPoliciesCount": extra_fields.get("activeMFAEnrollPoliciesCount", 0),
                "policiesWithRequiredFactorCount": extra_fields.get("policiesWithRequiredFactorCount", 0)
            }
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
