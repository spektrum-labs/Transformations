"""
Transformation: authTypesAllowed
Vendor: Duo  |  Category: iam
Evaluates: Inspects GET /admin/v1/policies to determine which authentication factor types
are permitted. Checks whether only strong phishing-resistant factors are allowed (Duo Push,
TOTP hardware tokens, WebAuthn/security keys) and flags permissive factors (phone call, SMS).
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for i in range(3):
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
                "transformationId": "authTypesAllowed",
                "vendor": "Duo",
                "category": "iam"
            }
        }
    }


STRONG_FACTORS = ["push", "totp", "webauthn", "hardware_token", "duo_push", "passcode", "u2f", "security_key"]
WEAK_FACTORS = ["phone", "sms", "call", "bypass", "phone_call"]


def is_weak_factor(factor):
    factor_lower = factor.lower()
    for wf in WEAK_FACTORS:
        if wf in factor_lower:
            return True
    return False


def is_strong_factor(factor):
    factor_lower = factor.lower()
    for sf in STRONG_FACTORS:
        if sf in factor_lower:
            return True
    return False


def collect_factors_from_policy(policy):
    found = []
    sections = policy.get("sections", {})
    if not isinstance(sections, dict):
        sections = {}

    for section_key in sections:
        section = sections[section_key]
        if not isinstance(section, dict):
            continue
        for factor_key in ["factors", "allowed_factors", "auth_types", "authTypes", "methods"]:
            if factor_key in section:
                val = section[factor_key]
                if isinstance(val, list):
                    for item in val:
                        if isinstance(item, str):
                            found.append(item)
                elif isinstance(val, str):
                    found.append(val)
        for k in section:
            if isinstance(section[k], bool) and section[k]:
                found.append(k)

    top_factors = policy.get("factors", [])
    if isinstance(top_factors, list):
        for item in top_factors:
            if isinstance(item, str):
                found.append(item)

    return found


def evaluate(data):
    try:
        policies = data.get("policies", [])
        if not isinstance(policies, list):
            policies = []

        total_policies = len(policies)
        all_factors_found = []
        weak_factors_found = []
        strong_factors_found = []
        policies_with_weak = []

        for policy in policies:
            if not isinstance(policy, dict):
                continue
            policy_name = policy.get("policy_name", policy.get("name", "unnamed"))
            factors = collect_factors_from_policy(policy)
            for f in factors:
                if f not in all_factors_found:
                    all_factors_found.append(f)
                if is_weak_factor(f):
                    if f not in weak_factors_found:
                        weak_factors_found.append(f)
                    if policy_name not in policies_with_weak:
                        policies_with_weak.append(policy_name)
                if is_strong_factor(f):
                    if f not in strong_factors_found:
                        strong_factors_found.append(f)

        has_strong = len(strong_factors_found) > 0
        has_weak = len(weak_factors_found) > 0

        if len(all_factors_found) == 0:
            only_strong_allowed = total_policies > 0
        else:
            only_strong_allowed = has_strong and not has_weak

        return {
            "authTypesAllowed": only_strong_allowed,
            "onlyStrongFactorsAllowed": only_strong_allowed,
            "totalPolicies": total_policies,
            "permittedFactors": all_factors_found,
            "strongFactors": strong_factors_found,
            "weakFactors": weak_factors_found,
            "policiesWithWeakFactors": policies_with_weak
        }
    except Exception as e:
        return {"authTypesAllowed": False, "error": str(e)}


def transform(input):
    criteriaKey = "authTypesAllowed"
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
        total_policies = eval_result.get("totalPolicies", 0)
        permitted_factors = eval_result.get("permittedFactors", [])
        strong_factors = eval_result.get("strongFactors", [])
        weak_factors = eval_result.get("weakFactors", [])
        policies_with_weak = eval_result.get("policiesWithWeakFactors", [])
        only_strong = eval_result.get("onlyStrongFactorsAllowed", False)

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if result_value:
            pass_reasons.append("Authentication factor policy allows only strong phishing-resistant factors")
            if strong_factors:
                pass_reasons.append("Strong factors detected: " + ", ".join(strong_factors))
            else:
                pass_reasons.append("No weak factors detected across " + str(total_policies) + " policies")
        else:
            if weak_factors:
                fail_reasons.append("Weak authentication factors are permitted: " + ", ".join(weak_factors))
                if policies_with_weak:
                    fail_reasons.append("Policies permitting weak factors: " + ", ".join(policies_with_weak))
                recommendations.append("Remove phone call and SMS from allowed authentication methods")
                recommendations.append("Restrict policies to Duo Push, TOTP passcodes, hardware tokens, or WebAuthn/security keys only")
            else:
                fail_reasons.append("authTypesAllowed check failed: could not confirm strong-only factor configuration")
                recommendations.append("Review Duo policy sections to ensure only strong authentication methods are permitted")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])

        if permitted_factors:
            additional_findings.append("All permitted factors observed: " + ", ".join(permitted_factors))

        result = {
            "authTypesAllowed": result_value,
            "onlyStrongFactorsAllowed": only_strong,
            "totalPolicies": total_policies,
            "permittedFactors": permitted_factors,
            "strongFactors": strong_factors,
            "weakFactors": weak_factors,
            "policiesWithWeakFactors": policies_with_weak
        }

        return create_response(
            result=result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalPolicies": total_policies,
                "permittedFactors": permitted_factors
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
