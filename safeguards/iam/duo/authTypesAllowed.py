"""
Transformation: authTypesAllowed
Vendor: Duo  |  Category: iam
Evaluates: Retrieve and validate which authentication methods (Duo Push, TOTP, hardware token,
SMS, phone call) are permitted or restricted across Duo account settings and policy definitions.
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
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "authTypesAllowed", "vendor": "Duo", "category": "iam"}
        }
    }


def is_method_enabled(factors, method_key):
    val = factors.get(method_key, False)
    if isinstance(val, bool):
        return val
    if isinstance(val, int):
        return val != 0
    if isinstance(val, str):
        return val.lower() in ["true", "1", "yes", "enabled"]
    return False


def extract_policies(data):
    if not isinstance(data, dict):
        return []
    if "policies" in data:
        candidate = data.get("policies", [])
        if isinstance(candidate, list):
            return candidate
    if "data" in data:
        inner = data.get("data", [])
        if isinstance(inner, list):
            return inner
    return []


def evaluate(data):
    try:
        settings = {}
        if isinstance(data, dict):
            candidate = data.get("data", {})
            if isinstance(candidate, dict):
                settings = candidate

        policies = extract_policies(data)

        strong_method_keys = ["allow_push", "allow_totp", "allow_hardware_token", "allow_u2f", "allow_webauthn"]
        weak_method_keys = ["allow_sms", "allow_voice", "allow_phone"]

        allowed_strong = []
        allowed_weak = []
        policy_config_found = False
        total_policies = len(policies)

        section_names = ["factors", "auth_methods", "authentication_methods"]

        for policy in policies:
            if not isinstance(policy, dict):
                continue
            sections = policy.get("sections", {})
            if not isinstance(sections, dict):
                continue
            factors = {}
            for sec_name in section_names:
                if sec_name in sections:
                    candidate = sections.get(sec_name, {})
                    if isinstance(candidate, dict):
                        factors = candidate
                        break
            if not factors:
                continue
            policy_config_found = True
            for method_key in strong_method_keys:
                if is_method_enabled(factors, method_key):
                    if method_key not in allowed_strong:
                        allowed_strong.append(method_key)
            for method_key in weak_method_keys:
                if is_method_enabled(factors, method_key):
                    if method_key not in allowed_weak:
                        allowed_weak.append(method_key)

        has_strong_factor = len(allowed_strong) > 0
        only_weak = len(allowed_strong) == 0 and len(allowed_weak) > 0

        if policy_config_found:
            auth_types_ok = has_strong_factor
        else:
            auth_types_ok = True

        return {
            "authTypesAllowed": auth_types_ok,
            "strongMethodsAllowed": allowed_strong,
            "weakMethodsAllowed": allowed_weak,
            "onlyWeakMethodsConfigured": only_weak,
            "policyConfigFound": policy_config_found,
            "totalPoliciesEvaluated": total_policies
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
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        strong = eval_result.get("strongMethodsAllowed", [])
        weak = eval_result.get("weakMethodsAllowed", [])
        policy_found = eval_result.get("policyConfigFound", False)
        total = eval_result.get("totalPoliciesEvaluated", 0)

        if result_value:
            if policy_found:
                pass_reasons.append("At least one strong authentication method is permitted in Duo policy configuration")
                pass_reasons.append("Strong methods configured: " + ", ".join(strong))
            else:
                pass_reasons.append("No explicit policy auth method restrictions found — Duo defaults apply (all methods including Duo Push are permitted)")
        else:
            fail_reasons.append("No strong authentication methods (Push, TOTP, hardware token) are permitted in any Duo policy")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable at least one strong authentication factor (Duo Push or TOTP) in Duo policy sections")
            recommendations.append("Review Duo policy 'factors' or 'authentication_methods' sections to permit secure auth methods")

        if len(weak) > 0:
            additional_findings.append("Weak authentication methods permitted: " + ", ".join(weak) + " — consider restricting SMS and voice call factors")
        if policy_found:
            additional_findings.append("Strong methods allowed: " + (", ".join(strong) if strong else "none"))
            additional_findings.append("Weak methods allowed: " + (", ".join(weak) if weak else "none"))
        additional_findings.append("Total Duo policies evaluated: " + str(total))

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={criteriaKey: result_value, **extra_fields}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
