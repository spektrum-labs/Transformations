"""
Transformation: authTypesAllowed
Vendor: Multifactor Authentication  |  Category: iam
Evaluates: Inspect active Duo MFA policies to determine which authentication factor
           types are permitted (e.g. Duo Push, TOTP, SMS, hardware token, phone call).
           Passes if at least one strong factor is enabled across policies and fails if
           SMS-only or phone-only is the sole permitted method.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for loop_idx in range(3):
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
                "vendor": "Multifactor Authentication",
                "category": "iam"
            }
        }
    }


def extract_methods_from_policy(policy):
    found = []
    sections = policy.get("sections", {})
    if isinstance(sections, dict):
        auth_section = sections.get("authentication_methods", sections.get("auth_methods", {}))
        if isinstance(auth_section, dict):
            enabled_methods = auth_section.get("enabled_methods", auth_section.get("allowed_factors", []))
            if isinstance(enabled_methods, list):
                for method in enabled_methods:
                    if method not in found:
                        found.append(method)
            for mk in auth_section:
                val = auth_section[mk]
                if isinstance(val, bool) and val and mk not in found:
                    found.append(mk)
    direct_methods = policy.get("auth_methods", policy.get("allowed_factors", policy.get("authentication_methods", [])))
    if isinstance(direct_methods, list):
        for method in direct_methods:
            if method not in found:
                found.append(method)
    elif isinstance(direct_methods, dict):
        for mk in direct_methods:
            val = direct_methods[mk]
            if isinstance(val, bool) and val and mk not in found:
                found.append(mk)
    return found


def evaluate(data):
    try:
        policies = []
        if isinstance(data, list):
            policies = data
        elif isinstance(data, dict):
            response_val = data.get("response", [])
            if isinstance(response_val, list):
                policies = response_val
            elif isinstance(data.get("policies", None), list):
                policies = data["policies"]

        strong_factor_keywords = ["push", "duo_push", "totp", "hotp", "hardware_token",
                                   "token", "authenticator", "webauthn", "u2f", "security_key"]
        weak_only_keywords = ["sms", "phone", "voice", "call"]

        all_methods = []
        for policy in policies:
            if not isinstance(policy, dict):
                continue
            methods = extract_methods_from_policy(policy)
            for m in methods:
                if m not in all_methods:
                    all_methods.append(m)

        strong_found = False
        for method in all_methods:
            method_lower = method.lower()
            for kw in strong_factor_keywords:
                if kw in method_lower:
                    strong_found = True
                    break

        weak_only = False
        if not strong_found and len(all_methods) > 0:
            all_weak = True
            for method in all_methods:
                method_lower = method.lower()
                is_weak = False
                for kw in weak_only_keywords:
                    if kw in method_lower:
                        is_weak = True
                        break
                if not is_weak:
                    all_weak = False
                    break
            weak_only = all_weak

        policy_count = len(policies)
        methods_detected = all_methods

        passed = strong_found or (policy_count > 0 and len(all_methods) == 0)

        return {
            "authTypesAllowed": passed,
            "strongFactorsPresent": strong_found,
            "weakFactorsOnly": weak_only,
            "detectedAuthMethods": methods_detected,
            "totalPoliciesEvaluated": policy_count,
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
                fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        detected = eval_result.get("detectedAuthMethods", [])
        policy_count = eval_result.get("totalPoliciesEvaluated", 0)
        if result_value:
            if eval_result.get("strongFactorsPresent", False):
                pass_reasons.append("One or more strong authentication factor types are permitted in active policies")
                pass_reasons.append("Detected auth methods: " + (", ".join(detected) if detected else "none explicitly listed"))
            else:
                pass_reasons.append("Policies found but no explicit auth method restrictions detected; strong factors assumed permitted")
        else:
            if eval_result.get("weakFactorsOnly", False):
                fail_reasons.append("Only weak authentication factors (SMS, phone/voice) are permitted across all policies")
                recommendations.append("Enable strong factor types such as Duo Push, TOTP, or hardware tokens in Duo policies")
            else:
                fail_reasons.append("No strong authentication factor types detected in active policies")
                recommendations.append("Configure authentication methods in Duo policies to include strong factors")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
        if detected:
            additional_findings.append("Auth methods found across policies: " + ", ".join(detected))
        additional_findings.append("Total policies evaluated: " + str(policy_count))
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalPoliciesEvaluated": policy_count,
                "detectedAuthMethods": detected,
                "strongFactorsPresent": eval_result.get("strongFactorsPresent", False)
            })
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
