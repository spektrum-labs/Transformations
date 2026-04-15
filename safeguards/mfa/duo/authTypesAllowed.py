"""
Transformation: authTypesAllowed
Vendor: Duo  |  Category: MFA
Evaluates: Determines which authentication factor types are permitted by inspecting
the Duo global policy factors array (push, phone, passcode, hardware-token,
WebAuthn security keys, etc.). Returns a list of allowed methods and passes when
at least one strong/phishing-resistant factor is present.
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
                "transformationId": "authTypesAllowed",
                "vendor": "Duo",
                "category": "MFA"
            }
        }
    }


def _extract_factors_from_policy(policy_obj):
    """
    Attempt to extract a factors list from a single policy dict.
    Duo policies nest factors under sections.factors.factors or factors directly.
    Returns a list of factor strings (possibly empty).
    """
    if not isinstance(policy_obj, dict):
        return []

    # Path 1: sections -> factors -> factors
    sections = policy_obj.get("sections", {})
    if isinstance(sections, dict):
        factors_section = sections.get("factors", {})
        if isinstance(factors_section, dict):
            factors = factors_section.get("factors", [])
            if isinstance(factors, list) and len(factors) > 0:
                return factors

    # Path 2: top-level factors key
    factors = policy_obj.get("factors", [])
    if isinstance(factors, list) and len(factors) > 0:
        return factors

    return []


def evaluate(data):
    """
    Extract allowed auth factor types from the Duo global policy response.
    data may be:
      - a dict representing the global policy object
      - a list of policy objects (first entry treated as global)
    Passes when at least one strong factor is present (push, hardware-token,
    security-key / WebAuthn).
    """
    try:
        strong_factors = ["push", "hardware-token", "security-key", "webauthn", "duo-push"]

        factors = []
        policy_name = ""

        if isinstance(data, list):
            # Iterate to find the global/default policy first
            for policy in data:
                name = ""
                if isinstance(policy, dict):
                    name = policy.get("policy_name", policy.get("name", ""))
                name_lower = name.lower()
                if "global" in name_lower or "default" in name_lower or policy_name == "":
                    candidate = _extract_factors_from_policy(policy)
                    if len(candidate) > 0 or policy_name == "":
                        factors = candidate
                        policy_name = name
            # If we found nothing in the preferred pass, take the first non-empty
            if len(factors) == 0 and len(data) > 0:
                for policy in data:
                    candidate = _extract_factors_from_policy(policy)
                    if len(candidate) > 0:
                        factors = candidate
                        if isinstance(policy, dict):
                            policy_name = policy.get("policy_name", policy.get("name", ""))
                        break
        elif isinstance(data, dict):
            policy_name = data.get("policy_name", data.get("name", ""))
            factors = _extract_factors_from_policy(data)

        factors_lower = [str(f).lower() for f in factors]

        has_strong_factor = False
        for sf in strong_factors:
            for fl in factors_lower:
                if sf in fl:
                    has_strong_factor = True
                    break

        has_any_factor = len(factors) > 0

        return {
            "authTypesAllowed": has_any_factor,
            "allowedFactors": factors,
            "totalFactorsConfigured": len(factors),
            "hasStrongAuthFactor": has_strong_factor,
            "policyName": policy_name
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
                result={criteriaKey: False, "allowedFactors": [], "totalFactorsConfigured": 0},
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

        if "error" in eval_result:
            fail_reasons.append("Evaluation error: " + eval_result["error"])
            recommendations.append("Ensure getGlobalPolicies returns a valid Duo policy object with a factors section")
        else:
            factors = eval_result.get("allowedFactors", [])
            total = eval_result.get("totalFactorsConfigured", 0)
            strong = eval_result.get("hasStrongAuthFactor", False)
            policy_name = eval_result.get("policyName", "")

            if result_value:
                pass_reasons.append(
                    str(total) + " authentication factor(s) are configured in Duo global policy"
                )
                if policy_name:
                    pass_reasons.append("Policy inspected: " + policy_name)
                factors_str = ", ".join([str(f) for f in factors])
                pass_reasons.append("Allowed factors: " + factors_str)
            else:
                fail_reasons.append("No authentication factors found in the Duo global policy")
                recommendations.append(
                    "Configure at least one authentication factor in the Duo global policy under "
                    "Policies > Global Policy > Authentication Methods"
                )

            if strong:
                pass_reasons.append(
                    "At least one strong/phishing-resistant factor is enabled (e.g. push, hardware-token, WebAuthn)"
                )
            else:
                if result_value:
                    additional_findings.append(
                        "No strong phishing-resistant factor detected. "
                        "Consider enabling Duo Push, hardware tokens, or WebAuthn security keys."
                    )
                    recommendations.append(
                        "Enable a strong factor such as Duo Push or WebAuthn to reduce phishing risk"
                    )

        full_result = {criteriaKey: result_value}
        for k in extra_fields:
            full_result[k] = extra_fields[k]

        return create_response(
            result=full_result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalFactorsConfigured": eval_result.get("totalFactorsConfigured", 0),
                "hasStrongAuthFactor": eval_result.get("hasStrongAuthFactor", False),
                "policyName": eval_result.get("policyName", "")
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False, "allowedFactors": [], "totalFactorsConfigured": 0},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
