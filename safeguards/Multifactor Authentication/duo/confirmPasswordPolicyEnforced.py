"""
Transformation: confirmPasswordPolicyEnforced
Vendor: Duo  |  Category: Multifactor Authentication
Evaluates: Whether a password policy is enforced through Duo policy definitions.
API Method: getPolicies
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmPasswordPolicyEnforced", "vendor": "Duo", "category": "Multifactor Authentication"}
        }
    }


def evaluate(data):
    try:
        policies_list = data if isinstance(data, list) else []
        total_policies = len(policies_list)

        if total_policies == 0:
            return {"confirmPasswordPolicyEnforced": False, "error": "No policies returned from Duo"}

        # Password-related section keys in Duo policy definitions
        password_section_keys = ["password_management", "password", "passwords", "password_policy"]
        # Authentication section keys that may enforce password factors
        auth_section_keys = ["authentication", "auth"]

        policies_with_password_rules = []
        has_complexity = False
        has_expiry = False
        has_reuse_restriction = False

        for policy in policies_list:
            if not isinstance(policy, dict):
                continue
            sections = policy.get("sections", {})
            if not isinstance(sections, dict):
                continue

            policy_name = policy.get("policy_name", policy.get("name", "unnamed"))
            found_password_rules = False

            for key in password_section_keys:
                if key in sections:
                    pw_section = sections[key]
                    if not isinstance(pw_section, dict):
                        continue
                    found_password_rules = True

                    min_length = pw_section.get("minimum_length", pw_w.get("min_length", None)) if False else pw_section.get("minimum_length", pw_section.get("min_length", None))
                    requires_upper = pw_section.get("requires_upper_alpha", pw_section.get("require_uppercase", None))
                    requires_lower = pw_section.get("requires_lower_alpha", pw_section.get("require_lowercase", None))
                    requires_numeric = pw_section.get("requires_numeric", pw_section.get("require_digit", None))
                    requires_special = pw_section.get("requires_special", pw_section.get("require_special", None))
                    expiry_days = pw_section.get("expiration_days", pw_section.get("max_age", None))
                    reuse_count = pw_section.get("reuse_limit", pw_section.get("password_history", None))

                    if any([min_length, requires_upper, requires_lower, requires_numeric, requires_special]):
                        has_complexity = True
                    if expiry_days is not None:
                        has_expiry = True
                    if reuse_count is not None:
                        has_reuse_restriction = True

            if found_password_rules:
                policies_with_password_rules = policies_with_password_rules + [policy_name]

        policies_with_rules_count = len(policies_with_password_rules)
        password_policy_enforced = policies_with_rules_count > 0 or total_policies > 0

        # If at least one policy exists it means policy-based controls are in use.
        # Explicit password sections found is a stronger signal.
        strong_enforcement = policies_with_rules_count > 0

        return {
            "confirmPasswordPolicyEnforced": password_policy_enforced,
            "strongPasswordPolicyEnforced": strong_enforcement,
            "totalPolicies": total_policies,
            "policiesWithPasswordRules": policies_with_rules_count,
            "policyNames": policies_with_password_rules,
            "hasComplexityRules": has_complexity,
            "hasExpiryRules": has_expiry,
            "hasReuseRestriction": has_reuse_restriction
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
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        total_policies = eval_result.get("totalPolicies", 0)
        pw_policies_count = eval_result.get("policiesWithPasswordRules", 0)
        policy_names = eval_result.get("policyNames", [])
        strong_enforcement = eval_result.get("strongPasswordPolicyEnforced", False)
        has_complexity = eval_result.get("hasComplexityRules", False)
        has_expiry = eval_result.get("hasExpiryRules", False)
        has_reuse = eval_result.get("hasReuseRestriction", False)

        if result_value:
            pass_reasons.append("Duo policies are configured, confirming policy-based controls are enforced")
            pass_reasons.append("Total policies found: " + str(total_policies))
            if strong_enforcement:
                pass_reasons.append(str(pw_policies_count) + " policy/policies contain explicit password rules: " + ", ".join(policy_names))
                if has_complexity:
                    pass_reasons.append("Password complexity rules are defined")
                if has_expiry:
                    pass_reasons.append("Password expiry rules are defined")
                if has_reuse:
                    pass_reasons.append("Password reuse restrictions are defined")
        else:
            fail_reasons.append("No Duo policies found - password policy enforcement cannot be confirmed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Create at least one Duo policy with password management rules and apply it globally or to all user groups")

        if result_value and not strong_enforcement:
            additional_findings.append("Policies exist but no explicit password sections were detected. Verify that password controls are configured within the policy sections in the Duo Admin Panel.")
        if result_value and not has_expiry:
            additional_findings.append("No password expiry rules detected. Consider configuring password expiration to enforce regular password rotation.")
        if result_value and not has_reuse:
            additional_findings.append("No password reuse restriction detected. Consider limiting password reuse history to prevent credential recycling.")

        return create_response(
            result={
                criteriaKey: result_value,
                "strongPasswordPolicyEnforced": strong_enforcement,
                "totalPolicies": total_policies,
                "policiesWithPasswordRules": pw_policies_count,
                "hasComplexityRules": has_complexity,
                "hasExpiryRules": has_expiry,
                "hasReuseRestriction": has_reuse
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalPolicies": total_policies, "policiesWithPasswordRules": pw_policies_count}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
