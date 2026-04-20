"""
Transformation: isMFAEnforcedForAdminAccess
Vendor: Okta  |  Category: cyber-essentials-plus
Evaluates: Retrieves OKTA_SIGN_ON policies with expanded rules from
GET /api/v1/policies?type=OKTA_SIGN_ON&expand=rules and returns true if at
least one active sign-on policy rule requires MFA (requireFactor == true)
for admin access -- prioritising policies whose name contains 'admin' or
is 'Admin App Policy', falling back to all active sign-on policy rules.
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
                "transformationId": "isMFAEnforcedForAdminAccess",
                "vendor": "Okta",
                "category": "cyber-essentials-plus"
            }
        }
    }


def get_rules_from_policy(policy):
    """Return the list of rules embedded in a policy object."""
    embedded = policy.get("_embedded", {})
    if not isinstance(embedded, dict):
        return []
    rules = embedded.get("rules", [])
    if not isinstance(rules, list):
        return []
    return rules


def rule_requires_factor(rule):
    """Return True when an ACTIVE rule has actions.signon.requireFactor == True."""
    if not isinstance(rule, dict):
        return False
    if rule.get("status", "") != "ACTIVE":
        return False
    actions = rule.get("actions", {})
    if not isinstance(actions, dict):
        return False
    signon = actions.get("signon", {})
    if not isinstance(signon, dict):
        return False
    return signon.get("requireFactor", False) is True


def evaluate(data):
    """Core evaluation logic for isMFAEnforcedForAdminAccess."""
    try:
        policies = data
        if isinstance(data, dict):
            policies = data.get("data", [])
        if not isinstance(policies, list):
            policies = []

        total_policies = len(policies)
        admin_policy_names = []
        all_mfa_rules = []
        admin_mfa_rules = []
        non_admin_mfa_rules = []

        for policy in policies:
            if not isinstance(policy, dict):
                continue

            policy_status = policy.get("status", "")
            if policy_status != "ACTIVE":
                continue

            policy_name = policy.get("name", "")
            policy_name_lower = policy_name.lower()
            is_admin_policy = (
                "admin" in policy_name_lower or
                policy_name == "Admin App Policy"
            )

            if is_admin_policy:
                admin_policy_names.append(policy_name)

            rules = get_rules_from_policy(policy)
            for rule in rules:
                if rule_requires_factor(rule):
                    rule_name = rule.get("name", "unnamed rule")
                    label = policy_name + " / " + rule_name
                    all_mfa_rules.append(label)
                    if is_admin_policy:
                        admin_mfa_rules.append(label)
                    else:
                        non_admin_mfa_rules.append(label)

        # Primary: at least one MFA-enforcing rule across all active OKTA_SIGN_ON policies.
        # Prefer admin-targeted policies but treat any requireFactor rule as sufficient
        # because Okta sign-on policies apply globally to the org (including admin sessions).
        is_enforced = len(all_mfa_rules) > 0
        admin_specific = len(admin_mfa_rules) > 0

        return {
            "isMFAEnforcedForAdminAccess": is_enforced,
            "adminSpecificPolicyFound": admin_specific,
            "totalPoliciesEvaluated": total_policies,
            "adminPoliciesFound": admin_policy_names,
            "enforcingRules": all_mfa_rules,
            "adminEnforcingRules": admin_mfa_rules
        }
    except Exception as e:
        return {"isMFAEnforcedForAdminAccess": False, "error": str(e)}


def transform(input):
    criteriaKey = "isMFAEnforcedForAdminAccess"
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

        extra_fields = {}
        for k in eval_result:
            if k != criteriaKey and k != "error":
                extra_fields[k] = eval_result[k]

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if result_value:
            pass_reasons.append("At least one active OKTA_SIGN_ON policy rule has requireFactor set to true, enforcing MFA for sign-on.")
            if eval_result.get("adminSpecificPolicyFound", False):
                pass_reasons.append("An admin-specific sign-on policy was found with MFA enforcement.")
                for rule_label in eval_result.get("adminEnforcingRules", []):
                    pass_reasons.append("Admin MFA rule: " + rule_label)
            else:
                additional_findings.append("No admin-named policy found; MFA enforcement detected on general sign-on policy. Verify policy scope covers admin sessions.")
            for rule_label in eval_result.get("enforcingRules", []):
                additional_findings.append("MFA-enforcing rule: " + rule_label)
        else:
            fail_reasons.append("No active OKTA_SIGN_ON policy rule was found with requireFactor set to true.")
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])
            recommendations.append("Create or update an Okta Sign-On Policy to include a rule that sets requireFactor to true for admin access.")
            recommendations.append("Consider creating a dedicated 'Admin App Policy' targeting the Okta Admin Console with MFA required.")
            if eval_result.get("totalPoliciesEvaluated", 0) == 0:
                fail_reasons.append("No OKTA_SIGN_ON policies were returned by the API. Verify API permissions and that policies exist.")

        combined_result = {criteriaKey: result_value}
        for k in extra_fields:
            combined_result[k] = extra_fields[k]

        input_summary = {
            "totalPoliciesEvaluated": eval_result.get("totalPoliciesEvaluated", 0),
            "adminPoliciesFound": eval_result.get("adminPoliciesFound", []),
            "mfaEnforcingRulesCount": len(eval_result.get("enforcingRules", []))
        }

        return create_response(
            result=combined_result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=input_summary,
            additional_findings=additional_findings
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
