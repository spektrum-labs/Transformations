"""
Transformation: isMFAEnforcedForAdminAccess
Vendor: Okta  |  Category: cyber-essentials-plus
Evaluates: Whether at least one ACTIVE ACCESS_POLICY (sign-on policy) rule
           requires MFA (possession factor / 2FA assurance) for administrative
           access to the Okta Admin Console.
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


def resolve_admin_mfa_policies(data):
    """
    The workflow merges all method results into one dict keyed by method name.
    Returns the ACCESS_POLICY list from whichever key is present, or [] if not found.
    """
    # Primary: merged key from getAdminMfaPolicy method
    if isinstance(data, dict) and "getAdminMfaPolicy" in data:
        candidate = data["getAdminMfaPolicy"]
        if isinstance(candidate, list):
            return candidate

    # Fallback: the data itself is the list
    if isinstance(data, list):
        return data

    # Fallback: look for any list value whose items have type == "ACCESS_POLICY"
    if isinstance(data, dict):
        for key in data:
            val = data[key]
            if isinstance(val, list) and len(val) > 0:
                first = val[0]
                if isinstance(first, dict) and first.get("type") == "ACCESS_POLICY":
                    return val

    return []


def rule_requires_mfa(rule):
    """
    Returns True if the given policy rule has a verification method
    that enforces MFA (2FA / possession / assurance).
    Supports both OIE (appSignOn) and classic (actions.signon) policy shapes.
    """
    if not isinstance(rule, dict):
        return False

    rule_status = rule.get("status", "ACTIVE")
    if rule_status != "ACTIVE":
        return False

    actions = rule.get("actions", {})
    if not isinstance(actions, dict):
        return False

    # OIE ACCESS_POLICY: actions.appSignOn.verificationMethod
    app_sign_on = actions.get("appSignOn", {})
    if isinstance(app_sign_on, dict):
        verification = app_sign_on.get("verificationMethod", {})
        if isinstance(verification, dict):
            factor_mode = verification.get("factorMode", "")
            v_type = verification.get("type", "")
            # factorMode 2FA means two factors required
            if factor_mode == "2FA":
                return True
            # type ASSURANCE with any factorMode other than 1FA is MFA
            if v_type == "ASSURANCE" and factor_mode != "1FA":
                return True
            # Check constraints for possession requirement
            constraints = verification.get("constraints", [])
            if isinstance(constraints, list):
                for constraint in constraints:
                    if isinstance(constraint, dict):
                        possession = constraint.get("possession", {})
                        if isinstance(possession, dict) and possession.get("required") is True:
                            return True

    # Classic / Okta Sign-On Policy: actions.signon.requireFactor
    sign_on = actions.get("signon", {})
    if isinstance(sign_on, dict):
        if sign_on.get("requireFactor") is True:
            return True
        if sign_on.get("factorPromptMode") in ("ALWAYS", "SESSION"):
            return True

    return False


def evaluate(data):
    """Core evaluation logic for isMFAEnforcedForAdminAccess."""
    try:
        policies = resolve_admin_mfa_policies(data)

        total_policies = len(policies)
        active_policies = [p for p in policies if isinstance(p, dict) and p.get("status") == "ACTIVE"]
        total_active = len(active_policies)

        if total_active == 0:
            return {
                "isMFAEnforcedForAdminAccess": False,
                "totalAccessPolicies": total_policies,
                "activePolicies": 0,
                "policiesWithMfaRule": 0,
                "detail": "No ACTIVE ACCESS_POLICY found"
            }

        mfa_enforcing_policies = []
        for policy in active_policies:
            policy_name = policy.get("name", "Unnamed")
            rules = policy.get("rules", [])
            if not isinstance(rules, list):
                rules = []
            mfa_rules = [r for r in rules if rule_requires_mfa(r)]
            if len(mfa_rules) > 0:
                mfa_enforcing_policies.append(policy_name)

        is_enforced = len(mfa_enforcing_policies) > 0

        return {
            "isMFAEnforcedForAdminAccess": is_enforced,
            "totalAccessPolicies": total_policies,
            "activePolicies": total_active,
            "policiesWithMfaRule": len(mfa_enforcing_policies),
            "mfaEnforcingPolicyNames": mfa_enforcing_policies
        }

    except Exception as e:
        return {
            "isMFAEnforcedForAdminAccess": False,
            "error": str(e)
        }


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

        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        total_policies = eval_result.get("totalAccessPolicies", 0)
        active_policies = eval_result.get("activePolicies", 0)
        policies_with_mfa = eval_result.get("policiesWithMfaRule", 0)
        mfa_policy_names = eval_result.get("mfaEnforcingPolicyNames", [])
        detail = eval_result.get("detail", "")

        if result_value:
            pass_reasons.append(
                "MFA is enforced for admin access: " +
                str(policies_with_mfa) + " of " + str(active_policies) +
                " active ACCESS_POLICY/policies contain a rule requiring MFA."
            )
            for name in mfa_policy_names:
                pass_reasons.append("MFA-enforcing policy: " + name)
        else:
            if detail:
                fail_reasons.append(detail)
            else:
                fail_reasons.append(
                    "No active ACCESS_POLICY rule requiring MFA was found. " +
                    str(active_policies) + " active polic(ies) examined, " +
                    str(policies_with_mfa) + " enforce MFA."
                )
            recommendations.append(
                "Configure an Okta Authentication Policy (ACCESS_POLICY) for the Admin Console "
                "application with a rule that sets verificationMethod.factorMode to '2FA' or "
                "requires a possession/phishing-resistant factor."
            )
            recommendations.append(
                "Ensure the rule is ACTIVE and that the Admin Console app is assigned to the policy."
            )

        if "error" in eval_result:
            fail_reasons.append("Evaluation error: " + eval_result["error"])

        additional_findings.append("Total ACCESS_POLICY records retrieved: " + str(total_policies))
        additional_findings.append("Active ACCESS_POLICY records: " + str(active_policies))

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "totalAccessPolicies": total_policies,
                "activePolicies": active_policies,
                "policiesWithMfaRule": policies_with_mfa
            },
            additional_findings=additional_findings
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
