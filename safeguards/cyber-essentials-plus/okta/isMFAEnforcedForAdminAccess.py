"""\nTransformation: isMFAEnforcedForAdminAccess\nVendor: Okta  |  Category: cyber-essentials-plus\nEvaluates: Whether MFA is enforced for administrator access to the Okta Admin Console.\nInspects global session policies (type=OKTA_SIGN_ON) and checks whether any active\nSIGN_ON policy rule with requireFactor=true applies to admin users.\n"""
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


def resolve_policies(data):
    """
    Resolve the OKTA_SIGN_ON policy list from the merged data structure.
    Handles: raw list, dict with 'getAdminMfaPolicy' key, dict with 'data' key,
    or a dict containing a list under any value.
    """
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        # Named method key (common in merged payloads)
        if "getAdminMfaPolicy" in data:
            candidate = data["getAdminMfaPolicy"]
            if isinstance(candidate, list):
                return candidate
        # Fallback to 'isStrongAuthRequired' since both hit the same endpoint
        if "isStrongAuthRequired" in data:
            candidate = data["isStrongAuthRequired"]
            if isinstance(candidate, list):
                return candidate
        # Generic 'data' wrapper
        if "data" in data and isinstance(data["data"], list):
            return data["data"]
        # Last resort: find the first list value
        for key in data:
            val = data[key]
            if isinstance(val, list) and len(val) > 0 and isinstance(val[0], dict):
                return val
    return []


def is_admin_policy(policy):
    """
    Return True if the policy is specifically an admin-console or admin-targeted policy.
    Okta OIE surfaces an 'Okta Admin Console' sign-on policy by name.
    """
    name = ""
    if isinstance(policy, dict):
        name = policy.get("name", "") or ""
    name_lower = name.lower()
    return "admin" in name_lower or "okta dashboard" in name_lower


def rule_requires_mfa(rule):
    """
    Return True if a SIGN_ON rule has requireFactor set to true in its signon action.
    Also accepts the OIE-style 'multiFactor' key.
    """
    if not isinstance(rule, dict):
        return False
    status = rule.get("status", "ACTIVE")
    if status != "ACTIVE":
        return False
    actions = rule.get("actions", {})
    if not isinstance(actions, dict):
        return False
    signon = actions.get("signon", {})
    if not isinstance(signon, dict):
        return False
    # Classic Engine key
    if signon.get("requireFactor") is True:
        return True
    # OIE key
    multi_factor = signon.get("multiFactor", {})
    if isinstance(multi_factor, dict) and multi_factor.get("required") is True:
        return True
    return False


def rule_applies_to_everyone(rule):
    """
    Return True if the rule applies to the built-in Everyone group or has no group restriction.
    """
    if not isinstance(rule, dict):
        return False
    conditions = rule.get("conditions", {})
    if not isinstance(conditions, dict):
        return True  # No conditions means it applies to all
    people = conditions.get("people", {})
    if not isinstance(people, dict):
        return True
    groups = people.get("groups", {})
    if not isinstance(groups, dict):
        return True
    include = groups.get("include", [])
    if not isinstance(include, list) or len(include) == 0:
        return True
    # Okta's built-in Everyone group ID starts with "00g" and is often named/referenced broadly
    # We treat any include list as potentially covering everyone when the policy is admin-scoped
    return True


def evaluate(data):
    """
    Core evaluation logic for isMFAEnforcedForAdminAccess.

    Strategy:
    1. Extract the OKTA_SIGN_ON policy list.
    2. Search for a policy named 'Okta Admin Console' (OIE) or any policy with 'admin'
       in its name; inspect its rules for requireFactor=true.
    3. If no dedicated admin policy exists, fall back to checking whether ANY active
       OKTA_SIGN_ON policy has a rule requiring MFA that applies broadly (Everyone),
       since admins are also governed by the global session policy.
    4. Track which policies and rules matched for findings.
    """
    criteriaKey = "isMFAEnforcedForAdminAccess"

    policies = resolve_policies(data)
    total_policies = len(policies)

    if total_policies == 0:
        return {
            criteriaKey: False,
            "totalPoliciesInspected": 0,
            "adminPoliciesFound": 0,
            "mfaEnforcingRulesFound": 0,
            "matchedPolicyNames": [],
            "error": "No OKTA_SIGN_ON policies found in API response"
        }

    admin_policies_found = 0
    mfa_enforcing_rules = 0
    matched_policy_names = []
    admin_mfa_enforced = False
    global_mfa_enforced = False

    # Pass 1: look for dedicated admin policies
    for policy in policies:
        if not isinstance(policy, dict):
            continue
        policy_status = policy.get("status", "")
        if policy_status != "ACTIVE":
            continue
        if is_admin_policy(policy):
            admin_policies_found = admin_policies_found + 1
            rules = policy.get("rules", [])
            if not isinstance(rules, list):
                rules = []
            for rule in rules:
                if rule_requires_mfa(rule):
                    mfa_enforcing_rules = mfa_enforcing_rules + 1
                    admin_mfa_enforced = True
                    policy_name = policy.get("name", "unnamed")
                    if policy_name not in matched_policy_names:
                        matched_policy_names.append(policy_name)

    # Pass 2: check global sign-on policies for broad MFA enforcement (covers admins too)
    if not admin_mfa_enforced:
        for policy in policies:
            if not isinstance(policy, dict):
                continue
            policy_status = policy.get("status", "")
            if policy_status != "ACTIVE":
                continue
            rules = policy.get("rules", [])
            if not isinstance(rules, list):
                rules = []
            for rule in rules:
                if rule_requires_mfa(rule) and rule_applies_to_everyone(rule):
                    global_mfa_enforced = True
                    mfa_enforcing_rules = mfa_enforcing_rules + 1
                    policy_name = policy.get("name", "unnamed")
                    if policy_name not in matched_policy_names:
                        matched_policy_names.append(policy_name)

    is_enforced = admin_mfa_enforced or global_mfa_enforced
    enforcement_source = "none"
    if admin_mfa_enforced:
        enforcement_source = "admin-specific policy"
    elif global_mfa_enforced:
        enforcement_source = "global sign-on policy (covers admins)"

    return {
        criteriaKey: is_enforced,
        "totalPoliciesInspected": total_policies,
        "adminPoliciesFound": admin_policies_found,
        "mfaEnforcingRulesFound": mfa_enforcing_rules,
        "enforcementSource": enforcement_source,
        "matchedPolicyNames": matched_policy_names
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
                fail_reasons=["Input validation failed — no API data available for evaluation"]
            )

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)

        extra_fields = {
            k: v for k, v in eval_result.items()
            if k != criteriaKey and k != "error"
        }

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        total = eval_result.get("totalPoliciesInspected", 0)
        admin_found = eval_result.get("adminPoliciesFound", 0)
        mfa_rules = eval_result.get("mfaEnforcingRulesFound", 0)
        source = eval_result.get("enforcementSource", "none")
        matched = eval_result.get("matchedPolicyNames", [])

        additional_findings.append(
            "Inspected " + str(total) + " active OKTA_SIGN_ON policy(ies); "
            + str(admin_found) + " admin-specific, "
            + str(mfa_rules) + " MFA-enforcing rule(s) found"
        )
        if matched:
            additional_findings.append("Matched policy names: " + ", ".join(matched))

        if result_value:
            pass_reasons.append(
                "MFA is enforced for admin access via " + source
            )
            if matched:
                pass_reasons.append(
                    "Enforcing policy(ies): " + ", ".join(matched)
                )
        else:
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            else:
                fail_reasons.append(
                    "No active OKTA_SIGN_ON policy rule with requireFactor=true was found "
                    "that applies to admin access"
                )
            recommendations.append(
                "Create or update an Okta global session policy rule targeting admin users "
                "(or the 'Okta Admin Console' policy in OIE) and set 'Require factor' to enforce MFA."
            )
            recommendations.append(
                "Navigate to Security > Authentication Policies (OIE) or Security > "
                "Authentication > Sign-On Policies (Classic) and ensure admin-facing rules "
                "require multifactor authentication."
            )

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalPoliciesInspected": total,
                "adminPoliciesFound": admin_found,
                "mfaEnforcingRulesFound": mfa_rules,
                "enforcementSource": source
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
