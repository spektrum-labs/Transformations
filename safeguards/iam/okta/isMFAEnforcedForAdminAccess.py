"""
Transformation: isMFAEnforcedForAdminAccess
Vendor: Okta  |  Category: iam
Evaluates: Whether MFA is enforced for administrator access by inspecting
OKTA_SIGN_ON (global session) policy rules that target admin/privileged groups
or catch-all rules, verifying that requireFactor is set to true.
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
                "category": "iam"
            }
        }
    }


def is_admin_scoped(policy_name, rule_name):
    """Return True if the policy or rule name indicates admin/privileged targeting."""
    admin_keywords = ["admin", "administrator", "privileged", "super", "elevated", "okta admin"]
    lower_policy = policy_name.lower()
    lower_rule = rule_name.lower()
    for keyword in admin_keywords:
        if keyword in lower_policy:
            return True
        if keyword in lower_rule:
            return True
    return False


def is_catchall_rule(rule_name, include_groups):
    """Return True if the rule is a default/catch-all that applies to everyone."""
    lower_name = rule_name.lower()
    if lower_name in ["default rule", "catch-all rule", "default sign on rule", "default"]:
        return True
    if len(include_groups) == 0:
        return True
    return False


def evaluate(data):
    criteriaKey = "isMFAEnforcedForAdminAccess"
    policies = data.get("policies", [])

    if not isinstance(policies, list):
        policies = []

    if not policies:
        return {
            criteriaKey: False,
            "error": "No OKTA_SIGN_ON policies found in response",
            "policiesChecked": 0,
            "adminPoliciesFound": 0,
            "mfaEnforcingPolicies": []
        }

    policies_checked = 0
    admin_policies_found = 0
    mfa_enforcing_policies = []
    admin_mfa_enforced = False

    for policy in policies:
        if not isinstance(policy, dict):
            continue

        policies_checked = policies_checked + 1
        policy_name = policy.get("name", "")
        policy_status = policy.get("status", "").upper()

        if policy_status != "ACTIVE":
            continue

        rules = policy.get("rules", [])
        if not isinstance(rules, list):
            rules = []

        for rule in rules:
            if not isinstance(rule, dict):
                continue

            rule_status = rule.get("status", "").upper()
            if rule_status != "ACTIVE":
                continue

            rule_name = rule.get("name", "")

            # Extract group conditions
            conditions = rule.get("conditions", {})
            if not isinstance(conditions, dict):
                conditions = {}
            people = conditions.get("people", {})
            if not isinstance(people, dict):
                people = {}
            groups = people.get("groups", {})
            if not isinstance(groups, dict):
                groups = {}
            include_groups = groups.get("include", [])
            if not isinstance(include_groups, list):
                include_groups = []

            # Extract signon action
            actions = rule.get("actions", {})
            if not isinstance(actions, dict):
                actions = {}
            signon = actions.get("signon", {})
            if not isinstance(signon, dict):
                signon = {}

            access = signon.get("access", "ALLOW").upper()
            require_factor = signon.get("requireFactor", False)
            factor_prompt_mode = signon.get("factorPromptMode", "")

            if access == "DENY":
                continue

            admin_targeted = is_admin_scoped(policy_name, rule_name)
            catchall = is_catchall_rule(rule_name, include_groups)

            if admin_targeted or catchall:
                admin_policies_found = admin_policies_found + 1

                if require_factor:
                    admin_mfa_enforced = True
                    entry = policy_name + " / " + rule_name + " (factorPromptMode=" + factor_prompt_mode + ")"
                    mfa_enforcing_policies.append(entry)

    return {
        criteriaKey: admin_mfa_enforced,
        "policiesChecked": policies_checked,
        "adminPoliciesFound": admin_policies_found,
        "mfaEnforcingPolicies": mfa_enforcing_policies
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

        policies_checked = extra_fields.get("policiesChecked", 0)
        admin_policies_found = extra_fields.get("adminPoliciesFound", 0)
        mfa_enforcing_policies = extra_fields.get("mfaEnforcingPolicies", [])

        if result_value:
            pass_reasons.append(
                "MFA (requireFactor=true) is enforced in at least one OKTA_SIGN_ON policy rule "
                "targeting administrators or all users."
            )
            for entry in mfa_enforcing_policies:
                pass_reasons.append("Enforcing rule: " + entry)
        else:
            fail_reasons.append(
                "No OKTA_SIGN_ON policy rule with requireFactor=true was found that targets "
                "admin/privileged groups or applies to all users."
            )
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(
                "Create or update an Okta Sign-On Policy that explicitly targets administrator "
                "groups (e.g. the built-in 'Okta Administrators' group) and set requireFactor=true "
                "with factorPromptMode=ALWAYS on its rules."
            )
            recommendations.append(
                "Review existing OKTA_SIGN_ON policies and ensure rules covering privileged users "
                "do not allow password-only authentication."
            )

        additional_findings.append("Total OKTA_SIGN_ON policies checked: " + str(policies_checked))
        additional_findings.append("Admin/catch-all scoped rules found: " + str(admin_policies_found))

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "criteriaKey": criteriaKey,
                "result": result_value,
                "policiesChecked": policies_checked,
                "adminPoliciesFound": admin_policies_found
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
