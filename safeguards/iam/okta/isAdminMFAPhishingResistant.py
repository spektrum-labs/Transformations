"""
Transformation: isAdminMFAPhishingResistant
Vendor: Okta
Category: iam
Method: listAccessPolicies

Evaluates whether admin accounts are required to use phishing-resistant MFA
by inspecting ACCESS_POLICY rules for constraints[].possession.phishingResistant=true
scoped to admin console or admin group targets.
"""
import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
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
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Create the standardized 5-section transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    data_collection_status = "error" if api_err_list else "success"
    transformation_status = "error" if transform_err_list else "success"
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": data_collection_status, "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": transformation_status,
                "errors": transform_err_list,
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": response_metadata,
        },
    }


# Keywords that suggest admin-related policy names or group targets
ADMIN_KEYWORDS = ["admin", "administrator", "okta admin", "super admin", "privileged", "it admin"]


def is_admin_related(name):
    """Return True if the given string contains admin-related keywords."""
    if not name:
        return False
    lowered = name.lower()
    for kw in ADMIN_KEYWORDS:
        if kw in lowered:
            return True
    return False


def rule_requires_phishing_resistant(rule):
    """
    Return True if the rule's verificationMethod constraints require
    phishing-resistant possession.
    Checks:
      - actions.appSignOn.verificationMethod.constraints[].possession.phishingResistant == true
      - actions.appSignOn.verificationMethod.type == "PHISHING_RESISTANT"
    """
    actions = rule.get("actions") or {}
    app_sign_on = actions.get("appSignOn") or {}
    if app_sign_on.get("access") == "DENY":
        return False
    vm = app_sign_on.get("verificationMethod") or {}
    vm_type = (vm.get("type") or "").upper()
    if vm_type == "PHISHING_RESISTANT":
        return True
    constraints = vm.get("constraints") or []
    for constraint in constraints:
        possession = constraint.get("possession") or {}
        if possession.get("phishingResistant") is True:
            return True
        if possession.get("hardwareProtection") is True and possession.get("deviceBound") is True:
            return True
    return False


def rule_is_active(rule):
    return (rule.get("status") or "").upper() == "ACTIVE"


def transform(input_data):
    data, validation = extract_input(input_data)

    # The response is a list of ACCESS_POLICY objects (or a dict with empty arrays from redaction)
    if isinstance(data, list):
        policies = data
    else:
        policies = []

    total_policies = len(policies)
    total_rules = 0
    admin_policies_found = []
    phish_resistant_rules = []
    non_phish_resistant_admin_rules = []
    all_findings = []

    for policy in policies:
        policy_name = policy.get("name") or ""
        embedded = policy.get("_embedded") or {}
        rules = embedded.get("rules") or []

        policy_is_admin_related = is_admin_related(policy_name)

        active_rules = [r for r in rules if rule_is_active(r)]
        total_rules = total_rules + len(active_rules)

        for rule in active_rules:
            rule_name = rule.get("name") or ""
            conditions = rule.get("conditions") or {}
            people = conditions.get("people") or {}
            groups = people.get("groups") or {}
            rule_groups = groups.get("include") or []

            rule_is_admin_scoped = policy_is_admin_related or is_admin_related(rule_name)
            for grp in rule_groups:
                if is_admin_related(grp):
                    rule_is_admin_scoped = True

            if rule_is_admin_scoped:
                if policy_name not in admin_policies_found:
                    admin_policies_found.append(policy_name)

                if rule_requires_phishing_resistant(rule):
                    phish_resistant_rules.append(
                        f"Policy '{policy_name}' / Rule '{rule_name}': phishingResistant=true"
                    )
                else:
                    non_phish_resistant_admin_rules.append(
                        f"Policy '{policy_name}' / Rule '{rule_name}': phishingResistant not enforced"
                    )

        # Record any phish-resistant rules as additional findings (all policies, not just admin)
        for rule in active_rules:
            if rule_requires_phishing_resistant(rule):
                rule_name = rule.get("name") or ""
                finding = f"Policy '{policy_name}' / Rule '{rule_name}' enforces phishingResistant=true"
                if finding not in all_findings:
                    all_findings.append(finding)

    # Determine verdict
    if total_policies == 0:
        # No policies returned — cannot confirm
        is_phish_resistant = False
        fail_reasons = [
            "No ACCESS_POLICY records were returned by the Okta API. "
            "Unable to confirm that any admin-scoped policy enforces phishing-resistant MFA "
            "(FIDO2/passkeys). This may indicate no policies are configured or the API "
            "returned an empty result."
        ]
        pass_reasons = []
        recommendations = [
            "Create an Okta Access Policy targeting the Okta Admin Console application and all "
            "admin groups. Add a rule with actions.appSignOn.verificationMethod.constraints[]"
            ".possession.phishingResistant=true to enforce FIDO2 or passkey authentication "
            "for all privileged accounts."
        ]
    elif len(phish_resistant_rules) > 0 and len(non_phish_resistant_admin_rules) == 0:
        # All admin rules enforce phish-resistant MFA
        is_phish_resistant = True
        pass_reasons = [
            f"Found {len(phish_resistant_rules)} admin-scoped ACCESS_POLICY rule(s) across "
            f"{len(admin_policies_found)} policy/policies enforcing phishingResistant=true: "
            + "; ".join(phish_resistant_rules)
        ]
        fail_reasons = []
        recommendations = []
    elif len(phish_resistant_rules) > 0 and len(non_phish_resistant_admin_rules) > 0:
        # Mixed: some admin rules enforce it, some do not
        is_phish_resistant = False
        fail_reasons = [
            f"{len(non_phish_resistant_admin_rules)} admin-scoped rule(s) do NOT enforce "
            "phishingResistant=true: " + "; ".join(non_phish_resistant_admin_rules)
        ]
        pass_reasons = [
            f"{len(phish_resistant_rules)} admin-scoped rule(s) do enforce phishingResistant=true: "
            + "; ".join(phish_resistant_rules)
        ]
        recommendations = [
            "Review and update all admin-scoped ACCESS_POLICY rules to require "
            "phishingResistant=true in verificationMethod constraints. Ensure no admin group "
            "has a fallback rule permitting weaker MFA."
        ]
    elif len(admin_policies_found) == 0:
        # Policies exist but none are admin-scoped by name/group
        is_phish_resistant = False
        fail_reasons = [
            f"Reviewed {total_policies} ACCESS_POLICY record(s) with {total_rules} active rule(s) "
            "but found no policies or rules explicitly targeting admin groups or the Okta Admin "
            "Console by name. Cannot confirm phishing-resistant MFA is enforced for admin accounts."
        ]
        pass_reasons = []
        recommendations = [
            "Create a dedicated ACCESS_POLICY for the Okta Admin Console application targeting all "
            "administrator groups. Configure rules with verificationMethod.constraints[].possession"
            ".phishingResistant=true to mandate FIDO2/passkey authentication."
        ]
    else:
        # Admin policies found but no rule enforces phish-resistant MFA
        non_pr_summary = "; ".join(non_phish_resistant_admin_rules) if non_phish_resistant_admin_rules else "no active rules with phishingResistant=true found"
        is_phish_resistant = False
        fail_reasons = [
            f"Found {len(admin_policies_found)} admin-related policy/policies "
            f"({', '.join(admin_policies_found)}) but none of their active rules require "
            f"phishingResistant=true in verificationMethod constraints: {non_pr_summary}"
        ]
        pass_reasons = []
        recommendations = [
            "Update admin-scoped ACCESS_POLICY rules to set "
            "actions.appSignOn.verificationMethod.constraints[].possession.phishingResistant=true. "
            "This enforces FIDO2 or passkeys (phish-resistant MFA) for all admin accounts."
        ]

    return create_response(
        result={
            "isAdminMFAPhishingResistant": is_phish_resistant,
            "totalPoliciesEvaluated": total_policies,
            "adminRelatedPoliciesFound": len(admin_policies_found),
            "phishResistantAdminRules": len(phish_resistant_rules),
            "nonPhishResistantAdminRules": len(non_phish_resistant_admin_rules),
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalPolicies": total_policies,
            "totalActiveRules": total_rules,
            "adminPoliciesFound": len(admin_policies_found),
        },
        additional_findings=all_findings,
        metadata={
            "transformationId": "isAdminMFAPhishingResistant",
            "vendor": "Okta",
            "category": "iam",
        },
    )
