"""
Transformation: phishResistantMfaCoveragePercentage
Vendor: Okta
Category: iam
Method: listAccessPolicies

Evaluates phish-resistant MFA coverage as a policy-based proxy using Okta
Access Policy rules that require phishing-resistant possession factors
(verificationMethod.constraints[].possession.phishingResistant=true).
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


def transform(input):
    data, validation = extract_input(input)

    # Okta /api/v1/policies returns a JSON array of policy objects directly.
    # The enriched runtime wraps that in {"data": [...], "validation": {...}}.
    if isinstance(data, list):
        policies = data
    elif isinstance(data, dict):
        inner = data.get("data")
        policies = inner if isinstance(inner, list) else []
    else:
        policies = []

    total_policies = len(policies)
    active_policies_count = 0
    total_rules_examined = 0
    rules_with_phish_resistant = 0
    # Broad-scope: rule has no group restriction (applies to all users)
    broad_scope_rules = 0
    # Narrow-scope: rule is limited to specific groups
    narrow_scope_rules = 0
    phish_resistant_policy_names = []
    non_phish_resistant_policy_names = []
    findings = []

    for policy in policies:
        if not isinstance(policy, dict):
            continue
        if policy.get("status") != "ACTIVE":
            continue
        active_policies_count = active_policies_count + 1
        policy_name = policy.get("name") or "unnamed"
        embedded = policy.get("_embedded") or {}
        rules = embedded.get("rules") or []

        policy_has_phish_resistant = False

        for rule in rules:
            if not isinstance(rule, dict):
                continue
            if rule.get("status") != "ACTIVE":
                continue
            total_rules_examined = total_rules_examined + 1

            actions = rule.get("actions") or {}
            app_sign_on = actions.get("appSignOn") or {}
            # Skip DENY rules — they block access, not enforce MFA
            if app_sign_on.get("access") == "DENY":
                continue

            verification_method = app_sign_on.get("verificationMethod") or {}
            constraints = verification_method.get("constraints") or []

            rule_has_phish = False
            for constraint in constraints:
                if not isinstance(constraint, dict):
                    continue
                possession = constraint.get("possession") or {}
                if possession.get("phishingResistant") is True:
                    rule_has_phish = True
                    break

            if rule_has_phish:
                rules_with_phish_resistant = rules_with_phish_resistant + 1
                policy_has_phish_resistant = True

                conditions = rule.get("conditions") or {}
                people = conditions.get("people") or {}
                groups = people.get("groups") or {}
                include_groups = groups.get("include") or []

                if len(include_groups) == 0:
                    broad_scope_rules = broad_scope_rules + 1
                else:
                    narrow_scope_rules = narrow_scope_rules + 1

        if policy_has_phish_resistant:
            phish_resistant_policy_names.append(policy_name)
        else:
            non_phish_resistant_policy_names.append(policy_name)

    # Derive policy-based coverage proxy
    # Broad-scope rules (no group restriction) = org-wide enforcement = 100%
    # Narrow-scope only = specific groups enforced = conservative ~50% estimate
    # No phish-resistant rules at all = 0%
    if rules_with_phish_resistant == 0:
        coverage_percentage = 0.0
    elif broad_scope_rules > 0:
        coverage_percentage = 100.0
    else:
        coverage_percentage = 50.0

    threshold = 95.0
    pass_reasons = []
    fail_reasons = []
    recommendations = []

    pr_names_str = ", ".join(phish_resistant_policy_names[:5]) if phish_resistant_policy_names else "none"
    non_pr_names_str = ", ".join(non_phish_resistant_policy_names[:5]) if non_phish_resistant_policy_names else "none"

    if coverage_percentage >= threshold:
        pass_reasons.append(
            f"{broad_scope_rules} Access Policy rule(s) across "
            f"{len(phish_resistant_policy_names)} policy/policies ({pr_names_str}) "
            f"enforce phishingResistant=true in verificationMethod.constraints.possession "
            f"with no group restrictions, indicating org-wide phish-resistant MFA "
            f"enforcement. Policy-based coverage estimate: {coverage_percentage:.1f}%."
        )
    else:
        if rules_with_phish_resistant == 0:
            fail_reasons.append(
                f"No active Access Policy rules found with phishingResistant=true in "
                f"verificationMethod.constraints.possession. Examined "
                f"{active_policies_count} active policies containing "
                f"{total_rules_examined} active non-DENY rules. "
                f"Policy-based coverage estimate: 0%."
            )
            recommendations.append(
                "Create or update Access Policy rules to require phishing-resistant MFA "
                "by setting verificationMethod.constraints.possession.phishingResistant=true "
                "and scoping the rule to all users. FIDO2/WebAuthn (key: webauthn) "
                "and Okta FastPass (key: signed_nonce) satisfy this requirement."
            )
        else:
            fail_reasons.append(
                f"Phish-resistant MFA (phishingResistant=true) is enforced in "
                f"{rules_with_phish_resistant} rule(s) across "
                f"{len(phish_resistant_policy_names)} policy/policies ({pr_names_str}), "
                f"but all {narrow_scope_rules} phish-resistant rule(s) are scoped to "
                f"specific groups — no universal-scope rule found. "
                f"Policy-based coverage estimate: ~{coverage_percentage:.1f}% (partial)."
            )
            recommendations.append(
                "Extend phish-resistant MFA enforcement to cover all users, not just "
                "specific groups. Add or modify an Access Policy rule so that "
                "phishingResistant=true applies without a group restriction, "
                "ensuring >=95% of accounts are protected."
            )

    if non_phish_resistant_policy_names:
        findings.append(
            f"{len(non_phish_resistant_policy_names)} active policy/policies lack "
            f"phish-resistant MFA rules: {non_pr_names_str}."
        )

    findings.append(
        "Coverage percentage is a policy-based proxy derived from Access Policy "
        "verificationMethod.constraints.possession.phishingResistant fields. "
        "Actual per-user enrollment counts would require iterating individual "
        "user factor enrollments, which cannot be retrieved in a single API call."
    )

    return create_response(
        result={
            "phishResistantMfaCoveragePercentage": coverage_percentage,
            "activePoliciesExamined": active_policies_count,
            "totalRulesExamined": total_rules_examined,
            "rulesWithPhishResistantMfa": rules_with_phish_resistant,
            "broadScopePhishResistantRules": broad_scope_rules,
            "narrowScopePhishResistantRules": narrow_scope_rules,
            "phishResistantPolicies": phish_resistant_policy_names,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalPolicies": total_policies,
            "activePolicies": active_policies_count,
            "totalRulesExamined": total_rules_examined,
            "rulesWithPhishResistantMfa": rules_with_phish_resistant,
        },
        additional_findings=findings,
        metadata={
            "transformationId": "phishResistantMfaCoveragePercentage",
            "vendor": "Okta",
            "category": "iam",
            "assessmentMethod": "policy-based-proxy",
        },
    )
