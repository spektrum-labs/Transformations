"""
Transformation: isMFAConfiguredForSecurityAdmins
Vendor: Microsoft Entra ID  |  Category: Multifactor Authentication
Evaluates: Whether MFA is required for security admin roles via Conditional Access

A policy satisfies this check when it is enabled, requires MFA (via
builtInControls or authenticationStrength), and covers security admin
roles either by targeting "All" users without excluding admin roles
or by explicitly including admin role IDs.

API: GET /v1.0/identity/conditionalAccess/policies
"""
import json
from datetime import datetime

# Well-known Microsoft Entra security admin role template IDs
SECURITY_ADMIN_ROLES = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "Conditional Access Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
    "7698a772-787b-4ac8-901f-60d6b08affd2": "Privileged Authentication Administrator",
}


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return {"data": input_data["data"], "validation": input_data["validation"]}
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return {"data": data, "validation": {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}}


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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isMFAConfiguredForSecurityAdmins", "vendor": "Microsoft Entra ID", "category": "Multifactor Authentication"}
        }
    }


def policy_requires_mfa(policy):
    """Check if a policy requires MFA via builtInControls or authenticationStrength.

    The CA policy response embeds authenticationStrength as {"id": "...", "displayName": "..."}
    without the requirementsSatisfied field (that lives on the full auth strength object at
    /identity/conditionalAccess/authenticationStrength/policies/{id}). All built-in
    authentication strengths (MFA, Passwordless MFA, Phishing-resistant MFA) satisfy MFA,
    so presence with a non-empty id is sufficient.
    """
    grant = policy.get("grantControls", None)
    if not grant or not isinstance(grant, dict):
        return False
    controls = grant.get("builtInControls", [])
    if isinstance(controls, list) and "mfa" in controls:
        return True
    auth_strength = grant.get("authenticationStrength", None)
    if isinstance(auth_strength, dict) and auth_strength.get("id"):
        return True
    return False


def policy_covers_admin_roles(policy):
    """Check if policy targets security admin roles. Returns list of covered role names."""
    conditions = policy.get("conditions", {})
    if not isinstance(conditions, dict):
        return []
    users = conditions.get("users", {})
    if not isinstance(users, dict):
        return []

    include_users = users.get("includeUsers", [])
    if not isinstance(include_users, list):
        include_users = []
    include_roles = users.get("includeRoles", [])
    if not isinstance(include_roles, list):
        include_roles = []
    exclude_roles = users.get("excludeRoles", [])
    if not isinstance(exclude_roles, list):
        exclude_roles = []

    covered = []

    # Path 1: Policy targets "All" users - check that admin roles are not excluded
    if "All" in include_users:
        for role_id in SECURITY_ADMIN_ROLES:
            if role_id not in exclude_roles:
                covered.append(SECURITY_ADMIN_ROLES[role_id])

    # Path 2: Policy explicitly includes admin role IDs or targets "All" roles
    if not covered:
        if "All" in include_roles:
            for role_id in SECURITY_ADMIN_ROLES:
                if role_id not in exclude_roles:
                    covered.append(SECURITY_ADMIN_ROLES[role_id])
        else:
            for role_id in include_roles:
                if role_id in SECURITY_ADMIN_ROLES:
                    covered.append(SECURITY_ADMIN_ROLES[role_id])

    return covered


def transform(input):
    criteriaKey = "isMFAConfiguredForSecurityAdmins"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        extracted = extract_input(input)
        data = extracted["data"]
        validation = extracted["validation"]

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        # Extract policies from the conditional access response
        policies = []
        if isinstance(data, dict):
            policies = data.get("value", [])
            if not isinstance(policies, list):
                policies = []
        elif isinstance(data, list):
            policies = data

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        matching_policies = []
        report_only_policies = []
        all_covered_roles = []

        for policy in policies:
            if not isinstance(policy, dict):
                continue

            state = (policy.get("state", "") or "").lower()
            name = policy.get("displayName", "unnamed")

            if not policy_requires_mfa(policy):
                continue

            covered_roles = policy_covers_admin_roles(policy)
            if not covered_roles:
                continue

            if state == "enabled":
                matching_policies.append(name)
                for role_name in covered_roles:
                    if role_name not in all_covered_roles:
                        all_covered_roles.append(role_name)
            elif state == "enabledforreportingbutnotenforced":
                report_only_policies.append(name)

        is_configured = len(matching_policies) > 0

        if is_configured:
            pass_reasons.append(
                str(len(matching_policies)) + " enabled Conditional Access policy/policies require MFA for security admins"
            )
            for pname in matching_policies:
                pass_reasons.append("Policy: " + str(pname))
            pass_reasons.append("Covered roles: " + ", ".join(all_covered_roles))

            # Check if any security admin roles are NOT covered
            uncovered = []
            for role_id in SECURITY_ADMIN_ROLES:
                rname = SECURITY_ADMIN_ROLES[role_id]
                if rname not in all_covered_roles:
                    uncovered.append(rname)
            if uncovered:
                additional_findings.append("Roles not explicitly covered: " + ", ".join(uncovered))
        else:
            fail_reasons.append("No enabled Conditional Access policy requires MFA for security admin roles")
            recommendations.append(
                "Create a Conditional Access policy that requires MFA and targets security admin roles "
                "(Global Admin, Security Admin, Conditional Access Admin, Privileged Role Admin, Authentication Admin)"
            )

        if report_only_policies:
            additional_findings.append(
                "Report-only (not enforced) MFA policies targeting admins: " + ", ".join(report_only_policies)
            )

        return create_response(
            result={
                criteriaKey: is_configured,
                "matchingPolicies": len(matching_policies),
                "coveredRoles": all_covered_roles,
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalPolicies": len(policies),
                "enabledMfaAdminPolicies": len(matching_policies),
                "reportOnlyMfaAdminPolicies": len(report_only_policies),
                "coveredRoleCount": len(all_covered_roles),
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
