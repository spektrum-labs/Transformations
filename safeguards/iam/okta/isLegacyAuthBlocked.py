"""
Transformation: isLegacyAuthBlocked
Criterion: PM-ID-05.4 - Legacy Authentication Blocked
Vendor: Okta
Category: iam

Evaluates Okta Global Session Policies (type=OKTA_SIGN_ON) to determine
whether legacy authentication protocols are blocked. Legacy auth in Okta
is identified by rules where:
  - conditions.authContext.authType = "ANY" with DENY action
  - conditions.clients contains legacy client types with DENY action
  - A DENY rule exists that targets legacy/non-MFA auth contexts
  - An ALLOW+requireFactor=true rule targeting legacy clients (legacy clients
    cannot complete MFA challenges, so they are effectively blocked)
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


# Legacy auth client types that Okta recognizes in conditions.clients
LEGACY_CLIENT_TYPES = [
    "LEGACY_IMAP",
    "LEGACY_POP",
    "LEGACY_SMTP",
    "LEGACY_EXCHANGE",
    "LEGACY_OFFICE365",
    "LEGACY_AUTODISCOVER",
    "LEGACY_MAPI",
    "LEGACY_JRPC",
    "LEGACY_WEBDAV",
    "LEGACY_SOAP",
    "LEGACY_WEB",
    "LEGACY_DIRECT_SYNC",
    "DESKTOP_OUTLOOK",
]


def check_rule_targets_legacy(rule):
    """
    Returns (bool, str) — whether the rule targets legacy auth clients,
    and a human-readable reason string.
    """
    conditions = rule.get("conditions") or {}
    clients = conditions.get("clients") or {}
    include = clients.get("include") or []
    auth_context = conditions.get("authContext") or {}
    auth_type = auth_context.get("authType") or ""

    # Check if clients condition includes known legacy types
    for client in include:
        if isinstance(client, str) and client in LEGACY_CLIENT_TYPES:
            return True, "conditions.clients.include contains legacy client type '%s'" % client
        if isinstance(client, dict):
            client_type = client.get("type") or client.get("id") or ""
            if client_type in LEGACY_CLIENT_TYPES:
                return True, "conditions.clients.include contains legacy client type '%s'" % client_type

    # authType=ANY on a DENY rule catches all auth types including legacy protocols
    if auth_type == "ANY":
        return True, "conditions.authContext.authType=ANY (matches all authentication types including legacy protocols)"

    return False, ""


def transform(input_data):
    data, validation = extract_input(input_data)

    # The response is a list of policy objects (array at the top level)
    if isinstance(data, list):
        policies = data
    elif isinstance(data, dict):
        # Try to find a list within the dict
        policies = []
        for key in ["policies", "items", "data"]:
            val = data.get(key)
            if isinstance(val, list):
                policies = val
                break
    else:
        policies = []

    total_policies = len(policies)
    total_active_policies = 0
    total_rules_inspected = 0
    legacy_blocking_rules = []
    deny_rules_found = 0
    mfa_required_rules_found = 0

    for policy in policies:
        policy_name = policy.get("name") or "unnamed"
        policy_status = policy.get("status") or ""
        if policy_status.upper() != "ACTIVE":
            continue

        total_active_policies = total_active_policies + 1
        embedded = policy.get("_embedded") or {}
        rules = embedded.get("rules") or []

        for rule in rules:
            rule_name = rule.get("name") or "unnamed rule"
            rule_status = rule.get("status") or ""
            if rule_status.upper() != "ACTIVE":
                continue

            total_rules_inspected = total_rules_inspected + 1
            actions = rule.get("actions") or {}
            signon = actions.get("signon") or {}
            access = signon.get("access") or ""
            require_factor = signon.get("requireFactor")

            is_legacy_targeted, legacy_reason = check_rule_targets_legacy(rule)

            if access.upper() == "DENY":
                deny_rules_found = deny_rules_found + 1
                if is_legacy_targeted:
                    legacy_blocking_rules.append({
                        "policy": policy_name,
                        "rule": rule_name,
                        "mechanism": "DENY action",
                        "reason": legacy_reason,
                    })
            elif access.upper() == "ALLOW" and require_factor is True:
                mfa_required_rules_found = mfa_required_rules_found + 1
                if is_legacy_targeted:
                    legacy_blocking_rules.append({
                        "policy": policy_name,
                        "rule": rule_name,
                        "mechanism": "ALLOW+requireFactor=true (legacy clients cannot complete MFA)",
                        "reason": legacy_reason,
                    })

    is_blocked = len(legacy_blocking_rules) > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []
    additional_findings = []

    if total_policies == 0:
        fail_reasons.append(
            "No Global Session Policies (OKTA_SIGN_ON type) were returned by the API. "
            "Cannot confirm legacy authentication is blocked without policy configuration data."
        )
        recommendations.append(
            "Configure an Okta Global Session Policy rule that targets legacy authentication "
            "clients (e.g., LEGACY_IMAP, LEGACY_POP, LEGACY_SMTP) and sets the sign-on "
            "action to DENY. Navigate to Security > Authentication in the Okta Admin Console."
        )
    elif is_blocked:
        for br in legacy_blocking_rules[:3]:
            pass_reasons.append(
                "Policy '%s', rule '%s' blocks legacy auth via %s (%s)." % (
                    br["policy"], br["rule"], br["mechanism"], br["reason"]
                )
            )
        if len(legacy_blocking_rules) > 3:
            pass_reasons.append(
                "%d additional legacy-auth blocking rules found across policies." % (
                    len(legacy_blocking_rules) - 3
                )
            )
    else:
        fail_reasons.append(
            "Inspected %d active Global Session Policies with %d active rules total. "
            "No rules were found that DENY legacy authentication client types "
            "(LEGACY_IMAP, LEGACY_POP, LEGACY_SMTP, LEGACY_EXCHANGE, etc.) or "
            "enforce MFA (requireFactor=true) on legacy auth contexts." % (
                total_active_policies, total_rules_inspected
            )
        )
        if mfa_required_rules_found > 0:
            additional_findings.append(
                "%d rules require MFA (requireFactor=true) but are not scoped specifically "
                "to legacy auth client types — legacy clients that bypass MFA challenges "
                "may still succeed." % mfa_required_rules_found
            )
        if deny_rules_found > 0:
            additional_findings.append(
                "%d DENY rules exist but none specifically target legacy authentication "
                "client types (LEGACY_IMAP, LEGACY_POP, LEGACY_SMTP, etc.)." % deny_rules_found
            )
        recommendations.append(
            "Add a Global Session Policy rule that targets legacy authentication client "
            "types (LEGACY_IMAP, LEGACY_POP, LEGACY_SMTP, LEGACY_EXCHANGE) and sets the "
            "action to DENY. This prevents MFA bypass via legacy protocols that cannot "
            "satisfy modern authentication challenges."
        )
        recommendations.append(
            "Review existing MFA-required rules to ensure they are scoped to include "
            "legacy client types so that those clients are effectively blocked when "
            "they cannot complete the MFA challenge."
        )

    input_summary = {
        "totalPoliciesReturned": total_policies,
        "totalActivePolicies": total_active_policies,
        "totalActiveRulesInspected": total_rules_inspected,
        "legacyBlockingRulesFound": len(legacy_blocking_rules),
        "denyRulesFound": deny_rules_found,
        "mfaRequiredRulesFound": mfa_required_rules_found,
    }

    return create_response(
        result={
            "isLegacyAuthBlocked": is_blocked,
            "legacyBlockingRulesFound": len(legacy_blocking_rules),
            "totalPoliciesEvaluated": total_active_policies,
            "totalRulesInspected": total_rules_inspected,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        additional_findings=additional_findings,
        metadata={
            "transformationId": "isLegacyAuthBlocked",
            "vendor": "Okta",
            "category": "iam",
        },
    )
