"""
Transformation: isSSOEnabled (Endpoint Administrator MFA)
Vendor: Microsoft
Category: Endpoint Security

Evaluates whether Endpoint Security administrator access requires MFA. Accepts
either tenant-wide coverage or complete coverage of the Microsoft Entra roles
that administer Defender, targeting all resources or the Defender admin portal.
Ambiguous exclusions and conditional coverage remain fail-closed.
"""

import json
from datetime import datetime


# Preserve the legacy requirement key while replacing its invalid identity-provider
# evidence with a real Conditional Access MFA evaluation.
CRITERIA_KEY = "isSSOEnabled"

# Microsoft Entra roles with Defender administrative permissions. Read-only
# Global Reader and Security Reader access is deliberately outside this
# administrative-access criterion.
DEFENDER_ADMIN_ROLE_IDS = (
    "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
    "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
    "5f2222b1-57c3-48ba-8ad5-d4759f1fde6f",  # Security Operator
)

DEFENDER_PORTAL_APP_ID = "80ccca67-54bd-44ab-8625-4b79c4dc7775"
DEFENDER_APPLICATION_TARGETS = (
    "microsoftadminportals",
    DEFENDER_PORTAL_APP_ID,
)

# Microsoft-managed authentication strengths whose documented requirement is
# MFA. A custom strength is accepted only when the response explicitly says it
# satisfies MFA; an opaque custom ID is not enough evidence.
MFA_AUTHENTICATION_STRENGTH_IDS = (
    "00000000-0000-0000-0000-000000000002",
    "00000000-0000-0000-0000-000000000003",
    "00000000-0000-0000-0000-000000000004",
)


def normalized_values(values):
    if values is None:
        return []
    if not isinstance(values, list):
        return None
    return [str(value).strip().lower() for value in values]


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]

    data = input_data
    if isinstance(data, dict):
        for _ in range(3):
            unwrapped = False
            for key in ["api_response", "response", "result", "apiResponse", "Output"]:
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break

    return data, {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None,
                    transformation_errors=None, api_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}

    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or [],
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": [],
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "2.0",
                "transformationId": CRITERIA_KEY,
                "vendor": "Microsoft",
                "category": "Endpoint Security",
            },
        },
    }


def requires_mfa(grant_controls):
    if not isinstance(grant_controls, dict):
        return False

    controls = normalized_values(grant_controls.get("builtInControls"))
    if controls is None:
        return False
    if "mfa" in controls:
        operator = str(grant_controls.get("operator") or "").upper()
        if operator == "AND":
            return True
        if operator == "OR" and controls == ["mfa"]:
            return not any([
                grant_controls.get("customAuthenticationFactors"),
                grant_controls.get("termsOfUse"),
                grant_controls.get("authenticationStrength"),
            ])

    authentication_strength = grant_controls.get("authenticationStrength")
    if not isinstance(authentication_strength, dict):
        return False

    # Authentication strength must itself be mandatory. An OR policy that also
    # permits another grant control does not require MFA on every sign-in.
    operator = str(grant_controls.get("operator") or "").upper()
    if operator not in ("AND", "OR"):
        return False
    for key in ("customAuthenticationFactors", "termsOfUse"):
        value = grant_controls.get(key)
        if value is not None and not isinstance(value, list):
            return False
    alternative_controls = any([
        controls,
        grant_controls.get("customAuthenticationFactors"),
        grant_controls.get("termsOfUse"),
    ])
    if alternative_controls and operator != "AND":
        return False

    requirements_satisfied = str(
        authentication_strength.get("requirementsSatisfied") or ""
    ).strip().lower()
    if requirements_satisfied == "mfa":
        return True

    return (
        str(authentication_strength.get("id") or "").strip().lower()
        in MFA_AUTHENTICATION_STRENGTH_IDS
    )


def covers_endpoint_administrators(users):
    if not isinstance(users, dict):
        return False

    # Without role membership evidence, any user/group/role exclusion could
    # remove an Endpoint administrator from the policy.
    if any([
        users.get("excludeUsers"),
        users.get("excludeGroups"),
        users.get("excludeRoles"),
        users.get("excludeGuestsOrExternalUsers"),
    ]):
        return False

    include_users = normalized_values(users.get("includeUsers"))
    include_roles = normalized_values(users.get("includeRoles"))
    if include_users is None or include_roles is None:
        return False
    if "all" in include_users:
        return True

    return all(role_id in include_roles for role_id in DEFENDER_ADMIN_ROLE_IDS)


def covers_defender_admin_portal(applications):
    if not isinstance(applications, dict):
        return False

    included = normalized_values(applications.get("includeApplications"))
    excluded = normalized_values(applications.get("excludeApplications"))
    if included is None or excluded is None:
        return False
    if (
        "applicationFilter" in applications
        and applications.get("applicationFilter") is not None
    ):
        return False

    # Excluding the admin-portals grouping, the Defender portal directly, or
    # the Office 365 grouping makes Defender coverage ambiguous.
    relevant_exclusions = DEFENDER_APPLICATION_TARGETS + ("office365",)
    if any(target in excluded for target in relevant_exclusions):
        return False

    return (
        "all" in included
        or any(target in included for target in DEFENDER_APPLICATION_TARGETS)
    )


def has_no_narrowing_conditions(conditions):
    client_app_types = normalized_values(conditions.get("clientAppTypes"))
    if client_app_types is None:
        return False
    if client_app_types and not any(
        value in client_app_types for value in ("all", "browser")
    ):
        return False

    return not any([
        conditions.get("signInRiskLevels"),
        conditions.get("userRiskLevels"),
        conditions.get("servicePrincipalRiskLevels"),
        conditions.get("platforms"),
        conditions.get("locations"),
        conditions.get("devices"),
        conditions.get("clientApplications"),
        conditions.get("authenticationFlows"),
        conditions.get("insiderRiskLevels"),
    ])


def is_enforced_endpoint_admin_mfa_policy(policy):
    if not isinstance(policy, dict) or str(policy.get("state") or "").lower() != "enabled":
        return False

    conditions = policy.get("conditions") or {}
    if not isinstance(conditions, dict):
        return False

    return (
        covers_endpoint_administrators(conditions.get("users"))
        and covers_defender_admin_portal(conditions.get("applications"))
        and has_no_narrowing_conditions(conditions)
        and requires_mfa(policy.get("grantControls"))
    )


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if isinstance(data, dict) and ("PSError" in data or "error" in data):
            return create_response(
                {CRITERIA_KEY: False, "matchingPolicies": 0},
                validation=validation,
                api_errors=[
                    "Microsoft Graph could not return Conditional Access policies"
                ],
                fail_reasons=["Could not retrieve Conditional Access policies"],
                recommendations=[
                    "Verify Microsoft Graph permissions and re-check the connection"
                ],
            )

        if validation.get("status") == "failed":
            errors = validation.get("errors") or ["Input validation failed"]
            return create_response(
                {CRITERIA_KEY: False, "matchingPolicies": 0},
                validation=validation,
                fail_reasons=["Conditional Access evidence could not be validated"],
                transformation_errors=errors,
            )

        malformed_error = None
        if not isinstance(data, dict):
            malformed_error = "Conditional Access response must be an object"
        elif "value" not in data:
            malformed_error = "Conditional Access response is missing 'value'"
        elif not isinstance(data.get("value"), list):
            malformed_error = "Conditional Access response 'value' must be a list"

        if malformed_error:
            return create_response(
                {CRITERIA_KEY: False, "matchingPolicies": 0},
                validation=validation,
                fail_reasons=["Conditional Access evidence is malformed"],
                transformation_errors=[malformed_error],
            )

        policies = data["value"]

        matches = [
            policy for policy in policies
            if is_enforced_endpoint_admin_mfa_policy(policy)
        ]
        is_enforced = bool(matches)
        result = {
            CRITERIA_KEY: is_enforced,
            "matchingPolicies": len(matches),
        }

        if is_enforced:
            names = [str(policy.get("displayName") or "unnamed") for policy in matches]
            return create_response(
                result,
                validation=validation,
                pass_reasons=[
                    "Enabled Conditional Access policy requires MFA for Endpoint Security administrative access: "
                    + ", ".join(names)
                ],
                input_summary={"totalPolicies": len(policies), "matchingPolicies": len(matches)},
            )

        return create_response(
            result,
            validation=validation,
            fail_reasons=[
                "No enabled Conditional Access policy proves MFA is required for all Endpoint administrators"
            ],
            recommendations=[
                "Require MFA for all users or all supported Defender administrator roles, targeting all resources or Microsoft Admin Portals without relevant exclusions"
            ],
            input_summary={"totalPolicies": len(policies), "matchingPolicies": 0},
        )
    except Exception as error:
        return create_response(
            {CRITERIA_KEY: False, "matchingPolicies": 0},
            transformation_errors=[str(error)],
            fail_reasons=["Transformation error: " + str(error)],
        )
