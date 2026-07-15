"""Evaluate whether Endpoint Security administrator access requires MFA.

The check deliberately accepts only broad, enforceable Conditional Access
policies. Narrower policies need additional identity and application evidence
before they can safely prove that every Endpoint administrator is covered.
"""

import json
from datetime import datetime


# Preserve the legacy requirement key while replacing its invalid identity-provider
# evidence with a real Conditional Access MFA evaluation.
CRITERIA_KEY = "isSSOEnabled"


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
                    recommendations=None, input_summary=None, transformation_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}

    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "success", "errors": []},
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

    controls = grant_controls.get("builtInControls") or []
    if not isinstance(controls, list) or "mfa" not in controls:
        return False

    operator = str(grant_controls.get("operator") or "").upper()
    if operator == "AND":
        return True
    if operator != "OR" or controls != ["mfa"]:
        return False

    return not (
        grant_controls.get("authenticationStrength")
        or grant_controls.get("customAuthenticationFactors")
        or grant_controls.get("termsOfUse")
    )


def covers_all_users(users):
    if not isinstance(users, dict) or "All" not in (users.get("includeUsers") or []):
        return False

    return not any([
        users.get("excludeUsers"),
        users.get("excludeGroups"),
        users.get("excludeRoles"),
        users.get("excludeGuestsOrExternalUsers"),
    ])


def covers_all_applications(applications):
    if not isinstance(applications, dict):
        return False
    return (
        "All" in (applications.get("includeApplications") or [])
        and not applications.get("excludeApplications")
    )


def has_no_narrowing_conditions(conditions):
    client_app_types = conditions.get("clientAppTypes") or []
    if client_app_types and "all" not in [str(value).lower() for value in client_app_types]:
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
        covers_all_users(conditions.get("users"))
        and covers_all_applications(conditions.get("applications"))
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
        policies = data.get("value", []) if isinstance(data, dict) else []
        if not isinstance(policies, list):
            policies = []

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
                    "Enabled Conditional Access policy requires MFA for all users and cloud applications: "
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
                "Enable a Conditional Access policy that requires MFA for all users and all cloud applications without exclusions"
            ],
            input_summary={"totalPolicies": len(policies), "matchingPolicies": 0},
        )
    except Exception as error:
        return create_response(
            {CRITERIA_KEY: False, "matchingPolicies": 0},
            transformation_errors=[str(error)],
            fail_reasons=["Transformation error: " + str(error)],
        )
