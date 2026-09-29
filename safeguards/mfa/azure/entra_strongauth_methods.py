"""isStrongAuthRequired for Microsoft Entra ID (Azure AD One-Click), from the authentication methods policy
(GET /v1.0/policies/authenticationMethodsPolicy, the One-Click method getEstateMFAStatus).

Why a new file: the One-Click definition ran d9b6f27a/isstrongauthrequired.py on getUsers (a bare
/v1.0/users page). That transform looks for objects with status "active", which user records never
carry, so it read false at 21 of 21 tenants (2026-09-29). isstrongauthrequired.py in this folder reads
the right policy but reads false on any body, including an error, so it is not reused as is.

Value: true when Microsoft Authenticator or FIDO2 is enabled in the policy; false when the policy was
read, its migration to the converged policy is complete (or not reported), and neither is enabled.

Not evaluated (dataCollection error, value None):
- an error or unrecognised body (no non-empty authenticationMethodConfigurations array);
- neither strong method enabled while policyMigrationState is preMigration or migrationInProgress: the
  legacy per-user MFA and SSPR policies still govern and this endpoint cannot read them;
- neither strong method enabled but an external authentication method (for example Cisco Duo) is
  enabled: the factor is enforced by that provider, which Entra cannot grade.
"""

import json
from datetime import datetime


CRITERIA_KEY = "isStrongAuthRequired"
STRONG_METHODS = {"fido2": "FIDO2 security key", "microsoftauthenticator": "Microsoft Authenticator"}
LEGACY_STATES = ("premigration", "migrationinprogress")


def extract_input(value):
    if isinstance(value, (str, bytes)):
        value = json.loads(value.decode("utf-8") if isinstance(value, bytes) else value)
    if isinstance(value, dict) and "data" in value and "validation" in value:
        return value["data"], value["validation"]
    data = value
    for attempt in range(3):
        if not isinstance(data, dict):
            break
        nested = None
        for key in ("api_response", "response", "result", "apiResponse", "Output"):
            if isinstance(data.get(key), (dict, list)):
                nested = data[key]
                break
        if nested is None:
            break
        data = nested
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation, errors=(), passed=(), failed=(), summary=None):
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if errors else "success", "errors": list(errors)},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {"status": "success", "errors": [], "inputSummary": summary or {}},
            "evaluation": {
                "passReasons": list(passed),
                "failReasons": list(failed) + list(errors),
                "recommendations": [],
                "additionalFindings": [],
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "2.0",
                "transformationId": CRITERIA_KEY,
                "vendor": "Microsoft Entra ID",
                "category": "Identity and Access Management",
            },
        },
    }


def is_external(config):
    return "externalauthenticationmethodconfiguration" in str(config.get("@odata.type") or "").lower()


def transform(input):
    try:
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            raise ValueError("Input validation failed")
        if not isinstance(data, dict) or "error" in data:
            raise ValueError("Microsoft did not return the authentication methods policy")
        configs = data.get("authenticationMethodConfigurations")
        if not isinstance(configs, list) or not configs or any(not isinstance(c, dict) for c in configs):
            raise ValueError("No authenticationMethodConfigurations array: the authentication methods policy was not read")
        enabled = [c for c in configs if str(c.get("state") or "").lower() == "enabled"]
        strong = [STRONG_METHODS[str(c.get("id") or "").lower()] for c in enabled
                  if str(c.get("id") or "").lower() in STRONG_METHODS]
        external = [str(c.get("displayName") or c.get("id") or "external method") for c in enabled if is_external(c)]
        migration = str(data.get("policyMigrationState") or "")
        summary = {"enabledStrongMethods": strong, "enabledExternalMethods": external,
                   "enabledMethods": [str(c.get("id") or "") for c in enabled], "policyMigrationState": migration}
        if strong:
            result = {CRITERIA_KEY: True}
            result.update(summary)
            return create_response(result, validation, passed=["Strong method(s) enabled: " + ", ".join(strong)],
                                   summary=summary)
        if migration.lower() in LEGACY_STATES:
            raise ValueError("No strong method is enabled in the authentication methods policy, but its migration "
                             "state is " + migration + ": the legacy MFA and SSPR policies still apply and cannot "
                             "be read here")
        if external:
            raise ValueError("No Microsoft strong method is enabled; the external authentication method(s) "
                             + ", ".join(external) + " enforce the factor and cannot be graded from Entra")
        result = {CRITERIA_KEY: False}
        result.update(summary)
        return create_response(result, validation,
                               failed=["Neither Microsoft Authenticator nor FIDO2 is enabled in the authentication "
                                       "methods policy"], summary=summary)
    except Exception as error:
        return create_response(
            {CRITERIA_KEY: None},
            {"status": "failed", "errors": [str(error)], "warnings": []},
            errors=[str(error)],
        )
