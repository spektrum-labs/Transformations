"""
Transformation: authTypesAllowed
Vendor: Microsoft
Category: Identity / Authentication

Evaluates if only secure authentication types (FIDO2, Microsoft Authenticator) are allowed.
Not evaluated (dataCollection error) when nothing is enabled in the policy, or when only secure
types are enabled but policyMigrationState is not migrationComplete or is not reported at all: the
legacy per-user MFA and SSPR policies may still apply then and cannot be read here.
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
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
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
                "transformationId": "authTypesAllowed",
                "vendor": "Microsoft",
                "category": "Identity"
            }
        }
    }



def parse_api_error(raw_error: str, source: str = None) -> tuple:
    """Parse raw API error into clean message with source."""
    raw_lower = raw_error.lower() if raw_error else ''
    src = source or "external service"

    if '401' in raw_error:
        return (f"Could not connect to {src}: Authentication failed (HTTP 401)",
                f"Verify {src} credentials and permissions are valid")
    elif '403' in raw_error:
        return (f"Could not connect to {src}: Access denied (HTTP 403)",
                f"Verify the integration has required {src} permissions")
    elif '404' in raw_error:
        return (f"Could not connect to {src}: Resource not found (HTTP 404)",
                f"Verify the {src} resource and configuration exist")
    elif '429' in raw_error:
        return (f"Could not connect to {src}: Rate limited (HTTP 429)",
                "Retry the request after waiting")
    elif '500' in raw_error or '502' in raw_error or '503' in raw_error:
        return (f"Could not connect to {src}: Service unavailable (HTTP 5xx)",
                f"{src} may be temporarily unavailable, retry later")
    elif 'timeout' in raw_lower:
        return (f"Could not connect to {src}: Request timed out",
                "Check network connectivity and retry")
    elif 'connection' in raw_lower:
        return (f"Could not connect to {src}: Connection failed",
                "Check network connectivity and firewall settings")
    else:
        clean = raw_error[:80] + "..." if len(raw_error) > 80 else raw_error
        return (f"Could not connect to {src}: {clean}",
                f"Check {src} credentials and configuration")

def transform(input):
    criteriaKey = "authTypesAllowed"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        # A body that decodes to nothing carries no evidence either way.
        if data in (None, {}, [], ""):
            return create_response(
                result={criteriaKey: False, "authTypes": []},
                validation={"status": "error", "errors": ["the vendor returned no data to evaluate"], "warnings": []},
                api_errors=["the vendor returned no data to evaluate"],
            )

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False, "authTypes": []},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )


        # Check for API error (e.g., OAuth failure)
        if isinstance(data, dict) and 'PSError' in data:
            api_error, recommendation = parse_api_error(data.get('PSError', ''), source="Microsoft 365")
            return create_response(
                result={criteriaKey: False},
                validation={"status": "skipped", "errors": [], "warnings": ["API returned error"]},
                api_errors=[api_error],
                fail_reasons=["Could not retrieve data from Microsoft 365"],
                recommendations=[recommendation]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # FAIL CLOSED ON A BODY THAT IS NOT THE POLICY. This used to default
        # `authenticationMethodConfigurations` to `[]`, and "no insecure authentication
        # method is enabled" is vacuously true of the empty set -- so a Graph error envelope,
        # a 401/403, or a response to some other call produced zero enabled methods and
        # reported the criterion satisfied.
        #
        # The shape read is Microsoft Graph GET /v1.0/policies/authenticationMethodsPolicy,
        # whose 200 body carries `authenticationMethodConfigurations` as an array of
        # configuration objects, each with `id` and `state` ("enabled"/"disabled")
        # (https://learn.microsoft.com/en-us/graph/api/authenticationmethodspolicy-get).
        # Graph returns a configuration object for every method it knows about, enabled or
        # not, so an empty array means this is not the policy. Anything without a non-empty
        # array routes to dataCollection.status="error": the policy was never read, so the
        # absence of an insecure method is not evidence that none is enabled.
        auth_configs = data.get('authenticationMethodConfigurations') if isinstance(data, dict) else None
        if not isinstance(auth_configs, list) or not auth_configs:
            return create_response(
                result={criteriaKey: False, "authTypes": []},
                validation=validation,
                api_errors=[("no authenticationMethodConfigurations array in the "
                             "authenticationMethodsPolicy response: the authentication "
                             "methods policy was never read, so the absence of an insecure "
                             "method is not evidence that none is enabled")])

        # Find enabled authentication methods
        enabled_methods = [
            {
                "id": obj.get('id', ''),
                "state": obj.get('state', 'enabled'),
                "includeTargets": obj.get('includeTargets', [])
            }
            for obj in auth_configs
            if obj.get('state', '').lower() == "enabled"
        ]

        # Filter to find non-secure auth types (anything other than FIDO2 or Microsoft Authenticator)
        secure_methods = ['fido2', 'microsoftauthenticator']
        insecure_methods = [
            auth_type for auth_type in enabled_methods
            if auth_type['id'].lower() not in secure_methods
        ]

        # Pass if no insecure methods are enabled
        is_allowed = len(insecure_methods) == 0
        migration = str(data.get('policyMigrationState') or '').strip()
        summary = {"totalEnabledMethods": len(enabled_methods), "insecureMethods": len(insecure_methods),
                   "policyMigrationState": migration[:40]}

        # A pass is only evidence when this policy is the one in force. With nothing enabled here
        # the methods members use are set elsewhere (typically the legacy per-user MFA and SSPR
        # policies while policyMigrationState is preMigration or migrationInProgress), and until
        # the state is migrationComplete Microsoft still applies those legacy policies, which can
        # allow SMS, voice or other methods this endpoint cannot read. Either way: not evaluated.
        # An insecure method enabled here still fails in any state, because a method enabled in
        # either policy can be used. A policy that reports no state (missing, null or empty) does
        # not show the migration is complete either, so a clean list is not evaluated too.
        if is_allowed and not enabled_methods:
            reason = "No authentication method is enabled in the authentication methods policy"
            if migration:
                reason += f" (policyMigrationState: {migration[:40]})"
            return create_response(
                result={criteriaKey: False, "authTypes": []},
                validation=validation, input_summary=summary,
                api_errors=[reason + ": the methods members can use are not set by this policy, so it is "
                            "not evidence either way"])
        if is_allowed and not migration:
            return create_response(
                result={criteriaKey: False, "authTypes": []},
                validation=validation, input_summary=summary,
                api_errors=["Only secure authentication methods are enabled in the authentication methods "
                            "policy (" + ", ".join(str(m['id'])[:60] for m in enabled_methods[:5]) + "), but "
                            "the migration state was not reported (no policyMigrationState): the legacy "
                            "per-user MFA and SSPR policies may still apply, may allow SMS, voice or other "
                            "methods, and cannot be read here"])
        if is_allowed and migration.lower() != "migrationcomplete":
            return create_response(
                result={criteriaKey: False, "authTypes": []},
                validation=validation, input_summary=summary,
                api_errors=["Only secure authentication methods are enabled in the authentication methods "
                            "policy (" + ", ".join(str(m['id'])[:60] for m in enabled_methods[:5]) + "), but "
                            f"policyMigrationState is {migration[:40]} (not migrationComplete): the legacy "
                            "per-user MFA and SSPR policies still apply, may allow SMS, voice or other "
                            "methods, and cannot be read here"])

        if is_allowed:
            method_names = [m['id'] for m in enabled_methods[:5]]
            pass_reasons.append(f"Only secure authentication methods enabled: {', '.join(method_names)}")
        else:
            insecure_names = [m['id'] for m in insecure_methods[:5]]
            fail_reasons.append(f"Insecure authentication methods enabled: {', '.join(insecure_names)}")
            recommendations.append("Disable legacy authentication methods and use only FIDO2 or Microsoft Authenticator")

        return create_response(
            result={criteriaKey: is_allowed, "authTypes": insecure_methods},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=summary
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False, "authTypes": []},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
