"""
Transformation: isSSOEnabled (Microsoft Entra ID)
Vendor: Microsoft
Category: Identity

Evaluates whether the Microsoft 365 tenant uses single sign-on for its applications.

WHY THIS FILE EXISTS. isssoenabled.py beside it reads GET /identity/identityProviders and
passes on any non-empty list. That endpoint describes how GUESTS sign in (B2B direct
federation, B2C, social logins), not workforce SSO, and every Entra tenant lists the
built-in AADSignup, MicrosoftAccount and EmailOTP providers there. So that check passes
every tenant whatever its SSO posture (a false pass, measured 2026-09-25: every recorded
pass listed only built-in providers), and it says nothing about whether Entra is the SSO
identity provider for the tenant's applications. This file never treats identityProviders
data as evidence.

WHAT "SSO ENABLED" MEANS HERE. The tenant is satisfied when there is direct evidence that
users sign in to applications through a central identity provider:

  1. at least one enabled, customer-configured enterprise application (servicePrincipal)
     has preferredSingleSignOnMode "saml", "oidc" or "password" -- Entra is acting as the
     SSO identity provider for that app; OR
  2. at least one tenant domain has authenticationType "Federated" -- sign-in for that
     domain is federated to an external identity provider (ADFS, Okta, Ping, ...).

Microsoft first-party service principals are ignored: they exist in every tenant and say
nothing about the customer's configuration.

INPUT. Either source alone, or both merged by a two-step workflow:

    {"servicePrincipals": <Graph list body>, "domains": <Graph list body>}

where a Graph list body is {"value": [...]} from
    GET /v1.0/servicePrincipals?$select=id,appId,displayName,preferredSingleSignOnMode,
        accountEnabled,appOwnerOrganizationId,servicePrincipalType&$top=999
    GET /v1.0/domains?$select=id,authenticationType,isVerified
A bare Graph list body is also accepted; its rows are classified by their fields.

FAIL CLOSED. An empty, null, unrecognised or error body (PSError, Graph {"error": {...}},
an HTTP 4xx/5xx envelope, an IS error status) returns isSSOEnabled = false together with a
dataCollection or transformation error -- never a silent pass. Every tenant has at least
one service principal and at least one domain, so an empty list is a failed read, not an
answer. A source that errored while the other shows no SSO is reported as an error too,
because the false may then be incomplete.
"""

import json
from datetime import datetime


# ============================================================================
# Response Helpers (inline for RestrictedPython compatibility)
# ============================================================================

def extract_input(input_data):
    """Extract data and validation from input, handling both new and legacy formats."""
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]

    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return unwrap(input_data), validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Create a standardized transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}

    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
        "transformationId": "isSSOEnabled",
        "vendor": "Microsoft",
        "category": "Identity",
    }
    if metadata:
        response_metadata.update(metadata)

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
                "additionalFindings": additional_findings or [],
            },
            "metadata": response_metadata,
        },
    }


# ============================================================================
# Transformation Logic
# ============================================================================

CRITERIA_KEY = "isSSOEnabled"
SOURCE = "Microsoft Graph"
SSO_MODES = ["saml", "oidc", "password"]
#: tenants that own Microsoft first-party applications (Microsoft Services, Microsoft corp)
MICROSOFT_OWNER_TENANTS = [
    "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
    "72f988bf-86f1-41af-91ab-2d7cd011db47",
]
WRAPPER_KEYS = ["api_response", "apiResponse", "response", "result", "Output", "rawResponse"]
ERROR_STATUSES = ["error", "failure", "failed", "not available"]
#: providers every Entra tenant lists under /identity/identityProviders
BUILT_IN_PROVIDERS = ["AADSignup", "MicrosoftAccount", "EmailOTP", "Facebook", "Google"]


def unwrap(data):
    """Peel engine wrappers ({"apiResponse": ...}, {"Output": ...}) off a body."""
    for depth in range(4):
        if not isinstance(data, dict):
            return data
        found = None
        for key in WRAPPER_KEYS:
            if key in data and isinstance(data.get(key), (dict, list)):
                found = key
                break
        if found is None:
            return data
        data = data[found]
    return data


def parse_api_error(raw_error, source=None):
    """Parse a raw API error into a clean message and a recommendation."""
    raw_text = str(raw_error or "")
    raw_lower = raw_text.lower()
    src = source or "external service"

    if "401" in raw_text or "invalidauthenticationtoken" in raw_lower:
        return (f"Could not connect to {src}: Authentication failed (HTTP 401)",
                f"Verify {src} credentials and permissions are valid")
    if "403" in raw_text or "authorization_requestdenied" in raw_lower or "forbidden" in raw_lower:
        return (f"Could not connect to {src}: Access denied (HTTP 403)",
                "Grant the integration Application.Read.All and Domain.Read.All "
                "(or Directory.Read.All) and re-consent the tenant")
    if "404" in raw_text:
        return (f"Could not connect to {src}: Resource not found (HTTP 404)",
                f"Verify the {src} resource and configuration exist")
    if "429" in raw_text:
        return (f"Could not connect to {src}: Rate limited (HTTP 429)",
                "Retry the request after waiting")
    if "500" in raw_text or "502" in raw_text or "503" in raw_text:
        return (f"Could not connect to {src}: Service unavailable (HTTP 5xx)",
                f"{src} may be temporarily unavailable, retry later")
    if "timeout" in raw_lower:
        return (f"Could not connect to {src}: Request timed out",
                "Check network connectivity and retry")
    if "connection" in raw_lower:
        return (f"Could not connect to {src}: Connection failed",
                "Check network connectivity and firewall settings")

    clean = raw_text[:80] + "..." if len(raw_text) > 80 else raw_text
    return (f"Could not connect to {src}: {clean}",
            f"Check {src} credentials and configuration")


def error_text(body):
    """Return the raw error text if this body is an error, else None."""
    if not isinstance(body, dict):
        return None
    if "PSError" in body:
        return str(body.get("PSError") or "PSError")
    err = body.get("error")
    if isinstance(err, dict):
        code = str(err.get("code") or err.get("statusCode") or "")
        message = str(err.get("message") or "")
        return (code + " " + message).strip() or "error"
    if isinstance(err, str) and err:
        code = body.get("statusCode", body.get("status_code", ""))
        return (str(code) + " " + err).strip()
    for key in ["statusCode", "status_code"]:
        code = body.get(key)
        if isinstance(code, int) and code >= 400:
            return str(code) + " " + str(body.get("message") or "")
    status = body.get("status")
    if isinstance(status, str) and status.lower() in ERROR_STATUSES:
        return str(body.get("message") or body.get("errorMessage") or status)
    return None


def rows_of(body):
    """The `value` list of a Graph list body, or None when the body is not one."""
    body = unwrap(body)
    if isinstance(body, list):
        return body
    if isinstance(body, dict) and isinstance(body.get("value"), list):
        return body["value"]
    return None


def is_service_principal(row):
    return isinstance(row, dict) and (
        "preferredSingleSignOnMode" in row or "servicePrincipalType" in row or "appOwnerOrganizationId" in row
    )


def is_identity_provider(row):
    """A row of GET /identity/identityProviders (built-in, social or B2B federation)."""
    if not isinstance(row, dict):
        return False
    odata_type = str(row.get("@odata.type") or "").lower()
    return "identityprovider" in odata_type or "identityProviderType" in row or (
        str(row.get("type") or "") in BUILT_IN_PROVIDERS
    )


def is_domain(row):
    return isinstance(row, dict) and "authenticationType" in row


def sso_apps(rows):
    """Enabled, customer-configured service principals whose SSO mode is saml/oidc/password."""
    found = []
    for row in rows:
        if not is_service_principal(row):
            continue
        mode = str(row.get("preferredSingleSignOnMode") or "").lower()
        if mode not in SSO_MODES:
            continue
        if row.get("accountEnabled") is False:
            continue
        owner = str(row.get("appOwnerOrganizationId") or "").lower()
        if owner in MICROSOFT_OWNER_TENANTS:
            continue
        found.append(row)
    return found


def federated_domains(rows):
    return [
        row for row in rows
        if is_domain(row) and str(row.get("authenticationType") or "").lower() == "federated"
    ]


def collect(data):
    """Split the input into service-principal rows, domain rows, and per-source errors."""
    sp_rows = None
    domain_rows = None
    api_errors = []
    recommendations = []

    def note_error(raw, label):
        message, recommendation = parse_api_error(raw, source=SOURCE + " " + label)
        api_errors.append(message)
        if recommendation not in recommendations:
            recommendations.append(recommendation)

    top_error = error_text(data)
    if top_error is not None:
        note_error(top_error, "")
        return None, None, api_errors, recommendations

    if isinstance(data, dict) and ("servicePrincipals" in data or "domains" in data):
        for label in ["servicePrincipals", "domains"]:
            if label not in data:
                continue
            part = unwrap(data.get(label))
            part_error = error_text(part)
            if part_error is not None:
                note_error(part_error, "/" + label)
                continue
            rows = rows_of(part)
            if rows is None:
                api_errors.append(f"{SOURCE} /{label} returned an unrecognised body")
                continue
            if label == "servicePrincipals":
                sp_rows = rows
            else:
                domain_rows = rows
        return sp_rows, domain_rows, api_errors, recommendations

    rows = rows_of(data)
    if rows is None:
        return None, None, api_errors, recommendations
    sp_rows = [row for row in rows if is_service_principal(row)]
    domain_rows = [row for row in rows if is_domain(row)]
    if len(rows) > 0 and len(sp_rows) == 0 and len(domain_rows) == 0:
        if len([row for row in rows if is_identity_provider(row)]) > 0:
            # /identity/identityProviders: every tenant lists the built-in AADSignup,
            # MicrosoftAccount and EmailOTP providers there, and any others are for
            # B2B/B2C guests. None of it shows workforce SSO, so it is never evidence.
            api_errors.append(
                "Input is a Microsoft Graph identityProviders list, which describes guest "
                "sign-in providers and is not evidence of single sign-on"
            )
        # rows of some other Graph resource: no evidence either way
        return None, None, api_errors, recommendations
    if len(sp_rows) == 0:
        sp_rows = None if len(domain_rows) > 0 else sp_rows
    if len(domain_rows) == 0:
        domain_rows = None if sp_rows else domain_rows
    return sp_rows, domain_rows, api_errors, recommendations


def transform(input):
    """Evaluate whether SSO is in use in the Microsoft Entra ID tenant."""
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={CRITERIA_KEY: False},
                validation=validation,
                fail_reasons=["Input validation failed: " + "; ".join(validation.get("errors", []))],
                recommendations=["Verify the Microsoft integration is configured correctly"],
            )

        sp_rows, domain_rows, api_errors, recommendations = collect(data)

        if sp_rows is None and domain_rows is None:
            if api_errors:
                return create_response(
                    result={CRITERIA_KEY: False},
                    validation=validation,
                    api_errors=api_errors,
                    fail_reasons=["Could not retrieve service principal or domain data from Microsoft Graph"],
                    recommendations=recommendations,
                )
            return create_response(
                result={CRITERIA_KEY: False},
                validation=validation,
                transformation_errors=[
                    "Input carries no Microsoft Graph servicePrincipals or domains data"
                ],
                fail_reasons=["No evidence about SSO configuration was received"],
                recommendations=[
                    "Wire isSSOEnabled to the servicePrincipals and domains Graph methods"
                ],
            )

        sp_list = sp_rows or []
        domain_list = domain_rows or []
        if len(sp_list) == 0 and len(domain_list) == 0:
            return create_response(
                result={CRITERIA_KEY: False},
                validation=validation,
                api_errors=api_errors + [
                    "Microsoft Graph returned no service principals and no domains; "
                    "every tenant has both, so the read is incomplete"
                ],
                fail_reasons=["No evidence about SSO configuration was received"],
                recommendations=recommendations + [
                    "Verify the integration can read /servicePrincipals and /domains"
                ],
            )

        apps = sso_apps(sp_list)
        federated = federated_domains(domain_list)
        is_enabled = len(apps) > 0 or len(federated) > 0

        pass_reasons = []
        fail_reasons = []
        if len(apps) > 0:
            names = [str(app.get("displayName") or app.get("appId") or "unnamed") for app in apps[:5]]
            pass_reasons.append(
                f"{len(apps)} enterprise application(s) use Entra ID single sign-on: {', '.join(names)}"
            )
        if len(federated) > 0:
            names = [str(row.get("id") or "unnamed") for row in federated[:5]]
            pass_reasons.append(
                f"{len(federated)} domain(s) federated to an external identity provider: {', '.join(names)}"
            )
        if not is_enabled:
            fail_reasons.append(
                "No enterprise application is configured for SAML, OIDC or password single "
                "sign-on, and no domain is federated"
            )
            recommendations.append(
                "Configure single sign-on for enterprise applications in Microsoft Entra ID "
                "(Enterprise applications > Single sign-on)"
            )
            if sp_rows is None:
                api_errors.append("Service principal data was not available; SSO apps could not be checked")
            elif domain_rows is None and len(api_errors) > 0:
                api_errors.append("Domain data was not available; federation could not be checked")

        modes = {}
        for row in sp_list:
            if is_service_principal(row):
                mode = str(row.get("preferredSingleSignOnMode") or "none").lower()
                modes[mode] = modes.get(mode, 0) + 1

        return create_response(
            result={
                CRITERIA_KEY: is_enabled,
                "ssoApplicationCount": len(apps),
                "federatedDomainCount": len(federated),
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations if not is_enabled else [],
            api_errors=api_errors if not is_enabled else [],
            additional_findings=api_errors if is_enabled else [],
            input_summary={
                "servicePrincipalCount": len(sp_list),
                "domainCount": len(domain_list),
                "servicePrincipalsReceived": sp_rows is not None,
                "domainsReceived": domain_rows is not None,
                "singleSignOnModes": modes,
            },
        )

    except json.JSONDecodeError as error:
        return create_response(
            result={CRITERIA_KEY: False},
            validation={"status": "unknown", "errors": [f"Invalid JSON: {str(error)}"], "warnings": []},
            transformation_errors=["Could not parse input as valid JSON"],
            fail_reasons=["Could not parse input as valid JSON"],
        )
    except Exception as error:
        return create_response(
            result={CRITERIA_KEY: False},
            validation={"status": "unknown", "errors": [], "warnings": []},
            transformation_errors=[str(error)],
            fail_reasons=[f"Transformation error: {str(error)}"],
        )
