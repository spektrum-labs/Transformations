"""
Transformation: isAdminMFAPhishingResistant
Vendor: Microsoft (Azure AD, d9b6f27a)
Category: Identity

Requirement asked: "Only phishing-resistant MFA for admins." Two Graph bodies are understood:

1. GET /v1.0/policies/authenticationMethodsPolicy (getAuthenticationMethodsPolicy; Policy.Read.All, already granted).
   This is the body that can answer the question. Same reading as Okta isAdminMFAPhishingResistant:
   - no phishing-resistant method (Fido2 incl. passkeys, X509Certificate in multi-factor mode) enabled -> False:
     admins cannot be limited to phishing-resistant MFA;
   - phishing-resistant methods only (no phishable member method, no external method, policyMigrationState
     migrationComplete) -> True. A TAP with a maximum lifetime is allowed (J.J.'s ruling as applied in #833);
     single-factor certificate auth counts as phishable; an unknown certificate mode reads None;
   - phishing-resistant AND phishable methods enabled -> None: whether admins are restricted is set by a
     Conditional Access authentication strength, which this body does not carry
     (isCAAuthStrengthPhishingResistantRequired is that check);
   - external method, any migration state but migrationComplete, a next-page link, a partial or error body -> None.
   Email OTP that targets only guests (includeTargets []) cannot reach an admin, so it is a finding here.

2. GET /v1.0/security/secureScores?$top=1 (getRecentSecureScores, the current wiring), control AdminMFAV2.
   AdminMFAV2 measures whether admin-role members are protected by MFA of ANY kind. Until 3 Oct 2026 a 100%
   score read True, which called push and SMS "phishing-resistant" (AT-2 follow-up 3). Now:
   - score below 100% -> False: some admins have no MFA at all, so they are not all on phishing-resistant MFA;
   - score 100% -> None: every admin has MFA, but its kind is not in this body;
   - no score, no AdminMFAV2 control, an ambiguous match, an API error or PSError -> None (not evaluated).
   This file never returns True from Secure Score.
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
                "transformationId": "isAdminMFAPhishingResistant",
                "vendor": "Microsoft",
                "category": "Identity"
            }
        }
    }


def parse_api_error(raw_error, source=None):
    raw_error = raw_error or ""
    raw_lower = raw_error.lower()
    src = source or "external service"

    if "401" in raw_error:
        return (
            f"Could not connect to {src}: Authentication failed (HTTP 401)",
            f"Verify {src} credentials and permissions are valid",
        )
    elif "403" in raw_error:
        return (
            f"Could not connect to {src}: Access denied (HTTP 403)",
            f"Verify the integration has required {src} permissions",
        )
    elif "404" in raw_error:
        return (
            f"Could not connect to {src}: Resource not found (HTTP 404)",
            f"Verify the {src} resource and configuration exist",
        )
    elif "429" in raw_error:
        return (
            f"Could not connect to {src}: Rate limited (HTTP 429)",
            "Retry the request after waiting",
        )
    elif "500" in raw_error or "502" in raw_error or "503" in raw_error:
        return (
            f"Could not connect to {src}: Service unavailable (HTTP 5xx)",
            f"{src} may be temporarily unavailable, retry later",
        )
    elif "timeout" in raw_lower:
        return (
            f"Could not connect to {src}: Request timed out",
            "Check network connectivity and retry",
        )
    elif "connection" in raw_lower:
        return (
            f"Could not connect to {src}: Connection failed",
            "Check network connectivity and firewall settings",
        )
    else:
        clean = raw_error[:80] + "..." if len(raw_error) > 80 else raw_error
        return (
            f"Could not connect to {src}: {clean}",
            f"Check {src} credentials and configuration",
        )


def as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def as_number(value, default=0):
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        try:
            number = float(value)
            return int(number) if number.is_integer() else number
        except ValueError:
            return default
    return default


RESISTANT = {"fido2": "FIDO2 security key / passkey", "x509certificate": "Certificate-based authentication"}
COMPLETE_STATE = "migrationcomplete"
CBA_MULTI = "x509certificatemultifactor"
CBA_SINGLE = "x509certificatesinglefactor"
STATES = ("enabled", "disabled")
CRITERIA_KEY = "isAdminMFAPhishingResistant"
CONTROL_NAME = "AdminMFAV2"


def unevaluated(message, validation=None, summary=None, findings=None, extra=None):
    result = {CRITERIA_KEY: None}
    if extra:
        result.update(extra)
    return create_response(
        result=result,
        validation=validation or {"status": "error", "errors": [message], "warnings": []},
        api_errors=[message],
        fail_reasons=[message],
        input_summary=summary or {},
        additional_findings=findings or [],
    )


def method_id(config):
    return str(config.get("id") or "").lower()


def cba_mode(config):
    """'multi', 'single' or 'unknown' for an X509Certificate configuration (authenticationModeConfiguration)."""
    mode_cfg = config.get("authenticationModeConfiguration")
    if not isinstance(mode_cfg, dict):
        return "unknown"
    rules = mode_cfg.get("rules")
    if rules is None:
        rules = []
    if not isinstance(rules, list):
        return "unknown"
    modes = [str(mode_cfg.get("x509CertificateAuthenticationDefaultMode") or "").lower()]
    for rule in rules:
        if not isinstance(rule, dict):
            return "unknown"
        modes.append(str(rule.get("x509CertificateAuthenticationMode") or "").lower())
    if any(m == CBA_SINGLE for m in modes):
        return "single"
    if all(m == CBA_MULTI for m in modes):
        return "multi"
    return "unknown"


def from_methods_policy(data, validation):
    if data.get("@odata.nextLink") or data.get("authenticationMethodConfigurations@odata.nextLink"):
        return unevaluated("The authentication methods policy carries a next-page link, so the method list is partial",
                           validation)
    configs = data.get("authenticationMethodConfigurations")
    if not isinstance(configs, list) or not configs:
        return unevaluated("No authenticationMethodConfigurations array: the authentication methods policy was not read",
                           validation)
    for config in configs:
        if (not isinstance(config, dict) or not method_id(config)
                or str(config.get("state") or "").lower() not in STATES):
            return unevaluated("The authentication methods policy is incomplete: a method configuration has no id or "
                               "no enabled/disabled state", validation)
    resistant, phishable, external, findings, cba_unknown = [], [], [], [], []
    for config in configs:
        if str(config.get("state")).lower() != "enabled":
            continue
        mid = method_id(config)
        name = str(config.get("displayName") or config.get("id"))[:60]
        targets = config.get("includeTargets")
        no_targets = isinstance(targets, list) and not targets
        if "externalauthenticationmethodconfiguration" in str(config.get("@odata.type") or "").lower():
            external.append(name)
        elif mid == "x509certificate":
            mode = cba_mode(config)
            if mode == "multi":
                resistant.append(RESISTANT[mid])
            elif mode == "single":
                phishable.append("X509Certificate (single-factor mode)")
            else:
                cba_unknown.append(name)
        elif mid in RESISTANT:
            resistant.append(RESISTANT[mid])
        elif mid == "temporaryaccesspass":
            try:
                bounded = int(config.get("maximumLifetimeInMinutes")) > 0
            except (ValueError, TypeError):
                bounded = False
            if bounded:
                findings.append("Temporary Access Pass is enabled with a maximum lifetime (onboarding/recovery credential)")
            else:
                phishable.append(name)
        elif no_targets:
            findings.append(name + " is enabled but targets no member (guests only or no one); it cannot reach an admin")
        else:
            phishable.append(name)
    migration = str(data.get("policyMigrationState") or "")[:40]
    summary = {"source": "authenticationMethodsPolicy", "enabledPhishResistantMethods": resistant,
               "enabledPhishableMethods": phishable, "enabledExternalMethods": external,
               "policyMigrationState": migration}
    if cba_unknown:
        return unevaluated("Certificate-based authentication is enabled but its authenticationModeConfiguration "
                           "(single- or multi-factor) is missing or unrecognised, so it cannot be graded",
                           validation, summary, findings)
    if not resistant:
        if external and not phishable:
            return unevaluated("No phishing-resistant Microsoft method is enabled; the external method(s) "
                               + ", ".join(external) + " cannot be graded from Entra", validation, summary, findings)
        return create_response(
            result={CRITERIA_KEY: False, "enabledPhishResistantMethods": resistant, "enabledPhishableMethods": phishable},
            validation=validation, input_summary=summary, additional_findings=findings,
            fail_reasons=["No phishing-resistant method (FIDO2 / passkeys or certificate-based authentication) is enabled "
                          "in the authentication methods policy, so admins cannot be limited to phishing-resistant MFA"
                          + ("; enabled: " + ", ".join(phishable) if phishable else "")],
            recommendations=["Enable FIDO2 security keys / passkeys or certificate-based authentication and require a "
                             "phishing-resistant authentication strength for admin roles in Conditional Access"])
    if phishable:
        return unevaluated("Phishing-resistant method(s) " + ", ".join(resistant) + " and phishable method(s) "
                           + ", ".join(phishable) + " are both enabled; whether admins are limited to the "
                           "phishing-resistant ones is set by a Conditional Access authentication strength, which this "
                           "policy does not show", validation, summary, findings)
    if external:
        return unevaluated("The external authentication method(s) " + ", ".join(external)
                           + " are enabled and cannot be graded from Entra", validation, summary, findings)
    if migration.lower() != COMPLETE_STATE:
        return unevaluated("Only phishing-resistant methods are enabled, but policyMigrationState is "
                           + (migration or "not reported") + " (not migrationComplete): the legacy per-user MFA and "
                           "SSPR policies may still apply and cannot be read here", validation, summary, findings)
    return create_response(
        result={CRITERIA_KEY: True, "enabledPhishResistantMethods": resistant, "enabledPhishableMethods": []},
        validation=validation, input_summary=summary, additional_findings=findings,
        pass_reasons=["Only phishing-resistant methods are enabled in the tenant (" + ", ".join(resistant)
                      + "), so admins can authenticate only with phishing-resistant MFA"])


def from_secure_score(data, validation):
    extra = {"scoreInPercentage": None, "count": None, "total": None}
    values = as_list(data.get("value"))
    if not values or not isinstance(values[0], dict):
        return unevaluated("Microsoft Secure Score data not available", validation, extra=extra)
    matched = [e for e in as_list(values[0].get("controlScores"))
               if isinstance(e, dict) and e.get("controlName") == CONTROL_NAME]
    if len(matched) != 1:
        return unevaluated(("Ambiguous data: " + str(len(matched)) + " objects match" if matched else "No")
                           + " Secure Score control " + CONTROL_NAME, validation, extra=extra)
    score = as_number(matched[0].get("scoreInPercentage"), None)
    count = as_number(matched[0].get("count"), 0)
    total = as_number(matched[0].get("total"), 0)
    summary = {"source": "secureScores", "hasSecureScoreData": True, "scoreInPercentage": score,
               "protectedCount": count, "totalCount": total}
    if not isinstance(score, (int, float)) or score < 0 or score > 100:
        return unevaluated("Secure Score control " + CONTROL_NAME + " has no usable scoreInPercentage", validation, summary,
                           extra=extra)
    if score < 100:
        return create_response(
            result={CRITERIA_KEY: False, "scoreInPercentage": score, "count": count, "total": total},
            validation=validation, input_summary=summary,
            fail_reasons=["Secure Score " + CONTROL_NAME + " is " + str(score) + "%: some admin-role members are not "
                          "protected by MFA at all, so admins are not limited to phishing-resistant MFA"],
            recommendations=["Require a phishing-resistant authentication strength for every admin role in "
                             "Conditional Access"])
    return unevaluated("Secure Score " + CONTROL_NAME + " is 100%: every admin is protected by MFA, but this score "
                       "does not show whether that MFA is phishing-resistant", validation, summary,
                       extra={"scoreInPercentage": score, "count": count, "total": total})


def transform(input):
    try:
        if isinstance(input, (str, bytes)):
            input = json.loads(input.decode("utf-8") if isinstance(input, bytes) else input)
        data, validation = extract_input(input)
        if not isinstance(data, dict):
            return unevaluated("Unexpected input format: expected a JSON object", validation)
        if "PSError" in data:
            api_error, recommendation = parse_api_error(str(data.get("PSError") or ""), source="Microsoft 365")
            return unevaluated(api_error, validation)
        if validation.get("status") == "failed":
            return unevaluated("Input validation failed", validation)
        if "error" in data:
            error_info = data.get("error") if isinstance(data.get("error"), dict) else {}
            return unevaluated("Microsoft Graph API error: " + str(error_info.get("code") or "unknown")[:80], validation)
        if "authenticationMethodConfigurations" in data:
            return from_methods_policy(data, validation)
        return from_secure_score(data, validation)
    except Exception as e:
        return unevaluated("Transformation error: " + str(e)[:200])
