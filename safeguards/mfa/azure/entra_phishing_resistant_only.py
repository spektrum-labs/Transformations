"""isPhishingResistantOnlyEnabled for Microsoft Entra ID (Azure AD and Azure AD One-Click), from the authentication
methods policy: GET /v1.0/policies/authenticationMethodsPolicy. That is the One-Click method getEstateMFAStatus and
the Azure AD method getAuthenticationMethodsPolicy. Both read the same Graph body, which needs Policy.Read.All
(already granted for isStrongAuthRequired and authTypesAllowed), so no new permission is involved.

Requirement asked: "Only phishing-resistant MFA is enabled" (CSP-001, CMMC IA.L2-3.5.4).

Why a new key: isStrongAuthRequired (entra_strongauth_methods.py) is True when ANY phishing-resistant method is
enabled, so "FIDO2 + SMS" passes it. Bundles 184dad1f, d349f8e9 and 133571e9 read that key as "strong auth
required", so its meaning stays. This key is the strict one.

Value:
- True: the policy was read, policyMigrationState is migrationComplete, a phishing-resistant method is enabled
  (FIDO2 security keys and passkeys, including passkeys in Microsoft Authenticator, which Entra configures under
  Fido2; or certificate-based authentication, X509Certificate, in MULTI-FACTOR mode), NO phishable method is
  enabled and no external method is enabled.
- False: the policy was read and a phishable method is enabled: Microsoft Authenticator (push, number match or
  phone sign-in), SMS, voice, email OTP, software or hardware OATH, a Temporary Access Pass with no maximum
  lifetime, certificate-based authentication in single-factor mode (default mode or any rule), or any method id
  this file does not know.
  - Email OTP counts even when it targets nobody but guests (includeTargets []). J.J., 3 Oct 2026 00:55 ET:
    guest-only email OTP FAILS (same rule as authtypesallowed.py, TX #833).
- None (not evaluated, dataCollection.status "error"):
  - an error, empty, partial or unrecognised body (no non-empty authenticationMethodConfigurations array, or a
    configuration without an id or a recognised state);
  - no phishable method, but an external method (for example Cisco Duo) is enabled: its factors cannot be graded
    from Entra;
  - no phishable method and no phishing-resistant member method (nothing enabled, or only a time-limited TAP);
  - no phishable method, but policyMigrationState is anything other than migrationComplete (preMigration,
    migrationInProgress, missing or unknown): the legacy per-user MFA and SSPR policies may still apply and this
    endpoint cannot read them;
  - certificate-based authentication is enabled and its authenticationModeConfiguration is missing or unknown.

Allowed and reported as a finding, never a fail: a Temporary Access Pass with a maximum lifetime (onboarding and
recovery credential; J.J.'s ruling as applied in authtypesallowed.py, TX #833 -- a TAP without one fails), and a
non-email method that is enabled but targets no one (includeTargets []).
Windows Hello for Business is phishing-resistant but is not a method in this policy; it does not change the result.
Conditional Access authentication strength (what sign-in actually requires) is a separate key.
"""

import json
from datetime import datetime


CRITERIA_KEY = "isPhishingResistantOnlyEnabled"
RESISTANT = {"fido2": "FIDO2 security key / passkey", "x509certificate": "Certificate-based authentication"}
COMPLETE_STATE = "migrationcomplete"
CBA_MULTI = "x509certificatemultifactor"
CBA_SINGLE = "x509certificatesinglefactor"
STATES = ("enabled", "disabled")


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


def create_response(result, validation, errors=(), passed=(), failed=(), findings=(), recommendations=(), summary=None):
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
                "recommendations": list(recommendations),
                "additionalFindings": list(findings),
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


def method_id(config):
    return str(config.get("id") or "").lower()


def label(config):
    return str(config.get("displayName") or config.get("id") or "method")[:60]


def is_external(config):
    return "externalauthenticationmethodconfiguration" in str(config.get("@odata.type") or "").lower()


def targets_no_one(config):
    targets = config.get("includeTargets")
    return isinstance(targets, list) and not targets


def bounded_tap(config):
    if method_id(config) != "temporaryaccesspass":
        return False
    try:
        return int(config.get("maximumLifetimeInMinutes")) > 0
    except (ValueError, TypeError):
        return False


def cba_mode(config):
    """'multi', 'single' or 'unknown' for an X509Certificate configuration (authenticationModeConfiguration)."""
    mode_cfg = config.get("authenticationModeConfiguration")
    if not isinstance(mode_cfg, dict):
        return "unknown"
    default = str(mode_cfg.get("x509CertificateAuthenticationDefaultMode") or "").lower()
    rules = mode_cfg.get("rules")
    if rules is None:
        rules = []
    if not isinstance(rules, list):
        return "unknown"
    modes = [default]
    for rule in rules:
        if not isinstance(rule, dict):
            return "unknown"
        modes.append(str(rule.get("x509CertificateAuthenticationMode") or "").lower())
    if any(m == CBA_SINGLE for m in modes):
        return "single"
    if all(m == CBA_MULTI for m in modes):
        return "multi"
    return "unknown"


def not_evaluated(message, validation=None, summary=None, findings=()):
    result = {CRITERIA_KEY: None}
    if summary:
        result.update(summary)
    return create_response(result, validation or {"status": "failed", "errors": [message], "warnings": []},
                           errors=[message], findings=findings, summary=summary)


def transform(input):
    try:
        data, validation = extract_input(input)
    except Exception as error:
        return not_evaluated("The authentication methods policy could not be parsed: " + str(error)[:120])
    if validation.get("status") == "failed":
        return not_evaluated("Input validation failed", validation)
    if not isinstance(data, dict) or "error" in data:
        return not_evaluated("Microsoft did not return the authentication methods policy")
    if data.get("@odata.nextLink") or data.get("authenticationMethodConfigurations@odata.nextLink"):
        return not_evaluated("The authentication methods policy carries a next-page link, so the method list is "
                             "partial")
    configs = data.get("authenticationMethodConfigurations")
    if not isinstance(configs, list) or not configs:
        return not_evaluated("No authenticationMethodConfigurations array: the authentication methods policy was not read")
    for config in configs:
        if (not isinstance(config, dict) or not method_id(config)
                or str(config.get("state") or "").lower() not in STATES):
            return not_evaluated("The authentication methods policy is incomplete: a method configuration has no id "
                                 "or no enabled/disabled state, so the set of enabled methods is not known")

    enabled = [c for c in configs if str(c.get("state")).lower() == "enabled"]
    resistant, phishable, external, taps, untargeted, cba_unknown = [], [], [], [], [], []
    guest_email = False
    for config in enabled:
        mid = method_id(config)
        if is_external(config):
            external.append(label(config))
        elif bounded_tap(config):
            taps.append(label(config))
        elif mid == "x509certificate":
            mode = cba_mode(config)
            if mode == "multi":
                resistant.append(RESISTANT[mid])
            elif mode == "single":
                phishable.append("X509Certificate (single-factor mode)")
            else:
                cba_unknown.append(label(config))
        elif mid in RESISTANT:
            resistant.append(RESISTANT[mid])
        elif mid == "email":
            phishable.append("Email" + (" (guests only)" if targets_no_one(config) else ""))
            guest_email = guest_email or targets_no_one(config)
        elif targets_no_one(config):
            untargeted.append(label(config))
        else:
            phishable.append(label(config))
    migration = str(data.get("policyMigrationState") or "")[:40]
    summary = {"enabledPhishResistantMethods": resistant, "enabledPhishableMethods": phishable,
               "enabledExternalMethods": external, "temporaryAccessPassBounded": bool(taps),
               "guestOnlyEmailOtp": guest_email, "policyMigrationState": migration}
    findings = []
    if taps:
        findings.append("Temporary Access Pass is enabled with a maximum lifetime (onboarding/recovery credential); "
                        "allowed")
    if untargeted:
        findings.append("Enabled but targeting no one, so not counted: " + ", ".join(untargeted))

    if phishable:
        result = {CRITERIA_KEY: False}
        result.update(summary)
        failed = ["Phishable authentication method(s) enabled: " + ", ".join(phishable)
                  + ("; phishing-resistant method(s) also enabled: " + ", ".join(resistant) if resistant else "")]
        if guest_email:
            failed.append("Email one-time passcode is enabled for external (guest) users; an email-based factor "
                          "allowed for any user, guests included, is not phishing-resistant")
        return create_response(result, validation, failed=failed, findings=findings, summary=summary,
                               recommendations=["Disable Microsoft Authenticator push/phone sign-in, SMS, voice, "
                                                "email OTP and OATH tokens in the authentication methods policy; keep "
                                                "FIDO2/passkeys or multi-factor certificate-based authentication only"])
    if external:
        return not_evaluated("No phishable Microsoft method is enabled, but the external authentication method(s) "
                             + ", ".join(external) + " enforce their own factors, which cannot be graded from Entra",
                             validation, summary, findings)
    if cba_unknown:
        return not_evaluated("Certificate-based authentication is enabled but its authenticationModeConfiguration "
                             "(single- or multi-factor) is missing or unrecognised, so it cannot be graded",
                             validation, summary, findings)
    if not resistant:
        return not_evaluated("No phishing-resistant or phishable member method is enabled in the authentication "
                             "methods policy" + (" (policyMigrationState: " + migration + ")" if migration else "")
                             + ": the methods members sign in with are not set by this policy, so it is not "
                             "evidence either way", validation, summary, findings)
    if migration.lower() != COMPLETE_STATE:
        return not_evaluated("Only phishing-resistant methods are enabled in the authentication methods policy, but "
                             "policyMigrationState is " + (migration or "not reported") + " (not migrationComplete): "
                             "the legacy per-user MFA and SSPR policies may still apply and cannot be read here",
                             validation, summary, findings)
    result = {CRITERIA_KEY: True}
    result.update(summary)
    return create_response(result, validation, findings=findings, summary=summary,
                           passed=["Only phishing-resistant methods are enabled: " + ", ".join(resistant)])
