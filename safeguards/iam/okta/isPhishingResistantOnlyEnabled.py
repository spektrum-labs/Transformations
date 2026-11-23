"""
Transformation: isPhishingResistantOnlyEnabled
Vendor: Okta (also Okta - Application)   Method: GET /api/v1/org/factors (listOrgFactors: every factor the org
can enroll, with its status). This is the same read as isAdminMFAPhishingResistant.py; no new Okta
permission is needed.

Requirement asked: "Only phishing-resistant MFA is enabled" (CSP-001, CMMC IA.L2-3.5.4).

Value:
- True: at least one of webauthn, u2f or smart_card is ACTIVE, NO phishable factor is ACTIVE, and Okta FastPass
  (signed_nonce) is not ACTIVE.
- False: the complete factor list was read and a phishable factor is ACTIVE (next to a phishing-resistant one or
  not), or no factor at all that could be phishing-resistant is ACTIVE. An ACTIVE phishable factor is a factor
  any user can enroll and sign in with, so the org does not allow phishing-resistant factors only.
- None (not evaluated, additionalInfo.dataCollection.status "error"):
  - Okta FastPass (signed_nonce) is ACTIVE and no phishable factor is. FastPass is phishing-resistant only when
    an authentication policy rule requires it (possession constraint phishingResistant REQUIRED); the factor
    list cannot show that, so FastPass never yields a PASS here. Proving it needs the authentication policy
    rules read (a follow-up key; it is not added here).
  - Anything that is not a COMPLETE factor list: null, {}, [], an error envelope, unrelated JSON, an unrecognised
    factor status, an enriched input whose validation status is "failed", a pagination marker (nextPage, next,
    _links.next, a Link rel="next" header, hasMore), or a list that lacks factor types every org lists
    (push, sms, token:software:totp, webauthn). /api/v1/org/factors returns every factor the org can enroll,
    ACTIVE or not, so a list without them is a partial read.

Difference from isAdminMFAPhishingResistant.py (same factor sets and read): that key asks about ADMINS, whose
factors the Admin Console policy can narrow, so a mixed list reads None there. This key asks about the whole
org, so a mixed list is a FAIL here. isStrongAuthRequired is not changed: other bundles read it as
"strong auth required".

Identity Engine (workflow getAuthenticatorPosture: GET /api/v1/authenticators -> authenticators, and
GET /api/v1/authenticators/{id}/methods -> authenticatorMethods, one list per authenticator, same order):
on an Identity Engine org /api/v1/org/factors is a frozen Classic catalogue that can disagree with what Okta
enforces, so when the input carries an authenticators list it is graded instead, and the factor list is not read:
- Phishable when ACTIVE: Phone (SMS or voice); Email or security question when allowed for sign-in; Okta Verify
  push or one-time code (totp); any OTP authenticator (Google Authenticator, custom OTP, RSA, Symantec, YubiKey
  OTP, Duo, on-prem MFA).
- Not counted: Email or security question with settings.allowedFor "recovery" (or "none"); Password.
- Phishing-resistant: WebAuthn / passkeys, smart card. Okta FastPass (Okta Verify signed_nonce) follows the
  rule above: with no phishable method it reads None.
- None: an error body, an empty or unreadable authenticator list, Okta Verify ACTIVE with an unreadable method
  list, or an ACTIVE authenticator this file does not recognise (and nothing phishable is ACTIVE).
Authenticators are recognised by key, then type, then name, because the key is not always shown.
Without an authenticators list the factor list below is graded exactly as before.

Phishing-resistant factor types (Okta factorType): webauthn (FIDO2 / WebAuthn), u2f (FIDO U2F security key),
smart_card (PIV / CAC), and signed_nonce (Okta FastPass) only under a policy that requires phishing resistance.
Every other type (push, sms, call, email, question, token:software:totp, token:hotp, token, token:hardware OTP,
web) can be relayed by a real-time phishing proxy.
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
        for attempt in range(3):
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
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_err_list else "success", "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": "error" if transform_err_list else "success",
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


PHISH_RESISTANT_TYPES = ["webauthn", "u2f", "signed_nonce", "smart_card"]
FASTPASS = "signed_nonce"
ALWAYS_LISTED = ["push", "sms", "token:software:totp", "webauthn"]
NEXT_KEYS = ["nextPage", "next", "nextLink", "@odata.nextLink", "nextCursor", "after"]
FACTOR_STATUSES = ["ACTIVE", "INACTIVE", "NOT_SETUP", "PENDING_ACTIVATION"]
KEY = "isPhishingResistantOnlyEnabled"
META = {"transformationId": KEY, "vendor": "Okta", "category": "iam"}


def factor_list(data):
    """Return the org factor list, or None when the body is not one."""
    if isinstance(data, (str, bytes)):
        try:
            data = json.loads(data.decode("utf-8") if isinstance(data, bytes) else data)
        except Exception:
            return None
    if isinstance(data, dict):
        for k in ("apiResponse", "factors", "rawResponse", "data"):
            if isinstance(data.get(k), list):
                data = data[k]
                break
    if not isinstance(data, list) or not data:
        return None
    for f in data:
        if not isinstance(f, dict) or not f.get("factorType") or f.get("status") not in FACTOR_STATUSES:
            return None
    return data


def has_more(obj):
    """True when any wrapper layer of the body carries a pagination marker (the list is one page of several)."""
    for attempt in range(6):
        if not isinstance(obj, dict):
            return False
        for k in NEXT_KEYS:
            if obj.get(k):
                return True
        if obj.get("hasMore") is True or obj.get("truncated") is True:
            return True
        links = obj.get("_links")
        if isinstance(links, dict) and links.get("next"):
            return True
        for hk in ("link", "Link", "headers"):
            hv = obj.get(hk)
            if isinstance(hv, dict):
                hv = hv.get("link") or hv.get("Link")
            if isinstance(hv, str) and 'rel="next"' in hv.replace("'", '"'):
                return True
        nested = None
        for k in ("data", "api_response", "response", "result", "apiResponse", "Output"):
            if isinstance(obj.get(k), dict):
                nested = obj[k]
                break
        obj = nested
    return False


def unevaluated_response(validation, message, summary=None):
    return create_response(
        result={KEY: None, "phishResistantActiveCount": None, "phishableActiveCount": None},
        validation=validation,
        api_errors=[message],
        fail_reasons=[message],
        input_summary=summary or {},
        metadata=META,
    )


def label(f):
    return (str(f.get("factorType"))[:40] + "/" + str(f.get("provider") or "")[:40])


OTP_KEYS = ["google_otp", "custom_otp", "rsa_token", "symantec_vip", "yubikey_token", "duo", "onprem_mfa"]
OTP_NAMES = ["otp", "google authenticator", "rsa securid", "symantec", "yubikey", "duo security", "on-prem"]
RECOVERY_ONLY = ["recovery", "none"]


def authenticator_posture(data):
    """The getAuthenticatorPosture body (a dict with an authenticators key), or None when the input is not one."""
    for attempt in range(4):
        if not isinstance(data, dict):
            return None
        if "authenticators" in data:
            return data
        nested = None
        for k in ("data", "apiResponse", "response", "result", "Output"):
            if isinstance(data.get(k), dict):
                nested = data[k]
                break
        data = nested
    return None


def objects(item):
    """A list of objects, or None when the entry is an error body or unreadable."""
    for attempt in range(4):
        if isinstance(item, list):
            return item if all(isinstance(x, dict) for x in item) else None
        if not isinstance(item, dict) or item.get("errorCode") or item.get("errorSummary") or item.get("error"):
            return None
        nested = None
        for k in ("apiResponse", "rawResponse", "response", "result", "data"):
            if k in item:
                nested = item[k]
                break
        item = nested
    return None


def kind(a):
    """What an authenticator is, from its key, then its type, then its name."""
    key = str(a.get("key") or "").lower()
    typ = str(a.get("type") or "").lower()
    name = str(a.get("name") or "").lower()
    if key == "okta_password" or typ == "password":
        return "password"
    if key == "okta_verify" or "okta verify" in name:
        return "okta_verify"
    if key == "okta_email" or typ == "email":
        return "email"
    if key == "security_question" or typ == "security_question":
        return "question"
    if key == "phone_number" or typ == "phone":
        return "phone"
    if key in OTP_KEYS or [n for n in OTP_NAMES if n in name]:
        return "otp"
    if key == "webauthn" or "passkey" in name or "webauthn" in name or "fido" in name or "biometric" in name:
        return "webauthn"
    if key == "smart_card_idp" or "smart card" in name or "piv" in name:
        return "smart_card"
    return "unknown"


def grade_authenticators(data, validation):
    err = [k for k in ("errorCode", "errorSummary", "error") if data.get(k)]
    authenticators = objects(data.get("authenticators"))
    if err or not authenticators:
        return unevaluated_response(validation, "No Okta authenticator list in the response (GET /api/v1/authenticators); "
                                                "whether only phishing-resistant authenticators are enabled cannot be judged.")
    methods = data.get("authenticatorMethods")
    aligned = isinstance(methods, list) and len(methods) == len(authenticators)
    resistant, phishable, unknown, fastpass, active_names = [], [], [], False, []
    for i in range(len(authenticators)):
        a = authenticators[i]
        if str(a.get("status") or "").upper() != "ACTIVE":
            continue
        k = kind(a)
        name = str(a.get("name") or a.get("key") or a.get("type") or "unnamed")[:60]
        active_names.append(name)
        settings = a.get("settings") if isinstance(a.get("settings"), dict) else {}
        allowed = str(settings.get("allowedFor") or "").lower()
        if k == "password":
            continue
        if k in ("email", "question"):
            if allowed not in RECOVERY_ONLY:
                phishable.append(("Email" if k == "email" else "Security question") + " sign-in")
        elif k == "phone":
            phishable.append("Phone (SMS or voice)")
        elif k == "otp":
            phishable.append(name)
        elif k in ("webauthn", "smart_card"):
            resistant.append(name)
        elif k == "okta_verify":
            ov = objects(methods[i]) if aligned else None
            if not ov:
                return unevaluated_response(validation, "Okta Verify is ACTIVE, but its method list could not be read, "
                                                        "so whether push or one-time codes are on cannot be judged.")
            on = [str(m.get("type") or "").lower() for m in ov if str(m.get("status") or "").upper() == "ACTIVE"]
            if "push" in on:
                phishable.append("Okta Verify push")
            if "totp" in on:
                phishable.append("Okta Verify one-time code")
            fastpass = fastpass or "signed_nonce" in on
        else:
            unknown.append(name)
    summary = {"source": "authenticators", "totalAuthenticators": len(authenticators),
               "activeAuthenticators": active_names, "phishResistantActiveCount": len(resistant),
               "phishableActiveCount": len(phishable), "fastPassActive": fastpass}
    if not phishable and unknown:
        return unevaluated_response(validation, "No phishable authenticator is ACTIVE, but the ACTIVE authenticator(s) "
                                    + ", ".join(unknown) + " could not be classified.", summary)
    if not phishable and fastpass:
        return unevaluated_response(
            validation, "Okta FastPass is ACTIVE. FastPass is phishing-resistant only when an authentication policy "
                        "rule requires phishing resistance, which the authenticator settings do not show; no phishable "
                        "authenticator is ACTIVE.", summary)
    passed = bool(resistant) and not phishable
    pass_reasons, fail_reasons, recommendations = [], [], []
    if passed:
        pass_reasons.append("Only phishing-resistant authenticators are ACTIVE: " + ", ".join(resistant) + ".")
    elif phishable:
        fail_reasons.extend([p + " is enabled; a real-time phishing proxy can relay it." for p in phishable])
        recommendations.append("Turn off the phishable authenticators and methods (Phone, Okta Verify push and "
                               "one-time code, OTP apps and tokens) and set Email and security question to recovery "
                               "only, so only passkeys (WebAuthn) or smart card remain for sign-in.")
    else:
        fail_reasons.append("No phishing-resistant authenticator (passkey/WebAuthn, smart card) is ACTIVE.")
        recommendations.append("Activate passkeys (WebAuthn) or smart card authentication.")
    return create_response(
        result={KEY: passed, "phishResistantActiveCount": len(resistant), "phishableActiveCount": len(phishable),
                "activePhishResistantFactors": resistant, "activePhishableFactors": phishable},
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=summary,
        metadata=META,
    )


def transform(input):
    try:
        if isinstance(input, (str, bytes)):
            input = json.loads(input.decode("utf-8") if isinstance(input, bytes) else input)
        data, validation = extract_input(input)
        paged = has_more(input)
        posture = authenticator_posture(data)
        factors = factor_list(data)
    except Exception as error:
        return unevaluated_response({"status": "failed", "errors": [str(error)[:200]], "warnings": []},
                                    "The Okta org factor list could not be parsed.")
    if str(validation.get("status") or "").lower() == "failed":
        return unevaluated_response(validation, "Input validation failed; the factor list is not evidence.")
    if posture is not None:
        try:
            return grade_authenticators(posture, validation)
        except Exception as error:
            return unevaluated_response({"status": "failed", "errors": [str(error)[:200]], "warnings": []},
                                        "The Okta authenticator list could not be parsed.")
    if factors is None:
        return unevaluated_response(validation, "No Okta org factor list in the response (GET /api/v1/org/factors); "
                                                "whether only phishing-resistant factors are enabled cannot be judged.")
    if paged:
        return unevaluated_response(validation, "The Okta factor list carries a next-page marker, so it is one page "
                                                "of several; a partial list is not evidence.")
    listed = set(str(f.get("factorType")) for f in factors)
    missing = [t for t in ALWAYS_LISTED if t not in listed]
    if missing:
        return unevaluated_response(validation, "The Okta factor list is incomplete: it has no entry for "
                                    + ", ".join(missing) + ", which /api/v1/org/factors always lists (ACTIVE or "
                                    "not); a partial list is not evidence.", {"totalFactors": len(factors)})

    active = [f for f in factors if f.get("status") == "ACTIVE"]
    resistant = [label(f) for f in active if f.get("factorType") in PHISH_RESISTANT_TYPES]
    phishable = [label(f) for f in active if f.get("factorType") not in PHISH_RESISTANT_TYPES]
    fastpass = [label(f) for f in active if f.get("factorType") == FASTPASS]
    summary = {"totalFactors": len(factors), "activeFactorCount": len(active),
               "phishResistantActiveCount": len(resistant), "phishableActiveCount": len(phishable),
               "fastPassActive": bool(fastpass)}

    if fastpass and not phishable:
        return unevaluated_response(
            validation, "Okta FastPass is ACTIVE. FastPass is phishing-resistant only when an authentication policy "
                        "rule requires phishing resistance, which the org factor list does not show; no phishable "
                        "factor is ACTIVE.", summary)

    passed = bool(resistant) and not phishable
    pass_reasons, fail_reasons, recommendations = [], [], []
    if passed:
        pass_reasons.append("Only phishing-resistant factors are ACTIVE in the org: " + ", ".join(resistant) + ".")
    elif resistant:
        fail_reasons.append("Phishable factor(s) " + ", ".join(phishable) + " are ACTIVE next to the "
                            "phishing-resistant factor(s) " + ", ".join(resistant) + "; users can still sign in "
                            "with a factor a phishing proxy can relay.")
        recommendations.append("Deactivate the phishable factors (push, SMS, voice, email, security question, "
                               "OTP tokens) so only FIDO2 (WebAuthn), FIDO U2F, smart card, or Okta FastPass under a policy that requires phishing resistance remain.")
    else:
        fail_reasons.append("No phishing-resistant factor (FIDO2/WebAuthn, FIDO U2F, Okta FastPass, smart card) is "
                            "ACTIVE; active factors: " + (", ".join(phishable) or "none") + ".")
        recommendations.append("Activate FIDO2 (WebAuthn), FIDO U2F or smart card and deactivate the phishable factors.")

    return create_response(
        result={KEY: passed, "phishResistantActiveCount": len(resistant), "phishableActiveCount": len(phishable),
                "activePhishResistantFactors": resistant, "activePhishableFactors": phishable},
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=summary,
        metadata=META,
    )
