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


def transform(input):
    try:
        if isinstance(input, (str, bytes)):
            input = json.loads(input.decode("utf-8") if isinstance(input, bytes) else input)
        data, validation = extract_input(input)
        paged = has_more(input)
        factors = factor_list(data)
    except Exception as error:
        return unevaluated_response({"status": "failed", "errors": [str(error)[:200]], "warnings": []},
                                    "The Okta org factor list could not be parsed.")
    if str(validation.get("status") or "").lower() == "failed":
        return unevaluated_response(validation, "Input validation failed; the factor list is not evidence.")
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
