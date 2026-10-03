"""
Transformation: isPhishingResistantOnlyEnabled
Vendor: Okta (also Okta - Application)   Method: GET /api/v1/org/factors (listOrgFactors: every factor the org
can enroll, with its status). This is the same read as isAdminMFAPhishingResistant.py; no new Okta
permission is needed.

Requirement asked: "Only phishing-resistant MFA is enabled" (CSP-001, CMMC IA.L2-3.5.4).

Value:
- True: at least one phishing-resistant factor is ACTIVE and NO phishable factor is ACTIVE.
- False: the factor list was read and either no phishing-resistant factor is ACTIVE, or a phishable factor is
  ACTIVE next to a phishing-resistant one. An ACTIVE phishable factor is a factor any user can enroll and sign
  in with, so the org does not allow phishing-resistant factors only.
- None (not evaluated, additionalInfo.dataCollection.status "error"): anything that is not a factor list
  (null, {}, [], an error envelope, unrelated JSON, a list with an unrecognised factor status).

Difference from isAdminMFAPhishingResistant.py (same factor sets, same parsing): that key asks about ADMINS,
whose factors the Admin Console policy can narrow, so a mixed list reads None there. This key asks about the
whole org, so a mixed list is a FAIL here. isStrongAuthRequired is not changed: other bundles read it as
"strong auth required".

Phishing-resistant factor types (Okta factorType): webauthn (FIDO2 / WebAuthn), u2f (FIDO U2F security key),
signed_nonce (Okta FastPass), smart_card (PIV / CAC). Every other type (push, sms, call, email, question,
token:software:totp, token:hotp, token, token:hardware OTP, web) can be relayed by a real-time phishing proxy.
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
        data, validation = extract_input(input)
        factors = factor_list(data)
    except Exception as error:
        return unevaluated_response({"status": "failed", "errors": [str(error)[:200]], "warnings": []},
                                    "The Okta org factor list could not be parsed.")
    if factors is None:
        return unevaluated_response(validation, "No Okta org factor list in the response (GET /api/v1/org/factors); "
                                                "whether only phishing-resistant factors are enabled cannot be judged.")

    active = [f for f in factors if f.get("status") == "ACTIVE"]
    resistant = [label(f) for f in active if f.get("factorType") in PHISH_RESISTANT_TYPES]
    phishable = [label(f) for f in active if f.get("factorType") not in PHISH_RESISTANT_TYPES]
    summary = {"totalFactors": len(factors), "activeFactorCount": len(active),
               "phishResistantActiveCount": len(resistant), "phishableActiveCount": len(phishable)}

    passed = bool(resistant) and not phishable
    pass_reasons, fail_reasons, recommendations = [], [], []
    if passed:
        pass_reasons.append("Only phishing-resistant factors are ACTIVE in the org: " + ", ".join(resistant) + ".")
    elif resistant:
        fail_reasons.append("Phishable factor(s) " + ", ".join(phishable) + " are ACTIVE next to the "
                            "phishing-resistant factor(s) " + ", ".join(resistant) + "; users can still sign in "
                            "with a factor a phishing proxy can relay.")
        recommendations.append("Deactivate the phishable factors (push, SMS, voice, email, security question, "
                               "OTP tokens) so only FIDO2 (WebAuthn), FIDO U2F, Okta FastPass or smart card remain.")
    else:
        fail_reasons.append("No phishing-resistant factor (FIDO2/WebAuthn, FIDO U2F, Okta FastPass, smart card) is "
                            "ACTIVE; active factors: " + (", ".join(phishable) or "none") + ".")
        recommendations.append("Activate FIDO2 (WebAuthn) or Okta FastPass and deactivate the phishable factors.")

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
