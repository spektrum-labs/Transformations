"""
Transformation: isAdminMFAPhishingResistant
Vendor: Okta   Method: GET /api/v1/org/factors (listOrgFactors: every factor the org can enroll, with status)

Requirement asked: "Only phishing-resistant factors for admins are permitted."

What the org factor list can and cannot prove:
- No phishing-resistant factor ACTIVE  -> admins cannot be limited to phishing-resistant MFA: False.
- Phishing-resistant factors ACTIVE and NO phishable factor ACTIVE -> the org permits only
  phishing-resistant factors, so admins too: True.
- Phishing-resistant AND phishable factors ACTIVE -> whether admins are restricted is decided by the
  Admin Console authentication policy, which this response does not carry: None (not evaluated).
- Anything that is not a factor list (null, {}, [], an error envelope, unrelated JSON): None, with
  additionalInfo.dataCollection.status "error", so a failed read is never scored.

Phishing-resistant factor types (Okta "Factors" API factorType values): webauthn (FIDO2 / WebAuthn),
u2f (FIDO U2F security key), signed_nonce (Okta FastPass), smart_card (PIV / CAC). Every other type
(push, sms, call, email, question, token:software:totp, token:hotp, token, token:hardware OTP, web)
can be relayed by a real-time phishing proxy.
Numbers: phishResistantActiveCount, phishableActiveCount.
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
        for _ in range(3):
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
    data_collection_status = "error" if api_err_list else "success"
    transformation_status = "error" if transform_err_list else "success"
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": data_collection_status, "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": transformation_status,
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
KEY = "isAdminMFAPhishingResistant"


def factor_list(data):
    """Return the org factor list, or None when the body is not one."""
    if isinstance(data, str):
        try:
            data = json.loads(data)
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
        metadata={"transformationId": KEY, "vendor": "Okta", "category": "iam"},
    )


def transform(input):
    data, validation = extract_input(input)
    factors = factor_list(data)
    if factors is None:
        return unevaluated_response(validation, "No Okta org factor list in the response (GET /api/v1/org/factors); "
                                        "phishing-resistant MFA for admins cannot be judged.")

    active = [f for f in factors if f.get("status") == "ACTIVE"]
    resistant = [f"{f.get('factorType')}/{f.get('provider') or ''}" for f in active
                 if f.get("factorType") in PHISH_RESISTANT_TYPES]
    phishable = [f"{f.get('factorType')}/{f.get('provider') or ''}" for f in active
                 if f.get("factorType") not in PHISH_RESISTANT_TYPES]
    summary = {"totalFactors": len(factors), "activeFactorCount": len(active),
               "phishResistantActiveCount": len(resistant), "phishableActiveCount": len(phishable)}

    if resistant and phishable:
        return unevaluated_response(
            validation,
            f"Phishing-resistant factor(s) {', '.join(resistant)} and phishable factor(s) {', '.join(phishable)} "
            f"are both ACTIVE. Whether admins are limited to the phishing-resistant ones is set by the Admin "
            f"Console authentication policy, which the org factor list does not show.",
            summary,
        )

    passed = bool(resistant)
    pass_reasons, fail_reasons, recommendations = [], [], []
    if passed:
        pass_reasons.append(f"Only phishing-resistant factors are ACTIVE in the org ({', '.join(resistant)}), "
                            f"so admins can authenticate only with phishing-resistant MFA.")
    else:
        fail_reasons.append(f"No phishing-resistant factor (FIDO2/WebAuthn, FIDO U2F, Okta FastPass, smart card) is "
                            f"ACTIVE; active factors: {', '.join(phishable) or 'none'}. Admins cannot be limited to "
                            f"phishing-resistant MFA.")
        recommendations.append("Activate FIDO2 (WebAuthn) or Okta FastPass and require a phishing-resistant "
                               "authenticator in the Okta Admin Console authentication policy.")

    return create_response(
        result={KEY: passed, "phishResistantActiveCount": len(resistant), "phishableActiveCount": len(phishable),
                "activePhishResistantFactors": resistant, "activeFactorTypes": resistant + phishable},
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=summary,
        metadata={"transformationId": KEY, "vendor": "Okta", "category": "iam"},
    )
