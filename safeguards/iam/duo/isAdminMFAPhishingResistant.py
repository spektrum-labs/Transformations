"""
Transformation: isAdminMFAPhishingResistant
Vendor: Duo (Cisco)  |  Integration: Duo (a2abbcf5)  |  Category: Multifactor Authentication

Evidence: workflow isAdminMFAPhishingResistant (two GETs, merged under output keys)
  allowedAuthMethods <- getAdminAllowedAuthMethods: GET /admin/v1/admins/allowed_auth_methods
      Duo Admin API "Retrieve Administrator Authentication Factors": the secondary authentication methods
      permitted for administrator log in to the Duo Admin Panel. Requires "Grant administrators - Read", the
      same permission getAdmins already needs. Response flags: hardware_token_enabled, mobile_otp_enabled,
      push_enabled, sms_enabled, verified_push_enabled, verified_push_length, voice_enabled,
      webauthn_enabled, yubikey_enabled.
  admins             <- getAdmins: GET /admin/v1/admins (findings only; never decides the verdict)

Rule (the account-wide setting that governs every Duo administrator login):
  True  only when webauthn_enabled is true (security keys / passkeys) AND every phishable method is
        false: push_enabled, verified_push_enabled, sms_enabled, voice_enabled, mobile_otp_enabled,
        hardware_token_enabled (OTP token) and yubikey_enabled (Yubikey OTP).
  False when any phishable method is permitted, or WebAuthn is not permitted.
  Not evaluated (null, dataCollection error): no allowed-methods body, an error body (a 403 means the
        Admin API application lacks "Grant administrators - Read"), or any of those flags missing or not a
        boolean. Duo bodies can reach the transform with booleans as the strings "True"/"False".

Per-admin enrolment (WebAuthn credentials on each active admin) is reported as a finding only: an
admin with no WebAuthn credential under a WebAuthn-only setting cannot sign in until they enrol one,
which does not make the setting weaker.

Does not prove: phishing-resistant MFA for administrators of other systems (domain controllers,
cloud consoles) that Duo does not sit in front of.
"""

import json
from datetime import datetime

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('isAdminMFAPhishingResistant',)


def criteria_unmeasured(result):
    """True when every criterion this file answers that the result carries is None.

    Token-Service grades a None criterion as FAILED unless additionalInfo.dataCollection.status
    is "error". The status is read per response, so it is set only when no criterion in the
    result was measured; marking a partly measured result would hide the measured ones.
    """
    present = [k for k in NONE_MEANS_NOT_EVALUATED if k in result]
    return len(present) > 0 and all(result[k] is None for k in present)

CRITERIA_KEY = "isAdminMFAPhishingResistant"
PHISHABLE = [
    ("push_enabled", "Duo Push"),
    ("verified_push_enabled", "Verified Duo Push"),
    ("sms_enabled", "SMS passcodes"),
    ("voice_enabled", "phone call"),
    ("mobile_otp_enabled", "Duo Mobile passcodes"),
    ("hardware_token_enabled", "OTP hardware tokens"),
    ("yubikey_enabled", "Yubikey OTP"),
]
STRONG = "webauthn_enabled"
WRAPPERS = ["apiResponse", "api_response", "response", "result", "Output", "data"]


def create_response(result, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, api_errors=None, transformation_errors=None, findings=None):
    # A None criterion was not measured. Token-Service grades None as FAILED unless
    # dataCollection.status is "error", which needs a non-empty api_errors, so carry the
    # reason across when the caller did not.
    if not api_errors and isinstance(result, dict) and criteria_unmeasured(result):
        api_errors = (list(fail_reasons or []) or list(transformation_errors or [])
                      or ["The response could not answer this check, so it was not evaluated."])
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "error" if (transformation_errors or []) else "success",
                               "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0",
                         "transformationId": CRITERIA_KEY, "vendor": "Duo", "category": "Multifactor Authentication"},
        },
    }


def not_evaluated(reason, findings=None):
    return create_response({CRITERIA_KEY: None}, api_errors=[reason], fail_reasons=["Not evaluated: " + reason],
                           findings=findings)


def decode(raw):
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    if isinstance(raw, str):
        if raw.strip() == "":
            return None
        return json.loads(raw)
    return raw


def error_text(body):
    """Duo's or Integration-Service's error text when body is an error envelope, else ''."""
    if body is None:
        return "no response body"
    if not isinstance(body, dict):
        return ""
    if body.get("error"):
        return str(body.get("message") or body.get("error"))[:300]
    if str(body.get("stat", "")).upper() == "FAIL":
        return ("Duo error %s: %s" % (body.get("code"), body.get("message") or "")).strip()[:300]
    code = body.get("statusCode", body.get("status_code"))
    try:
        if code is not None and int(code) >= 400:
            return ("HTTP %s %s" % (code, body.get("message") or "")).strip()[:300]
    except (TypeError, ValueError):
        pass
    if str(body.get("status", "")).lower() == "error":
        return str(body.get("message") or "integration error")[:300]
    return ""


def flag(value):
    """True / False for a real boolean or its string form; None for anything else."""
    if value is True or value is False:
        return value
    text = str(value).strip().lower()
    if text == "true":
        return True
    if text == "false":
        return False
    return None


def unwrap(body):
    for attempt in range(3):
        if not isinstance(body, dict) or "allowedAuthMethods" in body or "admins" in body:
            return body
        moved = False
        for key in WRAPPERS:
            if isinstance(body.get(key), dict):
                body = body[key]
                moved = True
                break
        if not moved:
            return body
    return body


def methods_of(part):
    """The allowed-methods flags dict from {"response": {...}} or the bare flags; None if absent."""
    part = decode(part)
    if isinstance(part, dict) and isinstance(part.get("response"), dict):
        part = part["response"]
    if isinstance(part, dict) and STRONG in part:
        return part
    return None


def admins_of(part):
    part = decode(part)
    if isinstance(part, dict):
        part = part.get("response")
    if isinstance(part, list):
        return [a for a in part if isinstance(a, dict)]
    return None


# Integration-Service hands a vendor refusal over as data when the method opts in (vendorErrorAsResponse):
# {"vendorErrorAsResponse": {"status": 403, "bodyContains": ..., "body": <vendor body>}}, as the whole input or as
# one of the workflow outputs merged into it. Duo answers a missing Admin API permission with HTTP 403
# {"stat": "FAIL", "code": 40301, "message": "Access forbidden"}. That says nothing about the tenant's posture, so the
# result stays None (Unevaluated) and the error names the refused call. A permission is named only where Duo's
# documentation states it; otherwise the error says the documentation does not name it. Any other handed-over
# refusal is Unevaluated with errorCode "vendor_refusal" and names no permission.
REFUSAL_FORBIDDEN_CODE = 40301
PERMISSION_NOT_GRANTED = "permission_not_granted"
VENDOR_REFUSAL = "vendor_refusal"
REFUSAL_ENDPOINTS = {"admins": "GET /admin/v1/admins",
                     "allowedAuthMethods": "GET /admin/v1/admins/allowed_auth_methods"}
REFUSAL_PERMISSIONS = {"admins": "Grant administrators - Read"}


def refusal_decoded(body):
    """A vendor body or workflow output as an object: dicts as they are, JSON object text or bytes parsed, else None."""
    if isinstance(body, bytes):
        try:
            body = body.decode("utf-8")
        except Exception:
            return None
    if isinstance(body, str):
        if not body.strip().startswith("{"):
            return None
        try:
            return json.loads(body)
        except Exception:
            return None
    return body


def refusal_find(value, path, depth):
    """[(path, marker)] for every vendorErrorAsResponse in the input: top level, under an output key, or nested."""
    value = refusal_decoded(value)
    if not isinstance(value, dict):
        return []
    if "vendorErrorAsResponse" in value:
        return [(path, value["vendorErrorAsResponse"])]
    found = []
    if depth < 3:
        for k in value:
            found.extend(refusal_find(value[k], path + [str(k)], depth + 1))
    return found


def refusal_unevaluated(found):
    problems = []
    recommendations = []
    seen = []
    forbidden_any = False
    permission = None
    for path, marker in found:
        which = None
        for part in path:
            if part in REFUSAL_ENDPOINTS:
                which = part
                break
        if which in seen:
            continue
        seen.append(which)
        status = marker.get("status") if isinstance(marker, dict) else None
        body = refusal_decoded(marker.get("body")) if isinstance(marker, dict) else None
        forbidden = (status == 403 and isinstance(body, dict)
                     and body.get("code") == REFUSAL_FORBIDDEN_CODE and body.get("message") == "Access forbidden")
        if which is None:
            target = "a call in this check's workflow (" + " or ".join(list(REFUSAL_ENDPOINTS.values())) + ")"
        else:
            target = REFUSAL_ENDPOINTS[which]
        if not forbidden:
            problems.append("Duo refused " + target + " (HTTP " + str(status)[:10] + "); nothing was measured.")
            recommendations.append("Confirm the Duo Admin API credentials are valid and the Admin API application is enabled.")
            continue
        forbidden_any = True
        head = "PERMISSION-NOT-GRANTED: Duo refused the call to " + target + " with HTTP 403 code 40301 (Access forbidden)"
        if which in REFUSAL_PERMISSIONS:
            permission = REFUSAL_PERMISSIONS[which]
            problems.append(head + ": the Admin API application lacks the \"" + permission
                            + "\" permission. Nothing was measured; this is not a posture result.")
            recommendations.append("In the Duo Admin Panel, open the Admin API application used for Spektrum and enable the \""
                                   + permission + "\" permission; the integration key and secret do not change.")
        elif which is None:
            problems.append(head + ": the Admin API application lacks a permission one of these endpoints needs, and the "
                            "refused call is not identified. Duo's documentation does not name the permission for every "
                            "endpoint, so check the application's permission grants. Nothing was measured; this is not a "
                            "posture result.")
            recommendations.append("In the Duo Admin Panel, check the permission grants of the Admin API application used for Spektrum.")
        else:
            problems.append(head + ": the Admin API application lacks a permission this endpoint needs; Duo's "
                            "documentation does not name it, so check the application's permission grants. Nothing was "
                            "measured; this is not a posture result.")
            recommendations.append("In the Duo Admin Panel, check the permission grants of the Admin API application used for Spektrum.")
    out = create_response({CRITERIA_KEY: None}, None, fail_reasons=problems, api_errors=problems,
                          recommendations=recommendations)
    collection = out["additionalInfo"]["dataCollection"]
    if forbidden_any:
        collection["errorCode"] = PERMISSION_NOT_GRANTED
        if permission is not None:
            collection["requiredPermission"] = permission
    else:
        collection["errorCode"] = VENDOR_REFUSAL
    return out


def transform(input):
    found = refusal_find(input, [], 0)
    if found:
        return refusal_unevaluated(found)
    try:
        body = unwrap(decode(input))
        text = error_text(body)
        if text:
            return not_evaluated(text)
        if not isinstance(body, dict):
            return not_evaluated("the allowed-methods body was not returned")
        part = body.get("allowedAuthMethods") if "allowedAuthMethods" in body else body
        part = decode(part)
        text = error_text(part) if isinstance(part, dict) and "response" not in part else ""
        if not text and isinstance(part, dict) and isinstance(part.get("response"), dict):
            text = error_text(part["response"]) if STRONG not in part["response"] else ""
        if text:
            return not_evaluated("GET /admin/v1/admins/allowed_auth_methods failed: " + text +
                                 " (needs the Admin API permission 'Grant administrators - Read')")
        methods = methods_of(part)
        if methods is None:
            return not_evaluated("GET /admin/v1/admins/allowed_auth_methods was not returned")

        values = {}
        for key, label in PHISHABLE + [(STRONG, "WebAuthn")]:
            values[key] = flag(methods.get(key))
        unknown = [k for k in values if values[k] is None]
        if unknown:
            return not_evaluated("allowed_auth_methods did not carry a boolean for: " + ", ".join(sorted(unknown)))

        findings = []
        admins = admins_of(body.get("admins")) if "admins" in body else None
        summary = {"webauthnEnabled": values[STRONG]}
        if admins is not None:
            active = [a for a in admins if str(a.get("status", "")).strip().lower() == "active"]
            no_key = [a for a in active if not (isinstance(a.get("webauthncredentials"), list) and a["webauthncredentials"])]
            summary["activeAdmins"] = len(active)
            summary["activeAdminsWithoutWebAuthn"] = len(no_key)
            if no_key:
                findings.append("%d of %d active Duo administrators have no WebAuthn credential registered" % (
                    len(no_key), len(active)))

        allowed = [label for key, label in PHISHABLE if values[key]]
        summary["phishableMethodsPermitted"] = allowed
        if values[STRONG] and not allowed:
            return create_response({CRITERIA_KEY: True}, input_summary=summary, findings=findings, pass_reasons=[
                "Duo Admin Panel login permits only WebAuthn (security keys / passkeys); push, Verified Push, SMS, "
                "phone call, Duo Mobile passcodes, OTP hardware tokens and Yubikey OTP are all disabled"])
        reasons = []
        if allowed:
            reasons.append("Duo administrators may log in with phishable methods: " + ", ".join(allowed))
        if not values[STRONG]:
            reasons.append("WebAuthn (security keys / passkeys) is not permitted for Duo administrator login")
        return create_response({CRITERIA_KEY: False}, input_summary=summary, findings=findings, fail_reasons=reasons,
                               recommendations=["In the Duo Admin Panel (Administrators > Admin Login Settings), allow "
                                                "only security keys / passkeys for administrator login and disable "
                                                "push, SMS, phone call, passcodes and OTP tokens"])
    except Exception as e:
        return create_response({CRITERIA_KEY: None}, transformation_errors=[str(e)],
                               fail_reasons=["Transformation error: %s" % str(e)])
