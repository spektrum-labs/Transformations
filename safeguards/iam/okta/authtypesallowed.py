# authtypesallowed.py - Okta Identity Engine
#
# Method: listAuthenticators -> GET /api/v1/authenticators   (scope okta.authenticators.read)
# Docs:   https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Authenticator/#tag/Authenticator/operation/listAuthenticators
#         Authenticator.{key (AuthenticatorKeyEnum), type, status, settings.allowedFor (any|none|recovery|sso)}
#
# Replaces the read of /api/v1/org/factors (safeguards/86ded564.../auth_types_allowed.py). That is
# the Classic Engine factor catalogue; on an Identity Engine org it reports okta_sms ACTIVE while the
# phone authenticator is INACTIVE, and Okta Verify push INACTIVE while Okta Verify is in use.


def transform(input):
    """
    authTypesAllowed is True when only strong authenticators can be used to authenticate:
      * no ACTIVE weak authenticator: phone_number (SMS / voice), security_question, tac
        (temporary access code), or okta_email unless its settings.allowedFor is "recovery" or
        "none" (email kept for password recovery only is not a sign-in factor);
      * no ACTIVE authenticator this code does not recognise (external_idp and anything new);
      * at least one ACTIVE strong authenticator: okta_verify, webauthn, security_key, google_otp,
        yubikey_token, symantec_vip, duo, smart_card_idp, custom_app, onprem_mfa.
    okta_password is a knowledge factor and is neither weak nor strong here.

    Fails closed on an error body, a non-list body, or a list with no authenticators.
    Does not prove: that the authentication policies demand a second factor (isMFAEnforcedForUsers),
    or which authenticators each user has enrolled.
    """
    import json
    from datetime import datetime

    key = "authTypesAllowed"
    strong_keys = ["okta_verify", "webauthn", "security_key", "google_otp", "yubikey_token", "symantec_vip",
                   "duo", "smart_card_idp", "custom_app", "onprem_mfa"]
    weak_keys = ["phone_number", "security_question", "tac"]

    def as_text(value):
        if value is None:
            return ""
        return str(value).strip()

    def respond(value, passes, fails, summary, errors):
        return {
            "transformedResponse": {key: value},
            "additionalInfo": {
                "dataCollection": {"status": "success", "errors": []},
                "validation": {"status": "error" if errors else "success", "errors": [], "warnings": []},
                "transformation": {"status": "error" if errors else "success", "errors": errors, "inputSummary": summary},
                "evaluation": {"passReasons": passes, "failReasons": fails,
                               "recommendations": [] if value else ["Deactivate SMS/voice, security question and email-as-sign-in authenticators; keep Okta Verify or FIDO2"],
                               "additionalFindings": []},
                "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                             "transformationId": key, "vendor": "Okta", "category": "Identity"},
            },
        }

    try:
        data = input
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        if isinstance(data, str):
            data = json.loads(data)
        for wrapper in ["data", "response", "result", "apiResponse", "_response_data"]:
            if isinstance(data, dict) and wrapper in data:
                data = data[wrapper]
        if isinstance(data, dict):
            for k in ["errorCode", "errorSummary", "error", "errors", "errorMessage"]:
                if data.get(k):
                    return respond(False, [], ["Okta returned an error: " + as_text(data.get(k))[:200]], {}, [])
            return respond(False, [], ["Response is not a list of authenticators"], {}, [])
        if not isinstance(data, list):
            return respond(False, [], ["Response is not a list of authenticators"], {}, [])
        authenticators = [a for a in data if isinstance(a, dict) and as_text(a.get("key"))]
        if not authenticators:
            return respond(False, [], ["No authenticators were returned"], {}, [])

        active_strong = []
        active_weak = []
        unknown = []
        recovery_only = []
        for item in authenticators:
            if as_text(item.get("status")).upper() != "ACTIVE":
                continue
            name = as_text(item.get("key")).lower()
            settings = item.get("settings") if isinstance(item.get("settings"), dict) else {}
            allowed_for = as_text(settings.get("allowedFor")).lower()
            if name == "okta_password":
                continue
            if name in strong_keys:
                active_strong.append(name)
            elif name == "okta_email":
                if allowed_for in ["recovery", "none"]:
                    recovery_only.append(name)
                else:
                    active_weak.append(name + " (allowedFor " + (allowed_for or "missing") + ")")
            elif name in weak_keys:
                active_weak.append(name)
            else:
                unknown.append(name)

        summary = {"activeStrong": active_strong, "activeWeak": active_weak, "activeUnrecognised": unknown,
                   "recoveryOnly": recovery_only, "authenticatorsReturned": len(authenticators)}
        fails = []
        if active_weak:
            fails.append("Weak authenticators are active: " + ", ".join(active_weak))
        if unknown:
            fails.append("Active authenticators not evaluated: " + ", ".join(unknown))
        if not active_strong:
            fails.append("No strong authenticator (Okta Verify, FIDO2/WebAuthn, OTP, hardware token) is active")
        if fails:
            return respond(False, [], fails, summary, [])
        passes = ["Only strong authenticators are active for sign-in: " + ", ".join(active_strong)]
        if recovery_only:
            passes.append("Email is active for recovery only, not sign-in")
        return respond(True, passes, [], summary, [])
    except Exception as e:
        return respond(False, [], ["Transformation error: " + str(e)], {}, [str(e)])
