"""
Transformation: authTypesAllowed
Vendor: Duo (Cisco)  |  Integration: Duo (a2abbcf5)  |  Category: Multifactor Authentication

Meaning: "no weak factors". Only strong authentication methods can be used to sign in through Duo, the same
meaning as the Entra (safeguards/mfa/azure/authtypesallowed.py) and Okta (safeguards/iam/okta/authtypesallowed.py)
authTypesAllowed transforms.

Evidence: workflow getStrongAuthPolicies (two GETs, merged under output keys; both Duo Admin API Policies v2,
v5-signed, "Grant resource - Read"):
  policies <- getDuoPolicies:      GET /admin/v2/policies (paged): every policy with its sections
  summary  <- getDuoPolicySummary: GET /admin/v2/policies/summary: policy_applies_to, policy_count,
                                   response_is_truncated

Why not GET /admin/v1/settings: Duo documents push_enabled, sms_enabled, voice_enabled and mobile_otp_enabled
there as "Legacy parameter; no effect if specified and always returns false. Use Duo Authentication Method
policies to configure this setting." (Duo Admin API, Settings, Retrieve Settings). A settings body therefore
says nothing about which methods users can use, and this transform reads it as Unevaluated.

Where the methods live (Duo Admin API, Policy Section Data, Authentication Methods, section
"authentication_methods"):
  allowed_auth_list  methods permitted for user authentication
  blocked_auth_list  methods blocked; "An authentication method not included in blocked_auth_list is allowed,
                     even if not specified here."
So a method is permitted unless it is in blocked_auth_list. A custom policy that does not carry the section
inherits it from the global policy.

Which policies count: the global policy (it governs every application without its own policy) plus every
custom policy the summary shows applied to an application or to groups within one. Unapplied custom policies
govern nothing.

Method classes (names from the Authentication Methods section):
  WEAK    sms, phonecall              SMS passcodes and phone-call (voice) approval: telephony factors, weak
                                      under Entra (sms, voice) and Okta (phone_number) alike.
          bypass, bypass-pwl          bypass codes: static codes an administrator or help desk issues, typed in
                                      like a password. The policy does not bound their lifetime or reuse, so
                                      they are treated like Okta's temporary access code (weak), not like
                                      Entra's Temporary Access Pass with a maximum lifetime.
  STRONG  duo-push, duo-push-pwl      Duo Push (Verified Push when require_verified_push is true)
          webauthn-platform, webauthn-roaming, webauthn-require-user-verification, webauthn-platform-pwl,
          webauthn-roaming-pwl        platform authenticators, FIDO security keys, passkeys
          smart-card                  PIV / smart cards
          duo-passcode                Duo Mobile passcodes (TOTP/HOTP). Strong, as Entra counts software OATH
                                      tokens and Okta counts google_otp.
          hardware-token              OTP hardware tokens. Strong, as Entra counts hardware OATH tokens.
          desktop                     Duo Desktop authentication (device-bound, push-style)

Rule:
  False  any governing policy leaves a WEAK method permitted.
  True   every governing policy permits only STRONG methods (and at least one).
  None   (Unevaluated, every key None, dataCollection error) when the evidence is missing or partial: no
         policies or summary body, an error body or vendorErrorAsResponse marker (a 403 means the Admin API
         application lacks "Grant resource - Read"), a settings body instead of the policies, a truncated
         summary or one whose policy_count does not match the policies read, no or several global policies, a
         global policy without an authentication_methods section, a method list that is not a list or string,
         a governing policy permitting a method this check does not recognise (and no weak one), a policy that
         blocks every method, or an exception. Never True on partial data.

Not judged here (findings only): user_auth_behavior "bypass" and new_user_behavior "no-mfa" are about whether
MFA is required, which isMFAEnforcedForUsers / isStrongAuthRequired judge, not which methods are allowed.
"""
import json
from datetime import datetime

CRITERIA_KEY = "authTypesAllowed"
RESULT_KEYS = ["authTypesAllowed", "weakAuthMethodsAllowed", "strongAuthMethodsAllowed", "governingPolicies",
               "policiesAllowingWeakMethods"]
WEAK = ["sms", "phonecall", "bypass", "bypass-pwl"]
STRONG = ["duo-push", "duo-push-pwl", "webauthn-platform", "webauthn-roaming", "webauthn-require-user-verification",
          "webauthn-platform-pwl", "webauthn-roaming-pwl", "smart-card", "duo-passcode", "hardware-token", "desktop"]
WEAK_LABELS = {"sms": "SMS passcodes", "phonecall": "phone call", "bypass": "bypass codes",
               "bypass-pwl": "passwordless bypass codes"}
WRAPPERS = ["apiResponse", "api_response", "result", "Output", "data"]
SETTINGS_FIELDS = ["push_enabled", "sms_enabled", "voice_enabled", "mobile_otp_enabled"]
PERMISSION = "Grant resource - Read"


def create_response(result, pass_reasons=None, fail_reasons=None, recommendations=None, input_summary=None,
                    api_errors=None, transformation_errors=None, findings=None):
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
                         "transformationId": CRITERIA_KEY, "vendor": "Duo",
                         "category": "Multifactor Authentication"},
        },
    }


def not_evaluated(reason, summary=None, findings=None, error_code=None):
    result = {}
    for k in RESULT_KEYS:
        result[k] = None
    text = "Not evaluated: " + reason + ". Nothing was measured; this is not a posture result."
    out = create_response(result, fail_reasons=[text], api_errors=[text], input_summary=summary, findings=findings,
                          recommendations=["Confirm the Duo Admin API application has the \"" + PERMISSION
                                           + "\" permission and that the Policies v2 reads succeed."])
    if error_code:
        out["additionalInfo"]["dataCollection"]["errorCode"] = error_code
    return out


def decode(raw):
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    if isinstance(raw, str):
        if raw.strip() == "":
            return None
        return json.loads(raw)
    return raw


def refusal_in(body):
    """The vendorErrorAsResponse marker in body or one level inside it, else None."""
    if not isinstance(body, dict):
        return None
    if "vendorErrorAsResponse" in body:
        return body.get("vendorErrorAsResponse")
    for k in body:
        inner = body[k]
        if isinstance(inner, dict) and "vendorErrorAsResponse" in inner:
            return inner.get("vendorErrorAsResponse")
    return None


def refusal_reason(marker):
    status = marker.get("status") if isinstance(marker, dict) else None
    if status == 403:
        return ("Duo refused the read with HTTP 403. This key needs the Policies v2 reads (workflow "
                "getStrongAuthPolicies), which need the Admin API permission \"" + PERMISSION + "\". If the refused "
                "call was GET /admin/v1/settings, the key is still routed to the legacy settings read, whose flags "
                "cannot answer it; the fix is the routing, not a permission"), "permission_not_granted"
    return "Duo refused the read (HTTP " + str(status)[:10] + ")", "vendor_refusal"


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
        if not isinstance(body, dict) or "policies" in body or "summary" in body:
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


def is_settings_body(body):
    if not isinstance(body, dict):
        return False
    inner = body.get("response") if isinstance(body.get("response"), dict) else body
    for k in SETTINGS_FIELDS:
        if k in inner:
            return True
    return False


def method_set(value):
    """A Duo method list (list or comma-separated string) as lower-case names; None when wrong-typed."""
    if value is None:
        return []
    if isinstance(value, str):
        items = value.split(",")
    elif isinstance(value, list):
        items = value
    else:
        return None
    out = []
    for item in items:
        if not isinstance(item, str):
            return None
        name = item.strip().lower()
        if name and name not in out:
            out.append(name)
    return out


def policy_list(part):
    """(policies, error) from the getDuoPolicies output."""
    part = decode(part)
    if isinstance(part, dict):
        text = error_text(part)
        if text:
            return None, text
        part = part.get("response", part.get("policies"))
        if isinstance(part, dict):
            text = error_text(part)
            if text:
                return None, text
            part = part.get("policies", part.get("response"))
    if not isinstance(part, list):
        return None, "GET /admin/v2/policies returned no policy list"
    for p in part:
        if not isinstance(p, dict):
            return None, "GET /admin/v2/policies returned an entry that is not a policy object"
    return part, ""


def summary_of(part):
    """(summary dict, error) from the getDuoPolicySummary output."""
    part = decode(part)
    if not isinstance(part, dict):
        return None, "GET /admin/v2/policies/summary was not returned"
    text = error_text(part)
    if text:
        return None, text
    if isinstance(part.get("response"), dict):
        part = part["response"]
        text = error_text(part)
        if text:
            return None, text
    if not isinstance(part.get("policies"), list):
        return None, "GET /admin/v2/policies/summary carried no policies list"
    return part, ""


def section(policy, name):
    sections = policy.get("sections")
    if isinstance(sections, dict) and isinstance(sections.get(name), dict):
        return sections[name]
    return None


def permitted_methods(policy, glob):
    """(permitted method names, error) for one governing policy, inheriting the section from the global one."""
    methods = section(policy, "authentication_methods") or section(glob, "authentication_methods")
    if methods is None:
        return None, "has no authentication_methods section to read"
    allowed = method_set(methods.get("allowed_auth_list"))
    blocked = method_set(methods.get("blocked_auth_list"))
    if allowed is None or blocked is None:
        return None, "carries an authentication method list that is not a list or string"
    permitted = [m for m in WEAK + STRONG if m not in blocked]
    for m in allowed:
        if m not in permitted and m not in blocked:
            permitted.append(m)
    return permitted, ""


def mfa_findings(policy, glob, name):
    out = []
    auth_policy = section(policy, "authentication_policy") or section(glob, "authentication_policy") or {}
    if str(auth_policy.get("user_auth_behavior") or "").strip().lower() == "bypass":
        out.append(name + " skips 2FA for all users (user_auth_behavior bypass); judged by the MFA-enforcement checks")
    new_user = section(policy, "new_user") or section(glob, "new_user") or {}
    if str(new_user.get("new_user_behavior") or "").strip().lower() == "no-mfa":
        out.append(name + " lets unenrolled users sign in without MFA (new_user_behavior no-mfa); judged by the "
                   "MFA-enforcement checks")
    return out


def evaluate(body):
    policies, text = policy_list(body.get("policies"))
    if text:
        return not_evaluated("GET /admin/v2/policies failed: " + text + " (needs v5 signing and the Admin API "
                             "permission '" + PERMISSION + "')")
    summary, text = summary_of(body.get("summary"))
    if text:
        return not_evaluated("GET /admin/v2/policies/summary failed: " + text + " (needs v5 signing and the "
                             "Admin API permission '" + PERMISSION + "')")
    if flag(summary.get("response_is_truncated")) is not False:
        return not_evaluated("the policy summary is truncated or does not say whether it is")
    count = summary.get("policy_count")
    if not isinstance(count, int) or isinstance(count, bool):
        try:
            count = int(str(count).strip())
        except (TypeError, ValueError):
            return not_evaluated("the policy summary carries no policy_count")
    if count != len(policies):
        return not_evaluated("read %d policies but the summary counts %d" % (len(policies), count))

    global_policies = [p for p in policies if flag(p.get("is_global_policy")) is True]
    if len(global_policies) != 1:
        return not_evaluated("expected exactly one global policy, found %d" % len(global_policies))
    glob = global_policies[0]
    if section(glob, "authentication_methods") is None:
        return not_evaluated("the global policy has no authentication_methods section")

    applied = {}
    for entry in summary["policies"]:
        if isinstance(entry, dict) and isinstance(entry.get("policy_applies_to"), list) \
                and entry["policy_applies_to"]:
            applied[str(entry.get("policy_key"))] = True
    governing = [glob] + [p for p in policies if p is not glob and str(p.get("policy_key")) in applied]

    weak_found = []
    strong_found = []
    unknown_reasons = []
    unreadable = []
    weak_policies = []
    findings = []
    for p in governing:
        name = "the global policy" if p is glob else "policy '%s'" % str(p.get("policy_name") or p.get("policy_key"))[:100]
        findings = findings + mfa_findings(p, glob, name)
        permitted, text = permitted_methods(p, glob)
        if text:
            unreadable.append(name + " " + text)
            continue
        weak = [m for m in permitted if m in WEAK]
        strong = [m for m in permitted if m in STRONG]
        unknown = [m for m in permitted if m not in WEAK and m not in STRONG]
        for m in weak:
            if m not in weak_found:
                weak_found.append(m)
        for m in strong:
            if m not in strong_found:
                strong_found.append(m)
        if weak:
            weak_policies.append(name + " permits " + ", ".join([WEAK_LABELS.get(m, m) + " (" + m + ")" for m in weak]))
        if unknown:
            unknown_reasons.append(name + " permits methods this check does not recognise: " + ", ".join(unknown)[:300])
        if not permitted:
            unreadable.append(name + " blocks every authentication method")

    info = {"policiesRead": len(policies), "governingPolicies": len(governing),
            "appliedCustomPolicies": len(governing) - 1, "policiesAllowingWeakMethods": len(weak_policies)}

    if weak_policies:
        result = {CRITERIA_KEY: False, "weakAuthMethodsAllowed": weak_found, "strongAuthMethodsAllowed": strong_found,
                  "governingPolicies": len(governing), "policiesAllowingWeakMethods": len(weak_policies)}
        return create_response(result, input_summary=info, findings=findings + unknown_reasons + unreadable,
                               fail_reasons=["Weak authentication methods are allowed by Duo policy"] + weak_policies,
                               recommendations=["In the Duo Admin Panel (Policies > Authentication Methods), block "
                                                "SMS passcodes, phone call and bypass codes in the global policy and "
                                                "in every applied custom policy; keep Duo Push (Verified Push), "
                                                "WebAuthn security keys / passkeys, platform authenticators or "
                                                "OTP passcodes"])
    if unreadable or unknown_reasons:
        return not_evaluated("no weak method is permitted, but " + "; ".join(unreadable + unknown_reasons)[:600],
                             summary=info, findings=findings)
    result = {CRITERIA_KEY: True, "weakAuthMethodsAllowed": [], "strongAuthMethodsAllowed": strong_found,
              "governingPolicies": len(governing), "policiesAllowingWeakMethods": 0}
    return create_response(result, input_summary=info, findings=findings, pass_reasons=[
        "Every Duo policy that governs an application (%d) permits only strong authentication methods: %s"
        % (len(governing), ", ".join(strong_found))])


def transform(input):
    try:
        raw = decode(input)
        marker = refusal_in(raw)
        if marker is None and isinstance(raw, dict):
            for k in ["policies", "summary"]:
                if marker is None:
                    marker = refusal_in(decode(raw.get(k)))
        if marker is not None:
            reason, code = refusal_reason(marker)
            return not_evaluated(reason, error_code=code)
        body = unwrap(raw)
        text = error_text(body)
        if text:
            return not_evaluated(text)
        if not isinstance(body, dict) or "policies" not in body or "summary" not in body:
            if is_settings_body(body):
                return not_evaluated("the input is a GET /admin/v1/settings body; Duo documents its push_enabled, "
                                     "sms_enabled, voice_enabled and mobile_otp_enabled fields as legacy and always "
                                     "false, so it cannot show which methods users can use (route this key to the "
                                     "getStrongAuthPolicies workflow)")
            return not_evaluated("the Policies v2 bodies (policies and summary) were not returned")
        return evaluate(body)
    except Exception as e:
        return not_evaluated("transformation raised " + str(e)[:200])
