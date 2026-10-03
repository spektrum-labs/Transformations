"""
Transformation: isStrongAuthRequired
Vendor: Duo (Cisco)  |  Integration: Duo (a2abbcf5)  |  Category: Multifactor Authentication

Evidence: workflow getStrongAuthPolicies (two GETs, merged under output keys). Both are Duo Admin API
Policies v2 endpoints, which "require v5 signing" (Integration-Service signs them with
"signatureVersion": 5). They need "Grant resource - Read".
  policies <- getDuoPolicies:      GET /admin/v2/policies (paged): every policy with its enabled sections
  summary  <- getDuoPolicySummary: GET /admin/v2/policies/summary: where each policy is applied
              (policy_applies_to), policy_count, response_is_truncated

What is judged: every policy that can govern a Duo-protected application. That is the global policy
(it governs every application without its own policy) plus every custom policy the summary shows
applied to an application or to groups within one. Unapplied custom policies govern nothing.

A policy is STRONG when, after inheriting any section it does not set from the global policy:
  * authentication_policy.user_auth_behavior is "deny" (nobody signs in), or
  * user_auth_behavior is not "bypass", new_user.new_user_behavior is not "no-mfa", and the methods
    the authentication_methods section leaves allowed are only phishing-resistant ones: WebAuthn
    security keys / platform authenticators / passkeys (webauthn-roaming, webauthn-platform,
    webauthn-require-user-verification, their -pwl forms) and smart cards.
    Per the docs, "An authentication method not included in blocked_auth_list is allowed", so every
    phishable method must be in blocked_auth_list: duo-push, duo-push-pwl, sms, phonecall,
    duo-passcode, hardware-token, desktop, bypass, bypass-pwl.
A policy is WEAK when it bypasses MFA (user_auth_behavior "bypass" or new_user_behavior "no-mfa") or
leaves a phishable method allowed. Anything else (an unrecognised method name) is UNCLEAR.

Rule:
  True   every governing policy is STRONG, so every Duo-protected service, VPN and RDP included,
         requires phishing-resistant MFA.
  False  every governing policy is WEAK, so whichever application is the VPN or RDP gateway, it
         permits a phishable method or no MFA at all.
  Not evaluated (null): the policies differ (some strong, some not). The Policies API does not say
         which application is a VPN or RDP gateway, and guessing from application names would be a
         proxy. Also null on: an error body (a 401 here before Integration-Service signs v5; a 403
         means the Admin API application lacks "Grant resource - Read"), no global policy, a global
         policy with no authentication_methods section, a truncated summary, or a policy list whose
         size does not match summary.policy_count.

Does not prove: the requirement's second clause (service accounts blocked from interactive logins),
or anything about services Duo does not sit in front of.
"""

import json
from datetime import datetime

CRITERIA_KEY = "isStrongAuthRequired"
PHISHING_RESISTANT = ["webauthn-platform", "webauthn-roaming", "webauthn-require-user-verification",
                      "webauthn-platform-pwl", "webauthn-roaming-pwl", "smart-card"]
PHISHABLE = ["duo-push", "duo-push-pwl", "sms", "phonecall", "duo-passcode", "hardware-token", "desktop",
             "bypass", "bypass-pwl"]
WRAPPERS = ["apiResponse", "api_response", "result", "Output", "data"]


def create_response(result, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, api_errors=None, transformation_errors=None, findings=None):
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


def not_evaluated(reason, summary=None, findings=None):
    return create_response({CRITERIA_KEY: None}, api_errors=[reason], fail_reasons=["Not evaluated: " + reason],
                           input_summary=summary, findings=findings)


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


def method_set(value):
    """A Duo method list (list or comma-separated string) as lower-case names."""
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
        name = str(item).strip().lower()
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
        part = part.get("response")
        if isinstance(part, dict):
            text = error_text(part)
            if text:
                return None, text
            part = part.get("policies", part.get("response"))
    if not isinstance(part, list):
        return None, "GET /admin/v2/policies returned no policy list"
    return [p for p in part if isinstance(p, dict)], ""


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


def classify(policy, glob):
    """('strong' | 'weak' | 'unclear', reason) for one governing policy, inheriting from the global one."""
    auth_policy = section(policy, "authentication_policy") or section(glob, "authentication_policy") or {}
    behavior = str(auth_policy.get("user_auth_behavior") or "enforce").strip().lower()
    if behavior == "deny":
        return "strong", "denies authentication to all users"
    if behavior == "bypass":
        return "weak", "skips 2FA for all users (user_auth_behavior bypass)"
    new_user = section(policy, "new_user") or section(glob, "new_user") or {}
    if str(new_user.get("new_user_behavior") or "enroll").strip().lower() == "no-mfa":
        return "weak", "lets unenrolled users sign in without MFA (new_user_behavior no-mfa)"
    methods = section(policy, "authentication_methods") or section(glob, "authentication_methods")
    if methods is None:
        return "unclear", "has no authentication_methods section to read"
    allowed = method_set(methods.get("allowed_auth_list"))
    blocked = method_set(methods.get("blocked_auth_list"))
    if allowed is None or blocked is None:
        return "unclear", "carries an authentication method list that is not a list or string"
    permitted = [m for m in PHISHING_RESISTANT + PHISHABLE if m not in blocked]
    for m in allowed:
        if m not in permitted and m not in blocked:
            permitted.append(m)
    phishable = [m for m in permitted if m in PHISHABLE]
    if phishable:
        return "weak", "allows phishable methods: " + ", ".join(phishable)
    unknown = [m for m in permitted if m not in PHISHING_RESISTANT]
    if unknown:
        return "unclear", "allows methods this check does not recognise: " + ", ".join(unknown)
    if not permitted:
        return "unclear", "blocks every authentication method"
    return "strong", "allows only phishing-resistant methods: " + ", ".join(permitted)


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
REFUSAL_ENDPOINTS = {"policies": "GET /admin/v2/policies", "summary": "GET /admin/v2/policies/summary"}
REFUSAL_PERMISSIONS = {}


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
        if not isinstance(body, dict) or "policies" not in body or "summary" not in body:
            return not_evaluated("the Policies v2 bodies (policies and summary) were not returned")

        policies, text = policy_list(body.get("policies"))
        if text:
            return not_evaluated("GET /admin/v2/policies failed: " + text +
                                 " (needs v5 signing and the Admin API permission 'Grant resource - Read')")
        summary, text = summary_of(body.get("summary"))
        if text:
            return not_evaluated("GET /admin/v2/policies/summary failed: " + text +
                                 " (needs v5 signing and the Admin API permission 'Grant resource - Read')")

        if flag(summary.get("response_is_truncated")) is not False:
            return not_evaluated("the policy summary is truncated or does not say whether it is")
        try:
            count = int(summary.get("policy_count"))
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
                applied[str(entry.get("policy_key"))] = len(entry["policy_applies_to"])
        governing = [glob] + [p for p in policies
                              if p is not glob and str(p.get("policy_key")) in applied]

        verdicts = []
        for p in governing:
            kind, reason = classify(p, glob)
            name = "the global policy" if p is glob else "policy '%s'" % str(p.get("policy_name") or p.get("policy_key"))[:100]
            verdicts.append((kind, name + " " + reason))
        strong = [r for k, r in verdicts if k == "strong"]
        weak = [r for k, r in verdicts if k == "weak"]
        unclear = [r for k, r in verdicts if k == "unclear"]
        info = {"policiesRead": len(policies), "governingPolicies": len(governing),
                "appliedCustomPolicies": len(governing) - 1, "strong": len(strong), "weak": len(weak),
                "unclear": len(unclear)}

        if len(strong) == len(governing):
            return create_response({CRITERIA_KEY: True}, input_summary=info, pass_reasons=[
                "Every Duo policy that governs an application requires phishing-resistant MFA (WebAuthn / "
                "passkeys / smart cards only, no bypass), so VPN, RDP and every other Duo-protected service do"]
                + strong)
        if len(weak) == len(governing):
            return create_response({CRITERIA_KEY: False}, input_summary=info, fail_reasons=[
                "No Duo policy that governs an application requires phishing-resistant MFA, so whichever "
                "application protects VPN or RDP permits a phishable method or no MFA"] + weak,
                recommendations=["In the Duo Admin Panel (Policies), block Duo Push, SMS, phone call, passcodes, "
                                 "OTP tokens, Duo Desktop and bypass codes in the Authentication Methods section of "
                                 "the policies applied to VPN, RDP and other network-service applications, allowing "
                                 "only security keys / passkeys"])
        return not_evaluated("Duo policies differ (%d phishing-resistant, %d not, %d unclear) and the Policies API "
                             "does not say which application is the VPN or RDP gateway" % (
                                 len(strong), len(weak), len(unclear)), summary=info, findings=strong + weak + unclear)
    except Exception as e:
        return create_response({CRITERIA_KEY: None}, transformation_errors=[str(e)],
                               fail_reasons=["Transformation error: %s" % str(e)])
