"""
Transformation: hasHighRiskUserDetectionAPIAccess (read from Duo policy settings)
Vendor: Duo (Cisco)  |  Integrations: Duo (a2abbcf5), Duo MSP (37d36d50)  |  Category: Multifactor Authentication

What it answers: is Duo's risk-based authentication (high-risk authentication detection) turned on
in the Duo policies that govern the protected applications?

Evidence: workflow getStrongAuthPolicies (two GETs, merged under output keys). Both are Duo Admin API
Policies v2 endpoints. They need v5 signing and the Admin API permission "Grant resource - Read".
  policies <- getDuoPolicies:      GET /admin/v2/policies (paged): every policy with its enabled sections
  summary  <- getDuoPolicySummary: GET /admin/v2/policies/summary: where each policy is applied
              (policy_applies_to), policy_count, response_is_truncated

Duo documents two risk-based settings (duo.com/docs/adminapi, "Policy Section Data"; duo.com/docs/policy;
duo.com/docs/risk-based-auth):
  * risk_based_factor_selection (Risk-Based Factor Selection). "This section is available in the Premier
    and Advantage editions." Key limit_to_risk_based_auth_methods: "true (default) if the user is limited
    to risk-based authentication methods when Duo detects a higher-risk authentication". The policy guide:
    this setting "enables detection and analysis of authentication requests and adaptively enforces the
    most-secure factors".
  * remembered_devices.browser_apps.remember_method: "One of user-based or risk-based (default).
    risk-based only available in the Premier and Advantage editions." Risk-Based Remembered Devices ends a
    remembered session when it detects anomalous access. It applies only when browser_apps.enabled is true.
A setting is ON when limit_to_risk_based_auth_methods is true, or when browser_apps.enabled is true and
remember_method is "risk-based". It is OFF when limit_to_risk_based_auth_methods is false and the browser
remembered-devices setting is disabled or user-based. Anything else is UNCLEAR (fail closed).

Edition: per the docs, the global policy carries every section the edition has, and "Essentials edition
contains: authentication_methods, authentication_policy, authorized_networks, duo_desktop, new_user,
remembered_devices, and trusted_endpoints sections". A global policy with only those sections, and no
policy that shows a risk-based setting, is the Essentials edition, which has no risk-based authentication.
That reads Not evaluated ("edition lacks"), never false and never true.

Governing policies: the global policy (it governs every application without its own policy) plus every
custom policy the summary shows applied to an application or to groups within one. A custom policy
inherits any section it does not set from the global policy.

Rule:
  True   every governing policy turns a risk-based setting on, or the global policy does (custom policies
         that turn it off are listed as findings).
  False  the edition has risk-based authentication and every governing policy turns both settings off.
  Not evaluated (null): the Essentials edition; the global policy off while only some custom policies are
         on; any UNCLEAR policy; an error body or vendorErrorAsResponse marker (a 403 means the Admin API
         application lacks "Grant resource - Read"); no global policy or more than one; a truncated summary;
         or a policy list whose size does not match summary.policy_count.

Scope: Duo speaks only for the applications it protects. Risk-Based Factor Selection acts only on
applications that show the Universal Prompt or use the Duo Auth API application; Risk-Based Remembered
Devices acts only on browser-based applications. The Policies API does not say which applications those are.
"""

import json
from datetime import datetime

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('hasHighRiskUserDetectionAPIAccess',)


def criteria_unmeasured(result):
    """True when every criterion this file answers that the result carries is None.

    Token-Service grades a None criterion as FAILED unless additionalInfo.dataCollection.status
    is "error". The status is read per response, so it is set only when no criterion in the
    result was measured; marking a partly measured result would hide the measured ones.
    """
    present = [k for k in NONE_MEANS_NOT_EVALUATED if k in result]
    return len(present) > 0 and all(result[k] is None for k in present)

CRITERIA_KEY = "hasHighRiskUserDetectionAPIAccess"
TRANSFORMATION_ID = "hasHighRiskUserDetectionByPolicy"
ESSENTIALS_SECTIONS = ["authentication_methods", "authentication_policy", "authorized_networks", "duo_desktop",
                       "new_user", "remembered_devices", "trusted_endpoints"]
WRAPPERS = ["apiResponse", "api_response", "result", "Output", "data"]
SCOPE_NOTE = ("Duo speaks only for the applications it protects: Risk-Based Factor Selection acts on applications "
              "that show the Universal Prompt or use the Duo Auth API application, and Risk-Based Remembered "
              "Devices on browser-based applications.")


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
                         "transformationId": TRANSFORMATION_ID, "vendor": "Duo",
                         "category": "Multifactor Authentication"},
        },
    }


def not_evaluated(reason, summary=None, findings=None, recommendations=None):
    return create_response({CRITERIA_KEY: None}, api_errors=[reason], fail_reasons=["Not evaluated: " + reason],
                           input_summary=summary, findings=findings, recommendations=recommendations)


def decode(raw):
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    if isinstance(raw, str):
        if raw.strip() == "":
            return None
        return json.loads(raw)
    return raw


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


def marker_text(body):
    """A description of a vendorErrorAsResponse marker in body, or ''."""
    if not isinstance(body, dict) or "vendorErrorAsResponse" not in body:
        return ""
    marker = body.get("vendorErrorAsResponse")
    status = marker.get("status") if isinstance(marker, dict) else None
    inner = marker.get("body") if isinstance(marker, dict) else None
    if isinstance(inner, str):
        try:
            inner = json.loads(inner)
        except ValueError:
            inner = None
    code = inner.get("code") if isinstance(inner, dict) else None
    if str(status) == "403":
        return ("Duo refused the Policies v2 read with HTTP 403%s: the Admin API application lacks "
                "\"Grant resource - Read\"" % ((", code %s" % code) if code is not None else ""))
    return "Duo returned an error instead of policy data: %s" % str(marker)[:300]


def error_text(body):
    """Duo's or Integration-Service's error text when body is an error envelope, else ''."""
    if body is None:
        return "no response body"
    if not isinstance(body, dict):
        return ""
    text = marker_text(body)
    if text:
        return text
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


def section_names(policy):
    sections = policy.get("sections")
    if not isinstance(sections, dict):
        return []
    return [str(name) for name in sections]


def rbfs_state(policy, glob):
    """'on' | 'off' | 'absent' | 'unclear' for Risk-Based Factor Selection, inheriting from the global policy."""
    rbfs = section(policy, "risk_based_factor_selection") or section(glob, "risk_based_factor_selection")
    if rbfs is None:
        return "absent"
    value = flag(rbfs.get("limit_to_risk_based_auth_methods"))
    if value is True:
        return "on"
    if value is False:
        return "off"
    return "unclear"


def rbrd_state(policy, glob):
    """'on' | 'off' | 'absent' | 'unclear' for Risk-Based Remembered Devices, inheriting from the global policy."""
    remembered = section(policy, "remembered_devices") or section(glob, "remembered_devices")
    if remembered is None:
        return "absent"
    browser = remembered.get("browser_apps")
    if not isinstance(browser, dict):
        return "unclear"
    enabled = flag(browser.get("enabled"))
    if enabled is False:
        return "off"
    if enabled is None:
        return "unclear"
    method = str(browser.get("remember_method") or "").strip().lower()
    if method == "risk-based":
        return "on"
    if method == "user-based":
        return "off"
    return "unclear"


def classify(policy, glob):
    """('on' | 'off' | 'unclear', reason) for one governing policy."""
    factor = rbfs_state(policy, glob)
    remember = rbrd_state(policy, glob)
    on = []
    if factor == "on":
        on.append("Risk-Based Factor Selection (limit_to_risk_based_auth_methods true)")
    if remember == "on":
        on.append("Risk-Based Remembered Devices (browser_apps remember_method risk-based)")
    if on:
        return "on", "turns on " + " and ".join(on)
    if factor == "off" and remember == "off":
        return "off", ("turns off Risk-Based Factor Selection (limit_to_risk_based_auth_methods false) and does not "
                       "remember browser devices with risk-based protection")
    return "unclear", ("does not say whether risk-based authentication is on (risk_based_factor_selection %s, "
                       "remembered_devices %s)" % (factor, remember))


def transform(input):
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
        if not isinstance(glob.get("sections"), dict):
            return not_evaluated("the global policy carries no sections")

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
            verdicts.append((p is glob, kind, name + " " + reason))
        on = [r for g, k, r in verdicts if k == "on"]
        off = [r for g, k, r in verdicts if k == "off"]
        unclear = [r for g, k, r in verdicts if k == "unclear"]
        global_kind = verdicts[0][1]

        extra = [n for n in section_names(glob) if n not in ESSENTIALS_SECTIONS]
        risk_seen = section(glob, "risk_based_factor_selection") is not None or len(on) > 0
        info = {"policiesRead": len(policies), "governingPolicies": len(governing),
                "appliedCustomPolicies": len(governing) - 1, "riskBasedOn": len(on), "riskBasedOff": len(off),
                "unclear": len(unclear),
                "edition": "advantage-or-premier" if (extra or risk_seen) else "essentials"}

        if not extra and not risk_seen:
            return not_evaluated(
                "the Duo edition lacks risk-based authentication: the global policy carries only the Duo "
                "Essentials sections (%s) and no risk_based_factor_selection section; Risk-Based Factor Selection "
                "and Risk-Based Remembered Devices are Duo Advantage and Premier features" % ", ".join(
                    sorted(section_names(glob))),
                summary=info, findings=on + off + unclear,
                recommendations=["Risk-based authentication needs Duo Advantage or Premier; otherwise answer this "
                                 "requirement by attestation"])

        if len(on) == len(governing) or (global_kind == "on" and not unclear):
            findings = [r for r in off]
            return create_response(
                {CRITERIA_KEY: True}, input_summary=info, findings=findings,
                pass_reasons=["Duo risk-based authentication (high-risk authentication detection) is on in %d of %d "
                              "governing Duo policies, including the global policy that governs every application "
                              "without its own policy. %s" % (len(on), len(governing), SCOPE_NOTE)] + on)
        if len(off) == len(governing):
            return create_response(
                {CRITERIA_KEY: False}, input_summary=info,
                fail_reasons=["The Duo edition offers risk-based authentication, but no governing Duo policy turns "
                              "it on, so Duo does not act on high-risk authentications. %s" % SCOPE_NOTE] + off,
                recommendations=["In the Duo Admin Panel (Policies), enable \"Limit available authentication methods "
                                 "based on risk\" (Risk-Based Factor Selection) and \"Remember devices for browser-based "
                                 "applications with risk-based protection\" in the global policy and in the custom "
                                 "policies applied to applications"])
        return not_evaluated(
            "Duo policies differ or are unclear (%d with risk-based authentication on, %d off, %d unclear): the "
            "global policy does not turn it on or a governing policy does not say, so whether high-risk "
            "authentications are detected across the protected applications cannot be read here. %s" % (len(on), len(off), len(unclear), SCOPE_NOTE),
            summary=info, findings=on + off + unclear)
    except Exception as e:
        return create_response({CRITERIA_KEY: None}, transformation_errors=[str(e)],
                               fail_reasons=["Transformation error: %s" % str(e)])
