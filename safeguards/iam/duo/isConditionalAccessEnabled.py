"""
Transformation: isConditionalAccessEnabled
Vendor: Duo (Cisco)  |  Integration: Duo (a2abbcf5)  |  Category: Multifactor Authentication

Evidence: workflow getStrongAuthPolicies (two GETs, merged under output keys). Both are Duo Admin API
Policies v2 endpoints (v5-signed by Integration-Service) and need "Grant resource - Read".
  policies <- getDuoPolicies:      GET /admin/v2/policies (paged): every policy with its enabled sections
  summary  <- getDuoPolicySummary: GET /admin/v2/policies/summary: where each policy is applied
              (policy_applies_to), policy_count, response_is_truncated

What is judged: every policy that can govern a Duo-protected application. That is the global policy (it
governs every application without its own policy) plus every custom policy the summary shows applied to
an application or to groups within one. A custom policy inherits, section by section, every section it
does not set from the global policy (Duo builds the resulting policy from the top-most section in the
stack). Unapplied custom policies govern nothing.

A CONDITION is a non-default setting that blocks access on a context signal. Only these count:
  user_location         default_action "deny-access", or a non-empty deny_access_countries_list (geo-blocking)
  anonymous_networks    anonymous_access_behavior "deny" (anonymous proxies, VPNs and Tor blocked)
  authorized_networks   deny_other_access true, or a non-empty blocked.ip_list
  trusted_endpoints     trusted_endpoint_checking "require-trusted"
  health_checks /       requires_duo_desktop, enforce_encryption, enforce_firewall, enforce_system_password or
  duo_desktop           an *_endpoint_security_list naming at least one OS or agent; enforce_signed_payload or
                        enforce_device_id_pinning "enforce-enabled"
  operating_systems     a non-empty block_os_list, or an os_restrictions block_policy other than "no-remediation"
  browsers              a non-empty blocked_browsers_list, or out_of_date_behavior "warn-and-block"
  full_disk_encryption  require_encryption true
Not counted, because they are Duo defaults or not access conditions: authentication_methods,
authentication_policy, new_user, remembered_devices, risk_based_factor_selection, screen_lock,
tampered_devices, duo_mobile_app, mobile_device_biometrics, plugins, and "require-mfa" settings (MFA is
already required by the authentication policy, so they add no block). A policy that carries only defaults
is not conditional access.

Rule:
  True   every governing policy carries at least one condition, so every Duo-protected application blocks
         access on location, network, device health, OS, browser or endpoint trust.
  False  no governing policy carries any condition (the global policy and every applied custom policy are
         defaults-only with respect to access conditions).
  Not evaluated (null): the governing policies differ (some carry a condition, some do not). The Policies API
         does not say which applications fall to the global policy or which application is the VPN, email or
         IAM gateway, so partial coverage is not graded. Also null on: an error body (a 403 means the Admin API
         application lacks "Grant resource - Read"), no or several global policies, a truncated summary, a
         policy list whose size does not match summary.policy_count, a section that is not an object, or a
         list or flag that cannot be read.

Does not prove: impossible-travel or risk scoring (Duo Trust Monitor is not in the Policies API), or anything
about services Duo does not sit in front of.
"""

import json
from datetime import datetime

CRITERIA_KEY = "isConditionalAccessEnabled"
WRAPPERS = ["apiResponse", "api_response", "result", "Output", "data"]
CONDITION_SECTIONS = ["user_location", "anonymous_networks", "authorized_networks", "trusted_endpoints",
                      "health_checks", "duo_desktop", "operating_systems", "browsers", "full_disk_encryption"]
HEALTH_LISTS = ["requires_duo_desktop", "enforce_encryption", "enforce_firewall", "enforce_system_password",
                "windows_endpoint_security_list", "macos_endpoint_security_list", "linux_endpoint_security_list"]
GRANT = "the Admin API permission 'Grant resource - Read'"


UNREADABLE = "unreadable setting: "


def unreadable(message):
    """An error that marks a policy setting this check cannot read (RestrictedPython allows no class here)."""
    return ValueError(UNREADABLE + message)


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


def items(value):
    """A Duo list (JSON list or comma-separated string) as non-empty strings; [] when absent."""
    if value is None:
        return []
    if isinstance(value, str):
        parts = value.split(",")
    elif isinstance(value, list):
        parts = value
    else:
        raise unreadable("a list that is neither a list nor a comma-separated string")
    out = []
    for part in parts:
        text = str(part).strip()
        if text:
            out.append(text)
    return out


def word(value):
    return str(value or "").strip().lower()


# Values that mean "nothing set" when Integration-Service stringifies an empty or false field.
EMPTY_TOKENS = ("", "none", "null", "false", "true", "[]", "{}", "n/a", "no", "off", "0", "disabled", "disable",
                "not-required", "not_required")
PLATFORMS = ("windows", "macos", "linux")
OS_NAMES = ("android", "ios", "ipados", "windows", "macos", "linux", "chromeos", "blackberry", "windows-phone",
            "windowsphone", "other", "unknown")
BROWSERS = ("chrome", "firefox", "safari", "edge", "ie", "internet-explorer", "opera", "brave", "chromium",
            "other", "unknown")
OS_BLOCK_POLICIES = ("end-of-life", "not-up-to-date", "less-than-version", "less-than-latest-version",
                     "less-than-latest")


def is_country(v):
    return len(v) == 2 and v.isalpha()


def is_network(v):
    """An IPv4/IPv6 address or CIDR, or an IPv4 range a.b.c.d-e.f.g.h (the forms Duo accepts)."""
    allowed = "0123456789abcdefABCDEF.:/-"
    return any(ch.isdigit() for ch in v) and all(ch in allowed for ch in v) and ("." in v or ":" in v)


# Endpoint-security agents Duo Desktop can require (Duo Policy API endpoint_security lists), in the token forms
# Duo uses. Anything else is not counted as a condition: it makes the setting unreadable (fail closed).
ENDPOINT_SECURITY_VENDORS = ("cisco-secure-endpoint", "cisco-amp", "crowdstrike", "crowdstrike-falcon", "cylance",
                             "eset", "f-secure", "withsecure", "mcafee", "trellix", "windows-defender",
                             "microsoft-defender", "defender", "palo-alto-cortex-xdr", "palo-alto-traps",
                             "cortex-xdr", "sentinelone", "sophos", "sophos-intercept-x", "symantec",
                             "broadcom-symantec", "trend-micro", "trendmicro", "carbon-black", "vmware-carbon-black",
                             "malwarebytes", "bitdefender", "kaspersky", "webroot", "avast", "avg", "norton",
                             "fortinet", "fortiedr", "fortinet-forticlient", "cybereason", "deep-instinct",
                             "elastic-endpoint", "harfanglab", "cisco-secure-client", "jamf-protect", "xprotect")


def is_vendor(v):
    return v.lower() in ENDPOINT_SECURITY_VENDORS


def real_items(value, valid, field):
    """The meaningful entries of a Duo list setting. Stringified empties ("False", "[]", "none") are not entries.
    Every remaining entry must be a known value for the field; anything else makes the setting unreadable, so an
    unrecognised value can never count as a condition (fail closed)."""
    if isinstance(value, str) and value.strip().startswith("["):
        try:
            value = json.loads(value)
        except Exception:
            raise unreadable(field + " is a malformed list")
    out = []
    for entry in items(value):
        token = entry.strip().strip("\"'").strip()
        if token.lower() in EMPTY_TOKENS:
            continue
        if not valid(token.lower() if valid in (in_platforms, in_os, in_browsers) else token):
            raise unreadable(field + " holds a value that is not a known setting: " + token[:20])
        out.append(token)
    return out


def in_platforms(v):
    return v in PLATFORMS


def in_os(v):
    return v in OS_NAMES


def in_browsers(v):
    return v in BROWSERS


HEALTH_VALIDATORS = {"requires_duo_desktop": in_platforms, "enforce_encryption": in_platforms,
                     "enforce_firewall": in_platforms, "enforce_system_password": in_platforms,
                     "windows_endpoint_security_list": is_vendor, "macos_endpoint_security_list": is_vendor,
                     "linux_endpoint_security_list": is_vendor}


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


def sections_of(policy):
    sections = policy.get("sections")
    if sections is None:
        return {}
    if not isinstance(sections, dict):
        raise unreadable("policy '%s' carries sections that are not an object" % name_of(policy))
    return sections


def name_of(policy):
    return str(policy.get("policy_name") or policy.get("policy_key") or "unnamed")[:100]


def effective_section(policy, glob, name):
    """The section that governs: the policy's own, else the global policy's; {} when neither sets it."""
    for source in (policy, glob):
        sections = sections_of(source)
        if name in sections:
            value = sections[name]
            if value is None:
                return {}
            if not isinstance(value, dict):
                raise unreadable("section %s of policy '%s' is not an object" % (name, name_of(source)))
            return value
    return {}


def conditions_in(section_name, s):
    """The access conditions one section imposes (a list of short descriptions)."""
    found = []
    if section_name == "user_location":
        if word(s.get("default_action")) == "deny-access":
            found.append("user location: unlisted countries are denied")
        denied = real_items(s.get("deny_access_countries_list"), is_country, "user_location.deny_access_countries_list")
        if denied:
            found.append("user location: %d countr%s denied" % (len(denied), "y" if len(denied) == 1 else "ies"))
    elif section_name == "anonymous_networks":
        if word(s.get("anonymous_access_behavior")) == "deny":
            found.append("anonymous networks (proxies, VPNs, Tor) are denied")
    elif section_name == "authorized_networks":
        deny_other = s.get("deny_other_access")
        if deny_other is not None:
            value = flag(deny_other)
            if value is None:
                raise unreadable("authorized_networks.deny_other_access is not a boolean")
            if value:
                found.append("authorized networks: access from other networks is denied")
        blocked = s.get("blocked")
        if blocked is not None:
            if not isinstance(blocked, dict):
                raise unreadable("authorized_networks.blocked is not an object")
            if real_items(blocked.get("ip_list"), is_network, "authorized_networks.blocked.ip_list"):
                found.append("authorized networks: listed networks are blocked")
    elif section_name == "trusted_endpoints":
        if word(s.get("trusted_endpoint_checking")) == "require-trusted":
            found.append("trusted endpoints: only managed (trusted) endpoints may sign in")
    elif section_name in ("health_checks", "duo_desktop"):
        named = [k for k in HEALTH_LISTS if real_items(s.get(k), HEALTH_VALIDATORS[k], section_name + "." + k)]
        if named:
            found.append("device health (%s): %s" % (section_name, ", ".join(named)))
        for k in ("enforce_signed_payload", "enforce_device_id_pinning"):
            if word(s.get(k)) == "enforce-enabled":
                found.append("device health (%s): %s" % (section_name, k))
    elif section_name == "operating_systems":
        blocked_os = real_items(s.get("block_os_list"), in_os, "operating_systems.block_os_list")
        if blocked_os:
            found.append("operating systems: %s blocked" % ", ".join([x[:20] for x in blocked_os[:9]]))
        restrictions = s.get("os_restrictions")
        if restrictions is not None:
            if not isinstance(restrictions, dict):
                raise unreadable("operating_systems.os_restrictions is not an object")
            for os_name in sorted(restrictions.keys()):
                rule = restrictions[os_name]
                if not isinstance(rule, dict):
                    raise unreadable("operating_systems.os_restrictions.%s is not an object" % str(os_name)[:20])
                policy_word = word(rule.get("block_policy"))
                if policy_word in OS_BLOCK_POLICIES:
                    found.append("operating systems: out-of-date %s blocked (%s)" % (str(os_name)[:20], policy_word[:30]))
    elif section_name == "browsers":
        blocked_browsers = real_items(s.get("blocked_browsers_list"), in_browsers, "browsers.blocked_browsers_list")
        if blocked_browsers:
            found.append("browsers: %s blocked" % ", ".join([x[:20] for x in blocked_browsers[:10]]))
        if word(s.get("out_of_date_behavior")) == "warn-and-block":
            found.append("browsers: out-of-date browsers blocked")
    elif section_name == "full_disk_encryption":
        value = s.get("require_encryption")
        if value is not None:
            parsed = flag(value)
            if parsed is None:
                raise unreadable("full_disk_encryption.require_encryption is not a boolean")
            if parsed:
                found.append("full-disk encryption required")
    return found


def conditions_of(policy, glob):
    found = []
    for name in CONDITION_SECTIONS:
        found.extend(conditions_in(name, effective_section(policy, glob, name)))
    return found


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
            return not_evaluated("GET /admin/v2/policies failed: " + text + " (needs " + GRANT + ")")
        summary, text = summary_of(body.get("summary"))
        if text:
            return not_evaluated("GET /admin/v2/policies/summary failed: " + text + " (needs " + GRANT + ")")

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

        applied = []
        for entry in summary["policies"]:
            if isinstance(entry, dict) and isinstance(entry.get("policy_applies_to"), list) \
                    and entry["policy_applies_to"]:
                applied.append(str(entry.get("policy_key")))
        governing = [glob] + [p for p in policies if p is not glob and str(p.get("policy_key")) in applied]

        try:
            verdicts = []
            for p in governing:
                label = "the global policy" if p is glob else "policy '%s'" % name_of(p)
                verdicts.append((label, conditions_of(p, glob)))
        except ValueError as e:
            if not str(e).startswith(UNREADABLE):
                raise
            return not_evaluated("a policy setting cannot be read: " + str(e)[len(UNREADABLE):])

        with_conditions = [(label, found) for label, found in verdicts if found]
        without = [label for label, found in verdicts if not found]
        info = {"policiesRead": len(policies), "governingPolicies": len(governing),
                "appliedCustomPolicies": len(governing) - 1, "policiesWithConditions": len(with_conditions),
                "policiesWithoutConditions": len(without)}
        described = [label + ": " + "; ".join(found[:6]) for label, found in with_conditions]

        if not without:
            return create_response({CRITERIA_KEY: True}, input_summary=info, pass_reasons=[
                "Every Duo policy that governs an application blocks access on a context condition (location, "
                "network, device health, OS, browser or endpoint trust)"] + described)
        if not with_conditions:
            return create_response({CRITERIA_KEY: False}, input_summary=info, fail_reasons=[
                "No Duo policy that governs an application carries an access condition: the global policy and "
                "every applied custom policy keep Duo's defaults for location, anonymous networks, authorized "
                "networks, device health, operating systems, browsers, encryption and trusted endpoints"],
                recommendations=["In the Duo Admin Panel (Policies), add blocking conditions to the global policy, "
                                 "for example User Location (deny high-risk countries), Anonymous Networks (deny), "
                                 "Trusted Endpoints (require trusted) or Device Health checks"])
        return not_evaluated("Duo policies differ (%d carry an access condition, %d do not: %s) and the Policies API "
                             "does not say which applications fall to which policy" % (
                                 len(with_conditions), len(without), ", ".join(without[:5])),
                             summary=info, findings=described)
    except Exception as e:
        return create_response({CRITERIA_KEY: None}, transformation_errors=[str(e)],
                               fail_reasons=["Transformation error: %s" % str(e)])
