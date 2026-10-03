"""
Transformation: isConditionalAccessEnabled (and conditionalAccessAppPercentage)
Vendor: Duo (Cisco)  |  Integration: Duo (a2abbcf5)  |  Category: Multifactor Authentication

Evidence: workflow getApplicationPolicyCoverage (three GETs, merged under output keys). All are Duo Admin API
endpoints, v5-signed by Integration-Service, and need "Grant resource - Read".
  policies     <- getDuoPolicies:      GET /admin/v2/policies (paged): every policy with its sections
  summary      <- getDuoPolicySummary: GET /admin/v2/policies/summary: where each policy is applied
                  (policy_applies_to), policy_count, response_is_truncated
  integrations <- getIntegrations:     GET /admin/v3/integrations (paged): every Duo-protected application.
                  An application's policy_key names the custom policy attached to it and is absent when none
                  is, so an application without one is governed by the global policy.

What is judged: every application. Its effective policy is its own policy's sections, falling back SECTION BY
SECTION to the global policy's sections (Duo: "custom policies only need to specify the settings they wish to
enforce"; the higher-precedence policy wins for a setting both configure). An application is COVERED when its
effective policy carries at least one access condition.

A CONDITION is a non-default setting that blocks access on a context signal. Only these count:
  user_location         default_action "deny-access", or a non-empty deny_access_countries_list (geo-blocking)
  anonymous_networks    anonymous_access_behavior "deny" (anonymous proxies, VPNs and Tor blocked)
  authorized_networks   deny_other_access true, or a non-empty blocked.ip_list
  trusted_endpoints     trusted_endpoint_checking "require-trusted"
  health_checks /       requires_duo_desktop, enforce_encryption, enforce_firewall, enforce_system_password or
  duo_desktop           an *_endpoint_security_list naming at least one OS or agent; enforce_signed_payload or
                        enforce_device_id_pinning "enforce-enabled". requires_duo_desktop is a LIST of operating
                        system names (["windows"]), empty when Duo Desktop is not required.
  operating_systems     a non-empty block_os_list, or an os_restrictions block_policy other than "no-remediation"
  browsers              a non-empty blocked_browsers_list, or out_of_date_behavior "warn-and-block"
  full_disk_encryption  require_encryption true
Not counted, because they are Duo defaults or not access conditions: authentication_methods,
authentication_policy, new_user, remembered_devices, risk_based_factor_selection, screen_lock,
tampered_devices, duo_mobile_app, mobile_device_biometrics, plugins, and "require-mfa" settings (MFA is
already required by the authentication policy, so they add no block). A policy that carries only defaults
is not conditional access. Lower Duo tiers do not return user_location or anonymous_networks at all; an
absent section is simply not a condition.

Application-group (group_app) bindings: some users of an application get a different policy, which
application-level data cannot resolve. An application with any such binding is INDETERMINATE: counted neither
covered nor uncovered, and while any application is indeterminate the boolean is never True. (Its group policies
are still read, so an unreadable one fails closed.)

Rule:
  isConditionalAccessEnabled
    True   every application is covered.
    False  the applications were fully enumerated and at least one is not covered.
    Not evaluated (null): an error body or vendorErrorAsResponse marker (a 403 means the Admin API application
           lacks "Grant resource - Read"); integrations missing, empty or not a list, or not read to the end
           (paginationTruncated / truncated set, metadata.next_offset remaining, or metadata.total_objects
           differing from the applications read); policies or summary
           missing; a truncated summary; a policy list whose size does not match summary.policy_count; no or
           several global policies; an application whose policy_key is not in the policy list; a section of a
           governing policy that is not an object, or a wrong-typed value or unrecognised enum in one; no
           uncovered application but at least one indeterminate one; any exception.
  conditionalAccessAppPercentage  covered applications / all applications * 100, one decimal. Emitted whenever
           the applications were enumerated and read, including when the boolean is False.
  conditionalAccessAppsCovered, conditionalAccessAppsTotal, conditionalAccessAppsOnGlobalPolicy,
  conditionalAccessAppsIndeterminate: the supporting counts.

Known limit: USER-GROUP policies (precedence below application, above global) are invisible in this data, so a
tenant that applies its conditions by user group is UNDERSTATED here. Resolving them needs the group membership
endpoints (GET /admin/v2/groups/{id}/users).

Does not prove: impossible-travel or risk scoring (Duo Trust Monitor is not in the Policies API), or anything
about services Duo does not sit in front of.
"""

import json
from datetime import datetime

CRITERIA_KEY = "isConditionalAccessEnabled"
PERCENT_KEY = "conditionalAccessAppPercentage"
COVERED_KEY = "conditionalAccessAppsCovered"
TOTAL_KEY = "conditionalAccessAppsTotal"
GLOBAL_COUNT_KEY = "conditionalAccessAppsOnGlobalPolicy"
INDETERMINATE_KEY = "conditionalAccessAppsIndeterminate"
WRAPPERS = ["apiResponse", "api_response", "result", "Output", "data"]
PARTS = ("policies", "summary", "integrations")
CONDITION_SECTIONS = ["user_location", "anonymous_networks", "authorized_networks", "trusted_endpoints",
                      "health_checks", "duo_desktop", "operating_systems", "browsers", "full_disk_encryption"]
HEALTH_LISTS = ["requires_duo_desktop", "enforce_encryption", "enforce_firewall", "enforce_system_password",
                "windows_endpoint_security_list", "macos_endpoint_security_list", "linux_endpoint_security_list"]
GRANT = "the Admin API permission 'Grant resource - Read'"
NAMED_LIMIT = 10


UNREADABLE = "unreadable setting: "


def unreadable(message):
    """An error that marks a policy setting this check cannot read (RestrictedPython allows no class here)."""
    return ValueError(UNREADABLE + message)


def create_response(result, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, api_errors=None, transformation_errors=None, findings=None, warnings=None):
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": "unknown", "errors": [], "warnings": warnings or []},
            "transformation": {"status": "error" if (transformation_errors or []) else "success",
                               "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0",
                         "transformationId": CRITERIA_KEY, "vendor": "Duo", "category": "Multifactor Authentication"},
        },
    }


def empty_result():
    return {CRITERIA_KEY: None, PERCENT_KEY: None, COVERED_KEY: None, TOTAL_KEY: None, GLOBAL_COUNT_KEY: None,
            INDETERMINATE_KEY: None}


def not_evaluated(reason, summary=None, findings=None):
    return create_response(empty_result(), api_errors=[reason], fail_reasons=["Not evaluated: " + reason],
                           input_summary=summary, findings=findings)


def decode(raw):
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    if isinstance(raw, str):
        if raw.strip() == "":
            return None
        return json.loads(raw)
    return raw


def marker_text(body):
    """Integration-Service's vendorErrorAsResponse marker as an error text, else ''."""
    if not isinstance(body, dict) or "vendorErrorAsResponse" not in body:
        return ""
    marker = body.get("vendorErrorAsResponse")
    status = ""
    detail = body
    if isinstance(marker, dict):
        status = str(marker.get("status") or "")
        detail = marker.get("body")
    detail = decode(detail) if isinstance(detail, (str, bytes)) else detail
    code = ""
    message = ""
    if isinstance(detail, dict):
        code = str(detail.get("code") or "")
        message = str(detail.get("message") or "")
    text = ("Duo answered HTTP %s %s %s" % (status or "error", code, message)).strip()
    if status == "403" or code == "40301":
        text = text + " (the Admin API application needs " + GRANT + ")"
    return text[:300]


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

# The enum values Duo documents for each deciding setting. A value outside its set is not guessed at: it makes
# the setting unreadable, so an unrecognised value can neither count as a condition nor quietly count as none.
DEFAULT_ACTIONS = ("deny-access", "ignore-location", "require-mfa", "no-2fa", "allow-access-no-2fa")
ANONYMOUS_BEHAVIOURS = ("deny", "no-action", "require-mfa")
TRUSTED_CHECKING = ("require-trusted", "allow-all", "not-configured")
OUT_OF_DATE_BEHAVIOURS = ("warn-and-block", "no-remediation", "warn-only")
ENFORCEMENT = ("enforce-enabled", "no-enforcement", "enforce-disabled", "warn-only")
OS_POLICIES = OS_BLOCK_POLICIES + ("no-remediation", "warn-only")


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


def enum(section, key, allowed, field):
    """The lower-cased enum value of a setting, '' when absent; unreadable when wrong-typed or unrecognised."""
    value = section.get(key)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise unreadable(field + " is not text")
    text = word(value)
    if text == "":
        return ""
    if text not in allowed:
        raise unreadable(field + " holds a value that is not a known setting: " + text[:30])
    return text


def unwrap(body):
    for attempt in range(3):
        if not isinstance(body, dict):
            return body
        for part in PARTS:
            if part in body:
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


def incomplete_text(container):
    """Why a paged applications read is incomplete, '' when nothing says it is. Integration-Service marks a read it
    stopped early with paginationTruncated (on the envelope or its response_metadata) and metadata.truncated, and
    clears metadata.next_offset once every page is read."""
    if not isinstance(container, dict):
        return ""
    meta_blocks = [container]
    for key in ("response_metadata", "metadata"):
        if isinstance(container.get(key), dict):
            meta_blocks.append(container[key])
    for block in meta_blocks:
        for key in ("paginationTruncated", "truncated"):
            if key in block and flag(block.get(key)) is not False:
                return "GET /admin/v3/integrations was not read to the end (%s is set)" % key
    metadata = container.get("metadata")
    if isinstance(metadata, dict):
        next_offset = metadata.get("next_offset")
        if next_offset is not None and str(next_offset).strip() not in ("", "none", "null"):
            return "GET /admin/v3/integrations was not read to the end (metadata.next_offset remains)"
    return ""


def expected_total(container):
    """metadata.total_objects when the envelope carries it, else None; unreadable -> -1 (never matches)."""
    if not isinstance(container, dict) or not isinstance(container.get("metadata"), dict):
        return None
    if "total_objects" not in container["metadata"]:
        return None
    value = container["metadata"].get("total_objects")
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return -1


def integration_list(part, body=None):
    """(applications, error) from the getIntegrations output; every entry must be an application object and the
    list must be complete."""
    part = decode(part)
    totals = []
    for container in (body, part):
        text = incomplete_text(container)
        if text:
            return None, text
    if isinstance(part, dict):
        text = error_text(part)
        if text:
            return None, text
        totals.append(expected_total(part))
        part = part.get("response", part.get("integrations"))
        if isinstance(part, dict):
            text = error_text(part) or incomplete_text(part)
            if text:
                return None, text
            totals.append(expected_total(part))
            part = part.get("integrations", part.get("response"))
    if not isinstance(part, list):
        return None, "GET /admin/v3/integrations returned no application list"
    if not part:
        return None, "GET /admin/v3/integrations returned no applications"
    apps = []
    for entry in part:
        if not isinstance(entry, dict):
            return None, "GET /admin/v3/integrations returned an entry that is not an application"
        key = entry.get("integration_key")
        if not isinstance(key, str) or key.strip() == "":
            return None, "GET /admin/v3/integrations returned an application without an integration_key"
        apps.append(entry)
    for total in totals:
        if total is not None and total != len(apps):
            return None, ("GET /admin/v3/integrations reports %s applications but %d were read"
                          % ("an unreadable count of" if total < 0 else str(total), len(apps)))
    return apps, ""


def sections_of(policy):
    sections = policy.get("sections")
    if sections is None:
        return {}
    if not isinstance(sections, dict):
        raise unreadable("policy '%s' carries sections that are not an object" % name_of(policy))
    return sections


def name_of(policy):
    return str(policy.get("policy_name") or policy.get("policy_key") or "unnamed")[:100]


def app_name(app):
    return str(app.get("name") or app.get("integration_key") or "unnamed")[:100]


def effective_section(chain, name):
    """The section that governs: the first policy in chain (highest precedence first) that sets it; {} if none."""
    for source in chain:
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
    field = section_name + "."
    if section_name == "user_location":
        if enum(s, "default_action", DEFAULT_ACTIONS, field + "default_action") == "deny-access":
            found.append("user location: unlisted countries are denied")
        denied = real_items(s.get("deny_access_countries_list"), is_country, field + "deny_access_countries_list")
        if denied:
            found.append("user location: %d countr%s denied" % (len(denied), "y" if len(denied) == 1 else "ies"))
    elif section_name == "anonymous_networks":
        if enum(s, "anonymous_access_behavior", ANONYMOUS_BEHAVIOURS, field + "anonymous_access_behavior") == "deny":
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
        if enum(s, "trusted_endpoint_checking", TRUSTED_CHECKING, field + "trusted_endpoint_checking") \
                == "require-trusted":
            found.append("trusted endpoints: only managed (trusted) endpoints may sign in")
    elif section_name in ("health_checks", "duo_desktop"):
        named = [k for k in HEALTH_LISTS if real_items(s.get(k), HEALTH_VALIDATORS[k], field + k)]
        if named:
            found.append("device health (%s): %s" % (section_name, ", ".join(named)))
        for k in ("enforce_signed_payload", "enforce_device_id_pinning"):
            if enum(s, k, ENFORCEMENT, field + k) == "enforce-enabled":
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
                policy_word = enum(rule, "block_policy", OS_POLICIES,
                                   "operating_systems.os_restrictions.%s.block_policy" % str(os_name)[:20])
                if policy_word in OS_BLOCK_POLICIES:
                    found.append("operating systems: out-of-date %s blocked (%s)" % (str(os_name)[:20], policy_word))
    elif section_name == "browsers":
        blocked_browsers = real_items(s.get("blocked_browsers_list"), in_browsers, "browsers.blocked_browsers_list")
        if blocked_browsers:
            found.append("browsers: %s blocked" % ", ".join([x[:20] for x in blocked_browsers[:10]]))
        if enum(s, "out_of_date_behavior", OUT_OF_DATE_BEHAVIOURS, field + "out_of_date_behavior") == "warn-and-block":
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


def conditions_of(chain):
    found = []
    for name in CONDITION_SECTIONS:
        found.extend(conditions_in(name, effective_section(chain, name)))
    return found


def named(labels):
    shown = ", ".join(labels[:NAMED_LIMIT])
    if len(labels) > NAMED_LIMIT:
        shown = shown + " and %d more" % (len(labels) - NAMED_LIMIT)
    return shown


def group_bindings(summary):
    """[(policy_key, integration_key)] for every application-group (group_app) binding in the summary."""
    out = []
    for entry in summary["policies"]:
        if not isinstance(entry, dict):
            continue
        applies = entry.get("policy_applies_to")
        if not isinstance(applies, list):
            continue
        for target in applies:
            if not isinstance(target, dict) or word(target.get("apply_type")) != "group_app":
                continue
            key = target.get("app_integration_key", target.get("integration_key"))
            out.append((str(entry.get("policy_key")), str(key)))
    return out


def transform(input):
    try:
        body = unwrap(decode(input))
        text = error_text(body)
        if text:
            return not_evaluated(text)
        if not isinstance(body, dict) or "policies" not in body or "summary" not in body:
            return not_evaluated("the Policies v2 bodies (policies and summary) were not returned")
        if "integrations" not in body:
            return not_evaluated("the applications list (GET /admin/v3/integrations) was not returned; the check "
                                 "needs the getApplicationPolicyCoverage workflow")

        policies, text = policy_list(body.get("policies"))
        if text:
            return not_evaluated("GET /admin/v2/policies failed: " + text + " (needs " + GRANT + ")")
        summary, text = summary_of(body.get("summary"))
        if text:
            return not_evaluated("GET /admin/v2/policies/summary failed: " + text + " (needs " + GRANT + ")")
        apps, text = integration_list(body.get("integrations"), body)
        if text:
            return not_evaluated(text + " (needs " + GRANT + ")")

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
        by_key = {}
        for p in policies:
            by_key[str(p.get("policy_key"))] = p

        app_keys = [str(a.get("integration_key")) for a in apps]
        groups = {}
        for policy_key, integration_key in group_bindings(summary):
            if policy_key not in by_key:
                return not_evaluated("an application-group binding names a policy the policy list does not carry")
            if integration_key not in app_keys:
                return not_evaluated("an application-group binding names an application the applications list "
                                     "does not carry, so the list is incomplete")
            groups.setdefault(integration_key, []).append(by_key[policy_key])

        covered = []
        uncovered = []
        indeterminate = []
        on_global = 0
        try:
            for app in apps:
                policy_key = app.get("policy_key")
                if policy_key is None or str(policy_key).strip() == "":
                    own = glob
                else:
                    own = by_key.get(str(policy_key))
                    if own is None:
                        return not_evaluated("application '%s' names a policy_key the policy list does not carry"
                                             % app_name(app))
                if own is glob:
                    on_global = on_global + 1
                chain = [glob] if own is glob else [own, glob]
                found = conditions_of(chain)
                bound = groups.get(str(app.get("integration_key")), [])
                for group_policy in bound:
                    # read every group policy so an unreadable one still fails closed
                    conditions_of([group_policy] + chain)
                if bound:
                    indeterminate.append(app_name(app))
                elif found:
                    covered.append((app_name(app), found))
                else:
                    uncovered.append(app_name(app))
        except ValueError as e:
            if not str(e).startswith(UNREADABLE):
                raise
            return not_evaluated("a policy setting cannot be read: " + str(e)[len(UNREADABLE):])

        total = len(apps)
        percentage = round(len(covered) * 100.0 / total, 1)
        result = {CRITERIA_KEY: None, PERCENT_KEY: percentage, COVERED_KEY: len(covered), TOTAL_KEY: total,
                  GLOBAL_COUNT_KEY: on_global, INDETERMINATE_KEY: len(indeterminate)}
        info = {"policiesRead": len(policies), "applications": total, "applicationsCovered": len(covered),
                "applicationsUncovered": len(uncovered), "applicationsIndeterminate": len(indeterminate),
                "applicationsOnGlobalPolicy": on_global, "groupBindings": sum([len(v) for v in groups.values()])}
        described = [label + ": " + "; ".join(found[:6]) for label, found in covered[:NAMED_LIMIT]]
        indeterminate_note = []
        if indeterminate:
            indeterminate_note = ["Application-group policies apply to some users of these applications, which "
                                  "application-level data cannot resolve, so they are counted neither covered nor "
                                  "uncovered: " + named(indeterminate)]
        user_group_note = ("User-group policies are not visible to this check, so coverage applied by user group "
                           "is understated")

        if uncovered:
            result[CRITERIA_KEY] = False
            return create_response(result, input_summary=info, findings=described + indeterminate_note,
                                   fail_reasons=["%d of %d Duo applications have no access condition in their "
                                                 "effective policy (%.1f%% covered): %s" % (
                                                     len(uncovered), total, percentage, named(uncovered))],
                                   recommendations=["In the Duo Admin Panel (Policies), add a blocking condition to "
                                                    "the global policy or to the policy of each application named, "
                                                    "for example Trusted Endpoints (require trusted), Device Health "
                                                    "or Duo Desktop requirements, Authorized Networks, or (on tiers "
                                                    "that offer them) User Location and Anonymous Networks",
                                                    user_group_note])
        if indeterminate:
            return create_response(result, input_summary=info, findings=described + indeterminate_note,
                                   fail_reasons=["Not evaluated: no application is uncovered, but %d cannot be "
                                                 "decided from application-level data" % len(indeterminate)],
                                   api_errors=indeterminate_note, warnings=indeterminate_note)
        result[CRITERIA_KEY] = True
        return create_response(result, input_summary=info, findings=described, pass_reasons=[
            "All %d Duo applications have an access condition (location, network, device health, OS, browser or "
            "endpoint trust) in their effective policy" % total], recommendations=[user_group_note])
    except Exception as e:
        return create_response(empty_result(), transformation_errors=[str(e)],
                               fail_reasons=["Transformation error: %s" % str(e)])
