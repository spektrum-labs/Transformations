"""
Transformation: isConditionalAccessEnabled
Vendor: Duo (Cisco)  |  Integration: Duo (a2abbcf5)  |  Category: Multifactor Authentication

Requirement (Atlas-authored, vendor-agnostic): conditional / contextual access, such as location, network,
device or risk conditions, is applied to authentication.

Evidence: workflow getStrongAuthPolicies (two GETs, merged under output keys), the same input
isStrongAuthRequiredByPolicy reads. Both are Duo Admin API Policies v2 endpoints.
  policies <- GET /admin/v2/policies:         every policy with its enabled sections (a policy's `sections`
                                              lists only the sections that are switched on; a new one has {})
  summary  <- GET /admin/v2/policies/summary: where each policy is applied (policy_applies_to),
                                              policy_count, response_is_truncated (not paged, can truncate)

Which policies are judged (EFFECTIVE): the global policy (it governs every application without its own
policy) plus every custom policy whose summary entry has a non-empty policy_applies_to (apply_type "app" or
"group_app" both count). A custom policy applied to nothing governs nothing and is ignored.

Sections that COUNT as an access condition, and the value that counts:
  user_location        default_action "deny-access" or "require-mfa", or a non-empty
                       deny_access_countries_list / require_mfa_countries_list
  authorized_networks  a non-empty mfa_required.ip_list or blocked.ip_list, or deny_other_access true
  anonymous_networks   anonymous_access_behavior "require-mfa" or "deny"
  trusted_endpoints    trusted_endpoint_checking "require-trusted"
  duo_desktop /        requires_duo_desktop true (the device must run Duo Desktop)
  health_checks
RELAXING values never count: default_action "allow-access-no-2fa" or "ignore-location", a
no_2fa_required network list, anonymous_access_behavior "no-action", trusted_endpoint_checking
"allow-all" / "not-configured", and the allow_access_no_2fa / ignore_location country lists.

Sections that deliberately DO NOT count: operating_systems, browsers, plugins (version hygiene, not an
access condition), remembered_devices (it skips MFA after a first success, the opposite of a condition) and
risk_based_factor_selection (Duo Risk-Based Authentication picks a factor by risk; it does not block or
require MFA by context). Counting RBA is a PRODUCT DECISION left out here on purpose.

Rule:
  True   at least one effective policy sets a restrictive value from the table.
  False  every effective policy was fully read (summary present, not truncated, policy_count equal to the
         policies read, exactly one global policy) and none sets a restrictive value. The message notes
         that Duo Essentials plans only carry authentication_methods, authentication_policy,
         authorized_networks, duo_desktop, new_user, remembered_devices and trusted_endpoints, so a False
         can reflect the plan's available sections as well as a configuration choice.
  Not evaluated (every key null, dataCollection status error): error bodies (stat FAIL, error keys,
         statusCode >= 400), the vendorErrorAsResponse marker (errorCode vendor_refusal; no permission is
         named because Duo's docs do not state which one /admin/v2/policies needs), empty / None / non-JSON /
         non-list input, an empty policy list, a truncated or count-mismatched read, no global policy, a
         recognised enum carrying an unrecognised value, a section of the wrong type, any exception. A
         restrictive value found in an effective policy is still a True even when another section of an
         effective policy is unreadable, since the positive evidence stands on its own.
"""

import json
from datetime import datetime

CRITERIA_KEY = "isConditionalAccessEnabled"
WRAPPERS = ["apiResponse", "api_response", "result", "Output", "data"]
LOCATION_RESTRICTIVE = ["deny-access", "require-mfa"]
LOCATION_RELAXING = ["allow-access-no-2fa", "ignore-location"]
ANON_RESTRICTIVE = ["require-mfa", "deny"]
ANON_RELAXING = ["no-action"]
ENDPOINT_RESTRICTIVE = ["require-trusted"]
ENDPOINT_RELAXING = ["allow-all", "not-configured"]
ESSENTIALS_NOTE = ("Duo Essentials plans only carry the authentication_methods, authentication_policy, "
                   "authorized_networks, duo_desktop, new_user, remembered_devices and trusted_endpoints "
                   "policy sections, so this can reflect the plan's available sections as well as a "
                   "configuration choice")
POLICIES_ENDPOINT = "GET /admin/v2/policies"
SUMMARY_ENDPOINT = "GET /admin/v2/policies/summary"
VENDOR_REFUSAL = "vendor_refusal"


def create_response(result, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, api_errors=None, transformation_errors=None, findings=None,
                    error_code=None):
    collection = {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []}
    if error_code:
        collection["errorCode"] = error_code
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": collection,
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "error" if (transformation_errors or []) else "success",
                               "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0",
                         "transformationId": CRITERIA_KEY, "vendor": "Duo", "category": "Multifactor Authentication"},
        },
    }


def not_evaluated(reason, summary=None, findings=None, error_code=None, transformation_errors=None):
    return create_response({CRITERIA_KEY: None}, api_errors=[reason], fail_reasons=["Not evaluated: " + reason],
                           input_summary=summary, findings=findings, error_code=error_code,
                           transformation_errors=transformation_errors)


def decode(raw):
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    if isinstance(raw, str):
        if raw.strip() == "":
            return None
        return json.loads(raw)
    return raw


def soft_decode(raw):
    """decode() that returns None instead of raising, for places that only look for a marker."""
    try:
        return decode(raw)
    except Exception:
        return None


def find_marker(value, depth=0):
    """The vendorErrorAsResponse marker dict anywhere in the first few levels of value, else None."""
    value = soft_decode(value)
    if not isinstance(value, dict) or depth > 4:
        return None
    if "vendorErrorAsResponse" in value:
        marker = value.get("vendorErrorAsResponse")
        return marker if isinstance(marker, dict) else {}
    for key in value:
        found = find_marker(value[key], depth + 1)
        if found is not None:
            return found
    return None


def refusal_unevaluated(body, marker):
    """Integration-Service handed a vendor refusal over as data. It says nothing about posture, so every key
    stays None; no permission is named because Duo's docs do not state one for the Policies endpoints."""
    status = marker.get("status")
    endpoint = POLICIES_ENDPOINT
    if isinstance(body, dict) and find_marker(body.get("policies")) is None and \
            find_marker(body.get("summary")) is not None:
        endpoint = SUMMARY_ENDPOINT
    problem = "Duo refused the call to %s (HTTP %s); nothing was measured." % (endpoint, str(status)[:10])
    return create_response(
        {CRITERIA_KEY: None}, api_errors=[problem], fail_reasons=["Not evaluated: " + problem],
        recommendations=["Confirm the Duo Admin API credentials are valid and the Admin API application is "
                         "enabled and permitted to read policies"],
        error_code=VENDOR_REFUSAL)


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


def policy_list(part):
    """(policies, error) from the GET /admin/v2/policies output."""
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
        return None, "returned no policy list"
    return [p for p in part if isinstance(p, dict)], ""


def summary_of(part):
    """(summary dict, error) from the GET /admin/v2/policies/summary output."""
    part = decode(part)
    if not isinstance(part, dict):
        return None, "was not returned"
    text = error_text(part)
    if text:
        return None, text
    if isinstance(part.get("response"), dict):
        part = part["response"]
        text = error_text(part)
        if text:
            return None, text
    if not isinstance(part.get("policies"), list):
        return None, "carried no policies list"
    return part, ""


def items(value):
    """A Duo list given as an array or a comma-separated string, as non-blank strings. None when it is
    neither (a wrong type), so the caller can refuse to guess."""
    if value is None:
        return []
    if isinstance(value, str):
        raw = value.split(",")
    elif isinstance(value, list):
        raw = value
    else:
        return None
    out = []
    for item in raw:
        text = str(item).strip()
        if text and text.lower() not in ("none", "null"):
            out.append(text)
    return out


def sub(parent, name, where):
    """(section dict, problem). A missing or null section is {} (disabled); a non-dict one is a problem."""
    value = parent.get(name)
    if value is None:
        return {}, ""
    if not isinstance(value, dict):
        return {}, "%s is not an object" % where
    return value, ""


def enum_value(section, key, restrictive, relaxing, where):
    """('restrictive' | 'relaxing' | 'unset', problem). A present value outside both lists is a problem."""
    value = section.get(key)
    if value is None or (isinstance(value, str) and value.strip() == ""):
        return "unset", ""
    text = str(value).strip().lower()
    if text in restrictive:
        return "restrictive", ""
    if text in relaxing:
        return "relaxing", ""
    return "unset", "%s is '%s', a value this check does not recognise" % (where, str(value)[:40])


def conditions(policy):
    """(restrictive settings found, problems) for one policy. A section the policy does not enable is
    absent from `sections` and contributes nothing."""
    found = []
    problems = []
    sections = policy.get("sections")
    if sections is None:
        sections = {}
    if not isinstance(sections, dict):
        return [], ["its sections value is not an object"]

    def note_problem(text):
        if text:
            problems.append(text)

    loc, text = sub(sections, "user_location", "user_location")
    note_problem(text)
    kind, text = enum_value(loc, "default_action", LOCATION_RESTRICTIVE, LOCATION_RELAXING,
                            "user_location.default_action")
    note_problem(text)
    if kind == "restrictive":
        found.append("user_location default_action is " + str(loc.get("default_action")).strip().lower())
    for key in ("deny_access_countries_list", "require_mfa_countries_list"):
        countries = items(loc.get(key))
        if countries is None:
            problems.append("user_location.%s is neither a list nor a string" % key)
        elif countries:
            found.append("user_location.%s names %d countr%s" % (key, len(countries),
                                                                "y" if len(countries) == 1 else "ies"))

    nets, text = sub(sections, "authorized_networks", "authorized_networks")
    note_problem(text)
    for key in ("mfa_required", "blocked"):
        block, text = sub(nets, key, "authorized_networks." + key)
        note_problem(text)
        addresses = items(block.get("ip_list"))
        if addresses is None:
            problems.append("authorized_networks.%s.ip_list is neither a list nor a string" % key)
        elif addresses:
            found.append("authorized_networks.%s lists %d address range(s)" % (key, len(addresses)))
    deny_other = nets.get("deny_other_access")
    if deny_other is not None:
        if flag(deny_other) is None:
            problems.append("authorized_networks.deny_other_access is not a boolean")
        elif flag(deny_other) is True:
            found.append("authorized_networks denies access from every other network")

    anon, text = sub(sections, "anonymous_networks", "anonymous_networks")
    note_problem(text)
    kind, text = enum_value(anon, "anonymous_access_behavior", ANON_RESTRICTIVE, ANON_RELAXING,
                            "anonymous_networks.anonymous_access_behavior")
    note_problem(text)
    if kind == "restrictive":
        found.append("anonymous_networks behavior is " + str(anon.get("anonymous_access_behavior")).strip().lower())

    endpoints, text = sub(sections, "trusted_endpoints", "trusted_endpoints")
    note_problem(text)
    kind, text = enum_value(endpoints, "trusted_endpoint_checking", ENDPOINT_RESTRICTIVE, ENDPOINT_RELAXING,
                            "trusted_endpoints.trusted_endpoint_checking")
    note_problem(text)
    if kind == "restrictive":
        found.append("trusted_endpoints requires a trusted endpoint")

    for name in ("duo_desktop", "health_checks"):
        block, text = sub(sections, name, name)
        note_problem(text)
        wanted = block.get("requires_duo_desktop")
        if wanted is not None:
            if flag(wanted) is None:
                problems.append("%s.requires_duo_desktop is not a boolean" % name)
            elif flag(wanted) is True:
                found.append("%s requires Duo Desktop on the device" % name)
    return found, problems


def transform(input):
    try:
        raw = decode(input)
        marker = find_marker(raw)
        if marker is not None:
            return refusal_unevaluated(raw, marker)
        body = unwrap(raw)
        text = error_text(body)
        if text:
            return not_evaluated(text)
        if not isinstance(body, dict) or "policies" not in body or "summary" not in body:
            return not_evaluated("the Policies v2 bodies (policies and summary) were not returned")

        policies, text = policy_list(body.get("policies"))
        if text:
            return not_evaluated(POLICIES_ENDPOINT + " failed: " + text)
        summary, text = summary_of(body.get("summary"))
        if text:
            return not_evaluated(SUMMARY_ENDPOINT + " failed: " + text)
        if not policies:
            return not_evaluated(POLICIES_ENDPOINT + " returned an empty policy list")

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
        effective = [glob] + [p for p in policies if p is not glob and str(p.get("policy_key")) in applied]

        restrictive = []
        problems = []
        for p in effective:
            name = "the global policy" if p is glob else "policy '%s'" % str(p.get("policy_name") or p.get("policy_key"))[:100]
            found, trouble = conditions(p)
            restrictive = restrictive + [name + ": " + f for f in found]
            problems = problems + [name + " " + t for t in trouble]
        info = {"policiesRead": len(policies), "effectivePolicies": len(effective),
                "appliedCustomPolicies": len(effective) - 1, "restrictiveSettings": len(restrictive),
                "unreadableSections": len(problems)}

        if restrictive:
            return create_response({CRITERIA_KEY: True}, input_summary=info, findings=problems, pass_reasons=[
                "Duo applies contextual access conditions to authentication (location, network, device or "
                "endpoint rules in an effective policy)"] + restrictive[:20])
        if problems:
            return not_evaluated("an effective policy carries a value this check cannot read, so the absence of "
                                 "access conditions is unproven: " + "; ".join(problems)[:300],
                                 summary=info, findings=problems)
        return create_response(
            {CRITERIA_KEY: False}, input_summary=info,
            fail_reasons=["None of the %d effective Duo policies (the global policy and the policies applied to "
                          "applications) sets a location, network, anonymous-network, trusted-endpoint or Duo "
                          "Desktop access condition. %s" % (len(effective), ESSENTIALS_NOTE)],
            recommendations=["Where the plan offers them, restrict authentication by context in the Duo "
                             "Admin Panel (Policies): user location, authorized networks, anonymous networks, "
                             "trusted endpoints or Duo Desktop"])
    except Exception as e:
        return not_evaluated("the policies could not be read: " + str(e)[:200], transformation_errors=[str(e)])
