"""
Transformation: isPowerShellConstrainedLanguageEnforced
Vendor: Microsoft Intune  |  Category: Endpoint Security
Claim (EP-004): PowerShell runs in constrained language mode on every Windows device. Windows puts PowerShell in
constrained language mode when an App Control for Business (WDAC) policy with user-mode code integrity, or an
AppLocker script rule, is ENFORCED on the device. Ruling (J.J., 6 Oct 2026): WDAC or AppLocker in enforce mode,
assigned to all devices, counts as constrained language mode.
Source: a new workflow getAppControlEvidence merging two read-only Intune reads (DeviceManagementConfiguration.Read.All,
the permission the existing device-configuration check uses), each link-paginated with reportPagination:
    appControlPolicies    GET /beta/deviceManagement/configurationPolicies?$expand=assignments,settings
    deviceConfigurations  GET /v1.0/deviceManagement/deviceConfigurations?$expand=assignments
App Control for Business policies (templateFamily endpointSecurityApplicationControl, or settings whose id starts
device_vendor_msft_policy_config_applicationcontrol) are read for their mode:
    built-in controls: a choice value ending _enable_app_control_0 is Enforce, _enable_app_control_1 is Audit;
    uploaded policy XML (<SiPolicy>): Enforce when it enables UMCI ("Enabled:UMCI") and not "Enabled:Audit Mode".
AppLocker comes from custom profiles (windows10CustomConfiguration) whose OMA-URI is .../AppLocker/
ApplicationLaunchRestrictions/.../Script/Policy: EnforcementMode="Enabled" is Enforce, "AuditOnly" is Audit.
A policy is ESTATE-WIDE when assigned to All devices or All users with no exclusion group and no filter.
True: at least one estate-wide policy enforces App Control (UMCI) or AppLocker script rules.
False: App Control or AppLocker policies were read and none of them is an estate-wide enforcing policy (audit only,
or enforced only on some groups); the reason names each policy and its mode and reach.
Not evaluated (None with a dataCollection error): an empty, error, truncated or unrecognised body; a missing part
(when nothing estate-wide enforces); an App Control or AppLocker policy whose mode or assignments cannot be read
(when nothing estate-wide enforces); or no App Control or AppLocker policy at all (it may be deployed by Group
Policy or Configuration Manager, which this read does not see).
"""
import json
from datetime import datetime, timezone

KEY = "isPowerShellConstrainedLanguageEnforced"

#: The criterion this file answers. None means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = (KEY,)

WRAPPERS = ("apiResponse", "api_response", "response", "result", "Output", "rawResponse")

PARTS = ("appControlPolicies", "deviceConfigurations")

APP_CONTROL_FAMILY = "endpointsecurityapplicationcontrol"
APP_CONTROL_PREFIX = "device_vendor_msft_policy_config_applicationcontrol"
ENFORCE_SUFFIX = "_enable_app_control_0"
AUDIT_SUFFIX = "_enable_app_control_1"
APPLOCKER_SCRIPT = ("/applocker/applicationlaunchrestrictions/", "/script/policy")
CUSTOM_PROFILE = "#microsoft.graph.windows10customconfiguration"

ESTATE_TARGETS = ("#microsoft.graph.alldevicesassignmenttarget", "#microsoft.graph.alllicensedusersassignmenttarget")
EXCLUSION_TARGET = "#microsoft.graph.exclusiongroupassignmenttarget"
NOT_ASSIGNED = "not assigned"

MAX_NAMED = 20


def to_obj(raw):
    """A parsed JSON value, or None for an empty or unparseable body."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    if isinstance(raw, str):
        text = raw.strip()
        if text == "":
            return None
        try:
            return json.loads(text)
        except Exception:
            return None
    return raw


def envelope_error(obj):
    """A short reason when obj is an error envelope rather than a Graph body, else None."""
    if not isinstance(obj, dict):
        return None
    err = obj.get("error")
    if err is True or isinstance(err, (str, dict)):
        detail = obj.get("message") or err
        if isinstance(detail, dict):
            detail = detail.get("message") or detail.get("code") or json.dumps(detail)[:200]
        return "the call did not return data: " + str(detail)[:300]
    code = obj.get("statusCode")
    if code is None:
        code = obj.get("status_code")
    if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
        return "the call returned HTTP " + str(code)
    return None


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, api_errors=None):
    """Standardized transformation response (CONTRIBUTING.md)."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_err_list else "success", "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {"status": "success", "errors": [], "inputSummary": input_summary or {}},
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": [],
            },
            "metadata": {
                "evaluatedAt": datetime.now(timezone.utc).isoformat(),
                "schemaVersion": "2.0",
                "transformationId": KEY,
                "vendor": "Microsoft Intune",
                "category": "Endpoint Security",
            },
        },
    }


def not_measured(validation, reason, recommendation=None, summary=None):
    """None with dataCollection status "error", so Token-Service records Not evaluated, not Failed."""
    return create_response(
        result={KEY: None},
        validation=validation,
        fail_reasons=[reason],
        recommendations=[recommendation] if recommendation else [],
        input_summary=summary or {},
        api_errors=[reason],
    )


def name_list(items):
    shown = ", ".join(items[:MAX_NAMED])
    if len(items) > MAX_NAMED:
        shown = shown + " and " + str(len(items) - MAX_NAMED) + " more"
    return shown


def graph_collection(part, what):
    """(items, None) for a complete Graph collection read, else (None, reason)."""
    cur = to_obj(part)
    for depth in range(5):
        if cur is None:
            return None, what + ": the part is missing or empty"
        if isinstance(cur, list):
            return None, what + ": a bare list carries no proof that every page was read"
        if not isinstance(cur, dict):
            return None, what + ": the part is not a JSON object"
        why = envelope_error(cur)
        if why:
            return None, what + ": " + why
        if isinstance(cur.get("value"), list):
            break
        nxt = None
        for w in WRAPPERS:
            if isinstance(cur.get(w), (dict, str)):
                nxt = to_obj(cur.get(w))
                break
        if nxt is None:
            return None, what + ": no value collection in the response"
        cur = nxt
    if not (isinstance(cur, dict) and isinstance(cur.get("value"), list)):
        return None, what + ": no value collection in the response"
    nxt_link = cur.get("@odata.nextLink")
    if nxt_link not in (None, "", "None"):
        return None, what + ": more pages were not read (@odata.nextLink is set)"
    trunc = cur.get("paginationTruncated")
    if trunc is True or str(trunc).strip().lower() == "true":
        return None, what + ": the read was truncated at the page limit"
    for it in cur.get("value"):
        if not isinstance(it, dict):
            return None, what + ": an entry is not an object"
    return cur.get("value"), None


def estate_wide(assignments):
    """(True, None) for an All devices / All users assignment with no exclusion or filter; (False, why) for a
    narrower one; (False, "not assigned") when no assignment includes any device or user (an empty list, or
    exclusion groups only), so the profile reaches no device; (None, why) when the assignments cannot be read."""
    if not isinstance(assignments, list):
        return None, "no readable assignments"
    estate = False
    includes = False
    excluded = False
    filtered = False
    for a in assignments:
        if not isinstance(a, dict):
            return None, "an assignment is not an object"
        target = a.get("target")
        if not isinstance(target, dict):
            return None, "an assignment has no target"
        t = str(target.get("@odata.type") or "").strip().lower()
        if t == EXCLUSION_TARGET:
            excluded = True
            continue
        includes = True
        fid = target.get("deviceAndAppManagementAssignmentFilterId")
        ftype = str(target.get("deviceAndAppManagementAssignmentFilterType") or "none").strip().lower()
        if fid not in (None, "", "None", "00000000-0000-0000-0000-000000000000") and ftype not in ("none", ""):
            filtered = True
        if t in ESTATE_TARGETS:
            estate = True
    if not includes:
        return False, NOT_ASSIGNED
    if excluded:
        return False, "excludes a group"
    if filtered:
        return False, "uses an assignment filter"
    if not estate:
        return False, "assigned to groups only"
    return True, None


def has_part(cur):
    for p in PARTS:
        if p in cur:
            return True
    return False


def unwrap(raw):
    """(body, validation) with the Token-Service envelope and Integration-Service wrappers removed."""
    validation = {"status": "unknown", "errors": [], "warnings": ["Legacy input format - no schema validation performed"]}
    cur = to_obj(raw)
    if isinstance(cur, dict) and "validation" in cur and "data" in cur:
        if isinstance(cur.get("validation"), dict):
            validation = cur.get("validation")
        cur = to_obj(cur.get("data"))
    for depth in range(8):
        if not isinstance(cur, dict) or has_part(cur):
            break
        nxt = None
        for w in WRAPPERS:
            if isinstance(cur.get(w), (dict, str)):
                nxt = to_obj(cur.get(w))
                break
        if nxt is None and isinstance(cur.get("data"), (dict, str)):
            nxt = to_obj(cur.get("data"))
        if nxt is None:
            break
        cur = nxt
    return cur, validation


def workflow_truncated(body, key):
    """True when the workflow reported that the part under key was cut off at its page limit (reportPagination)."""
    stats = to_obj(body.get("paginationStats"))
    if isinstance(stats, dict):
        entry = to_obj(stats.get(key))
        if isinstance(entry, dict):
            flag = entry.get("paginationTruncated")
            if flag is True or str(flag).strip().lower() == "true":
                return True
    return False


def setting_pairs(node, out, depth):
    """Every (settingDefinitionId, value) pair in a settings-catalog setting instance tree, depth-capped."""
    if depth > 12 or node is None:
        return out
    if isinstance(node, list):
        for x in node:
            setting_pairs(x, out, depth + 1)
        return out
    if not isinstance(node, dict):
        return out
    sid = str(node.get("settingDefinitionId") or "").strip().lower()
    if sid:
        for k in ("choiceSettingValue", "simpleSettingValue"):
            v = node.get(k)
            if isinstance(v, dict) and v.get("value") is not None:
                out.append((sid, str(v.get("value"))))
    for k in ("settingInstance", "choiceSettingValue", "children", "groupSettingCollectionValue",
              "groupSettingValue", "simpleSettingCollectionValue", "choiceSettingCollectionValue"):
        if k in node:
            setting_pairs(node.get(k), out, depth + 1)
    return out


def xml_mode(text):
    """'enforce' / 'audit' / None for an App Control policy XML string."""
    low = text.lower()
    if "<sipolicy" not in low:
        return None
    if "enabled:audit mode" in low:
        return "audit"
    if "enabled:umci" in low:
        return "enforce"
    return "kernel-only"


def app_control_mode(policy):
    """(is_app_control, mode): mode is 'enforce', 'audit', 'kernel-only' or None when it cannot be read."""
    tref = policy.get("templateReference") if isinstance(policy.get("templateReference"), dict) else {}
    family = str(tref.get("templateFamily") or "").strip().lower()
    pairs = setting_pairs(policy.get("settings"), [], 0)
    is_ac = family == APP_CONTROL_FAMILY or any([sid.startswith(APP_CONTROL_PREFIX) for sid, v in pairs])
    if not is_ac:
        return False, None
    if not isinstance(policy.get("settings"), list):
        return True, None
    modes = []
    for sid, v in pairs:
        low = v.strip().lower()
        if low.endswith(ENFORCE_SUFFIX):
            modes.append("enforce")
        elif low.endswith(AUDIT_SUFFIX):
            modes.append("audit")
        else:
            m = xml_mode(v)
            if m:
                modes.append(m)
    if "audit" in modes:
        return True, "audit"
    if "enforce" in modes:
        return True, "enforce"
    if "kernel-only" in modes:
        return True, "kernel-only"
    return True, None


def applocker_mode(profile):
    """(is_applocker_script, mode) for a custom profile: mode 'enforce', 'audit' or None when unreadable."""
    if str(profile.get("@odata.type") or "").strip().lower() != CUSTOM_PROFILE:
        return False, None
    found = False
    modes = []
    settings = profile.get("omaSettings")
    if not isinstance(settings, list):
        return False, None
    for s in settings:
        if not isinstance(s, dict):
            continue
        uri = str(s.get("omaUri") or "").strip().lower()
        if APPLOCKER_SCRIPT[0] in uri and uri.endswith(APPLOCKER_SCRIPT[1]):
            found = True
            value = s.get("value")
            text = str(value if value is not None else "")
            enc = s.get("isEncrypted")
            if enc is True or str(enc).strip().lower() == "true" or text.strip().lower() in ("", "none", "null"):
                modes.append(None)
                continue
            low = text.replace("'", '"').replace(" ", "").lower()
            if 'enforcementmode="auditonly"' in low:
                modes.append("audit")
            elif 'enforcementmode="enabled"' in low:
                modes.append("enforce")
            else:
                modes.append(None)
    if not found:
        return False, None
    if "audit" in modes:
        return True, "audit"
    if None in modes:
        return True, None
    return True, "enforce"


def label(p):
    mode = p["mode"] or "mode unreadable"
    reach = "all devices or all users" if p["wide"] is True else (p["reach"] or "assignments unreadable")
    return p["name"] + " (" + p["kind"] + ", " + mode + ", " + reach + ")"


def transform(input):
    # Reading input.get("data") marks this transform as new-format for Token-Service, which then hands it the
    # undrilled workflow result as {"data": <response>, "validation": ...}, so @odata.nextLink survives.
    validation = {"status": "unknown", "errors": [], "warnings": []}
    try:
        if isinstance(input, dict) and "validation" in input and "data" in input:
            if isinstance(input.get("validation"), dict):
                validation = input.get("validation")
            body = unwrap(input.get("data"))[0]
        else:
            body, validation = unwrap(input)
        if body is None:
            return not_measured(validation, "The response body is empty; nothing was read from Microsoft Intune.")
        why = envelope_error(body)
        if why:
            return not_measured(validation, "Microsoft Intune: " + why + ". This is a credential or permission "
                                "result, not a finding.")
        if not isinstance(body, dict) or not has_part(body):
            return not_measured(validation, "Microsoft Intune: the response is not the getAppControlEvidence workflow "
                                "result.")
        policies = []
        gaps = []
        for part, what in (("appControlPolicies", "configuration policies"), ("deviceConfigurations",
                                                                              "device configuration profiles")):
            if workflow_truncated(body, part):
                gaps.append(what + ": cut off at the page limit")
                continue
            items, why = graph_collection(body.get(part), what)
            if why:
                gaps.append(why)
                continue
            for it in items:
                name = str(it.get("name") or it.get("displayName") or it.get("id") or "policy")[:60]
                if part == "appControlPolicies":
                    is_it, mode = app_control_mode(it)
                    kind = "App Control"
                else:
                    is_it, mode = applocker_mode(it)
                    kind = "AppLocker script rules"
                if not is_it:
                    continue
                wide, reach = estate_wide(it.get("assignments"))
                policies.append({"name": name, "kind": kind, "mode": mode, "wide": wide, "reach": reach})
        enforcing = [p for p in policies if p["mode"] == "enforce" and p["wide"] is True]
        summary = {"policiesRead": len(policies), "policies": [label(p) for p in policies][:MAX_NAMED],
                   "readGaps": gaps[:MAX_NAMED]}
        if enforcing:
            return create_response(
                result={KEY: True},
                validation=validation,
                pass_reasons=[str(len(enforcing)) + " polic(ies) enforce application control on all devices, which "
                              "puts PowerShell in constrained language mode: " + name_list([label(p) for p in enforcing])
                              + ". Scope: Intune policies; Group Policy and Configuration Manager are not read."],
                input_summary=summary,
            )
        if gaps:
            return not_measured(validation, "Microsoft Intune: " + "; ".join(gaps[:3]) + ". No estate-wide enforcing "
                                "App Control or AppLocker policy was found in what was read, but the read is incomplete.",
                                "The reads need DeviceManagementConfiguration.Read.All.", summary)
        unreadable = [p for p in policies if p["mode"] is None or p["wide"] is None]
        if unreadable:
            return not_measured(validation, str(len(unreadable)) + " App Control or AppLocker polic(ies) could not be "
                                "read for mode or assignments (" + name_list([label(p) for p in unreadable]) + "), so "
                                "whether one enforces on all devices cannot be shown.", None, summary)
        if len(policies) == 0:
            return not_measured(validation, "No App Control for Business or AppLocker script policy is configured in "
                                "Intune. Application control may be deployed by Group Policy or Configuration Manager, "
                                "which this read does not see.",
                                "Deploy an App Control for Business policy in enforce mode to all devices (Intune: "
                                "Endpoint security > App Control for Business), or provide the evidence as a document.",
                                summary)
        return create_response(
            result={KEY: False},
            validation=validation,
            fail_reasons=["No App Control or AppLocker policy enforces on all devices, so PowerShell is not shown to "
                          "run in constrained language mode everywhere: " + name_list([label(p) for p in policies])],
            recommendations=["Switch the App Control for Business policy from Audit to Enforce (or AppLocker script "
                             "rules to EnforcementMode Enabled) and assign it to all devices, after reviewing the audit "
                             "events."],
            input_summary=summary,
        )
    except Exception as e:
        return not_measured(validation, "Transformation error: " + str(e)[:300])
