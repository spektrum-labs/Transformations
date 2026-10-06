"""
Transformation: screenLockTimeoutMinutes
Vendor: Microsoft Intune  |  Category: Endpoint Security
Claim (EP-005): Windows devices lock after at most 15 minutes of inactivity. Value: the longest inactivity limit, in
minutes, set by an Intune device configuration profile assigned to every device (or every user). Pass rule lessThan
15 (inclusive, so 15 passes and 16 fails).
Source: a new read-only method getDeviceConfigurationsWithAssignments
    GET /v1.0/deviceManagement/deviceConfigurations?$expand=assignments   (DeviceManagementConfiguration.Read.All,
    the permission the existing getDeviceConfigurations method already uses), link-paginated by
    Integration-Service; an unread @odata.nextLink marks the read truncated.
Settings read (minutes):
    #microsoft.graph.windows10GeneralConfiguration          passwordMinutesOfInactivityBeforeScreenTimeout
                                                            (DeviceLock/MaxInactivityTimeDeviceLock)
    #microsoft.graph.windows10EndpointProtectionConfiguration localSecurityOptionsMachineInactivityLimit,
                                                            localSecurityOptionsMachineInactivityLimitInMinutes
                                                            ("Interactive logon: machine inactivity limit")
A profile is ESTATE-WIDE when it is assigned to All devices or All users, has no exclusion-group assignment and no
assignment filter. A null or 0 value is "not configured" and is ignored; any other value that does not read as minutes is
Not evaluated (a fraction rounds up). A device restriction limit counts only when a password is required
(passwordRequired), because DeviceLock applies it only then: either the same profile requires one, or a profile
assigned to all devices or all users does (Intune merges DeviceLock settings per setting across profiles). Once at least one estate-wide profile sets a
limit, the value is the longest limit set by ANY profile, estate-wide or narrower (a device in a narrower profile's
group receives both, and Intune flags the conflict), so a group profile at 60 minutes fails. A profile that reaches no
device (no assignment, or exclusion groups only) is named in the summary and never sets the value.
Scope, stated in every reason: Intune device configuration profiles. Settings catalog policies, security baselines
and Group Policy are not read; a limit set only there reads Not evaluated, never failed.
Not evaluated (None with a dataCollection error): an empty, error, truncated or unrecognised body; a profile with no
readable assignments; or no estate-wide profile that sets an inactivity limit.
"""
import json
from datetime import datetime, timezone

KEY = "screenLockTimeoutMinutes"

#: The criterion this file answers. None means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = (KEY,)

WRAPPERS = ("apiResponse", "api_response", "response", "result", "Output", "rawResponse")

#: Profile type (lower-case @odata.type) -> the fields that hold an inactivity limit in minutes.
LIMIT_FIELDS = {
    "#microsoft.graph.windows10generalconfiguration": ("passwordMinutesOfInactivityBeforeScreenTimeout",),
    "#microsoft.graph.windows10endpointprotectionconfiguration": ("localSecurityOptionsMachineInactivityLimit",
                                                                  "localSecurityOptionsMachineInactivityLimitInMinutes"),
}

#: Profile types whose inactivity limit (DeviceLock MaxInactivityTimeDeviceLock) only takes effect when the profile
#: also requires a device password (DeviceLock DevicePasswordEnabled = passwordRequired).
PASSWORD_GATED = ("#microsoft.graph.windows10generalconfiguration",)

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


def has_part(cur):
    return isinstance(cur.get("value"), list)


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


NOT_SET = ("", "none", "null", "0")


def minutes(value):
    """(minutes, None): a positive whole number of minutes (a fraction rounds up), or None when not configured
    (null, empty, 0). (None, reason) when the value is set but cannot be read as minutes."""
    if value is None:
        return None, None
    if isinstance(value, bool):
        return None, "a true/false value where minutes were expected"
    text = str(value).strip().lower()
    if text in NOT_SET:
        return None, None
    try:
        n = float(text)
    except Exception:
        return None, "an unreadable value '" + text[:20] + "'"
    if n != n or n > 1000000 or n < 0:
        return None, "an out-of-range value '" + text[:20] + "'"
    if n == 0:
        return None, None
    whole = int(n)
    if whole < n:
        whole = whole + 1
    return whole, None


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


def transform(input):
    # Reading input.get("data") marks this transform as new-format for Token-Service, which then hands it the
    # undrilled response as {"data": <response>, "validation": ...}, so @odata.nextLink survives.
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
        profiles, why = graph_collection(body, "Intune device configuration profiles")
        if why:
            return not_measured(validation, "Microsoft " + why + ".", "The read needs "
                                "DeviceManagementConfiguration.Read.All, which the existing device configuration "
                                "check already uses.")
        limits = []
        narrowed = []
        no_password = []
        gated = []
        password_estate_wide = False
        for p in profiles:
            if (str(p.get("@odata.type") or "").strip().lower() in PASSWORD_GATED
                    and str(p.get("passwordRequired")).strip().lower() == "true"
                    and estate_wide(p.get("assignments"))[0] is True):
                password_estate_wide = True
        for p in profiles:
            ptype = str(p.get("@odata.type") or "").strip().lower()
            fields = LIMIT_FIELDS.get(ptype)
            if not fields:
                continue
            name = str(p.get("displayName") or p.get("id") or "profile")[:60]
            values = []
            for f in fields:
                v, bad = minutes(p.get(f))
                if bad:
                    return not_measured(validation, "Intune profile '" + name + "' sets " + f + " to " + bad +
                                        ", so its inactivity limit cannot be read.")
                if v is not None:
                    values.append(v)
            if not values:
                continue
            if ptype in PASSWORD_GATED and str(p.get("passwordRequired")).strip().lower() != "true":
                # Intune merges DeviceLock settings per setting: a required password from another profile may
                # still make this limit apply. Held until every profile is read (see below).
                gated.append((p, name, max(values)))
                continue
            wide, why = estate_wide(p.get("assignments"))
            if wide is None:
                return not_measured(validation, "Intune profile '" + name + "' sets an inactivity limit but its "
                                    "assignments could not be read (" + why + "), so its reach is unknown.")
            if wide:
                limits.append((max(values), name))
            else:
                narrowed.append((max(values), name, why))
        for p, name, v in gated:
            if not password_estate_wide:
                no_password.append(name)
                continue
            wide, why = estate_wide(p.get("assignments"))
            if wide is None:
                return not_measured(validation, "Intune profile '" + name + "' sets an inactivity limit but its "
                                    "assignments could not be read (" + why + "), so its reach is unknown.")
            if wide:
                limits.append((v, name))
            else:
                narrowed.append((v, name, why))
        summary = {"profilesRead": len(profiles), "estateWideLimits": [n + ": " + str(v) + " min" for v, n in limits][:MAX_NAMED],
                   "narrowerProfiles": [n + " (" + str(v) + " min, " + w + ")" for v, n, w in narrowed][:MAX_NAMED],
                   "limitWithoutPasswordRequired": no_password[:MAX_NAMED]}
        if not limits:
            return not_measured(validation, "No Intune device configuration profile assigned to all devices or all "
                                "users sets a Windows inactivity limit (" + str(len(profiles)) + " profiles read" +
                                ("; narrower profiles: " + name_list(summary["narrowerProfiles"]) if narrowed else "") +
                                ("; limit set without a required password (not enforced): " + name_list(no_password)
                                 if no_password else "") + "). The limit "
                                "may be set by a settings catalog policy, a security baseline or Group Policy, which "
                                "this read does not see.",
                                "Assign a device restriction (Password > Maximum minutes of inactivity until screen "
                                "locks) or endpoint protection (Interactive logon: machine inactivity limit) profile "
                                "of 15 minutes or less to All devices, or provide the evidence as a document.", summary)
        # Once an estate-wide limit exists, every profile that sets one counts: a device in a narrower profile's
        # group receives both, so the longest limit set anywhere is the one some devices may get.
        every = [(v, n) for v, n in limits] + [(v, n + " [" + w + "]") for v, n, w in narrowed if w != NOT_ASSIGNED]
        worst = max([v for v, n in every])
        names = [n + " (" + str(v) + " min)" for v, n in sorted(every, reverse=True)]
        line = ("The longest inactivity limit set by an Intune profile is " + str(worst) + " minutes (estate-wide "
                "baseline from a profile assigned to all devices or all users): " + name_list(names))
        if worst > 15:
            return create_response(
                result={KEY: worst},
                validation=validation,
                fail_reasons=[line + "."],
                recommendations=["Set the inactivity limit to 15 minutes or less in every profile named."],
                input_summary=summary,
            )
        return create_response(
            result={KEY: worst},
            validation=validation,
            pass_reasons=[line + ". Settings catalog policies and Group Policy are not read."],
            input_summary=summary,
        )
    except Exception as e:
        return not_measured(validation, "Transformation error: " + str(e)[:300])
