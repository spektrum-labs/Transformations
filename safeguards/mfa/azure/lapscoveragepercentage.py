"""
Transformation: lapsCoveragePercentage
Vendor: Microsoft Entra ID (One-Click)  |  Category: Identity and Access Management
Claim (IAM-005): local administrator passwords are managed by Windows LAPS. Value: the percentage of active
Entra-joined and hybrid-joined Windows devices that have a Windows LAPS password backed up to Entra ID. Pass rule
greaterThan 95 (inclusive, both sides truncated to whole numbers by Token-Service).
Source: a new workflow getLapsCoverageEvidence merging two NEW read-only methods:
    deviceLocalCredentials  GET /v1.0/directory/deviceLocalCredentials  (needs the NEW application permission
                            DeviceLocalCredential.ReadBasic.All: metadata only, never the password itself)
    windowsDevices          GET /v1.0/devices?$filter=operatingSystem eq 'Windows'&$select=id,deviceId,displayName,
                            accountEnabled,trustType,approximateLastSignInDateTime&$top=999  (Directory.Read.All,
                            already granted)
Both link-paginated; an unread @odata.nextLink left in a part marks it truncated.
deviceLocalCredentialInfo: {"id": <the device's Entra deviceId>, "deviceName", "lastBackupDateTime", "refreshDateTime"}

Denominator: Windows devices that are enabled, Entra-joined (trustType AzureAd) or hybrid-joined (ServerAd), and
signed in within the last 90 days (Entra ID's stale-device guidance). Registered personal devices (Workplace) cannot
use Windows LAPS and are left out. A device counts as covered when a credential entry with a lastBackupDateTime
matches its deviceId. Scope, stated in every reason: Windows LAPS backed up to Entra ID. Devices whose LAPS
password is kept in on-premises Active Directory, and legacy Microsoft LAPS, are not visible to this read.
Not evaluated (None with a dataCollection error): an empty, error or unrecognised body (including the 403 a tenant
returns before it grants DeviceLocalCredential.ReadBasic.All); either part missing, in error or truncated; or no
active Entra-joined or hybrid-joined Windows device.
"""
import json
from datetime import datetime, timezone, timedelta

KEY = "lapsCoveragePercentage"

#: The criterion this file answers. None means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = (KEY,)

WRAPPERS = ("apiResponse", "api_response", "response", "result", "Output", "rawResponse")

PARTS = ("deviceLocalCredentials", "windowsDevices")

#: Entra ID's stale-device guidance: a device with no sign-in for 90 days is stale.
ACTIVE_DAYS = 90

#: trustType values of devices that can back up a Windows LAPS password to Entra ID.
JOINED = ("azuread", "serverad")

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
                "vendor": "Microsoft Entra ID",
                "category": "Identity and Access Management",
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


def parse_time(value):
    """A timezone-aware datetime from a Graph timestamp, or None."""
    text = str(value or "").strip()
    if text in ("", "None"):
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    if "." in text:
        main, rest = text.split(".", 1)
        frac = ""
        tz = ""
        for i in range(len(rest)):
            if rest[i] in "+-":
                frac = rest[:i]
                tz = rest[i:]
                break
        else:
            frac = rest
        text = main + "." + (frac + "000000")[:6] + tz
    try:
        dt = datetime.fromisoformat(text)
    except Exception:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def is_enabled(value):
    return value is True or str(value).strip().lower() == "true"


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
            return not_measured(validation, "The response body is empty; nothing was read from Microsoft Entra ID.")
        why = envelope_error(body)
        if why:
            return not_measured(validation, "Microsoft Entra ID: " + why + ". This is a credential or permission "
                                "result, not a finding.")
        if not isinstance(body, dict) or not has_part(body):
            return not_measured(validation, "Microsoft Entra ID: the response is not the getLapsCoverageEvidence "
                                "workflow result.")
        creds, why = graph_collection(body.get("deviceLocalCredentials"), "Windows LAPS credentials")
        if why:
            return not_measured(validation, "Microsoft Entra ID " + why + ". Needs access, not a finding.",
                                "Grant the Spektrum app the read-only DeviceLocalCredential.ReadBasic.All permission "
                                "(admin re-consent). It reads LAPS backup metadata only, never a password.")
        devices, why = graph_collection(body.get("windowsDevices"), "Windows devices")
        if why:
            return not_measured(validation, "Microsoft Entra ID " + why + ".")
        backed_up = {}
        for c in creds:
            did = str(c.get("id") or "").strip().lower()
            if did and parse_time(c.get("lastBackupDateTime")) is not None:
                backed_up[did] = True
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=ACTIVE_DAYS)
        active = []
        missing = []
        skipped = {"disabled": 0, "notJoined": 0, "stale": 0}
        for d in devices:
            if not is_enabled(d.get("accountEnabled")):
                skipped["disabled"] = skipped["disabled"] + 1
                continue
            if str(d.get("trustType") or "").strip().lower() not in JOINED:
                skipped["notJoined"] = skipped["notJoined"] + 1
                continue
            seen = parse_time(d.get("approximateLastSignInDateTime"))
            if seen is None or seen < cutoff:
                skipped["stale"] = skipped["stale"] + 1
                continue
            did = str(d.get("deviceId") or "").strip().lower()
            name = str(d.get("displayName") or did or "device")[:60]
            active.append(name)
            if did == "" or did not in backed_up:
                missing.append(name)
        covered = len(active) - len(missing)
        summary = {"activeJoinedWindowsDevices": len(active), "devicesWithLapsBackup": covered,
                   "devicesWithoutLapsBackup": missing[:MAX_NAMED], "credentialEntriesRead": len(creds),
                   "devicesLeftOut": skipped}
        if len(active) == 0:
            return not_measured(validation, "Entra ID lists no enabled Entra-joined or hybrid-joined Windows device that "
                                "signed in within " + str(ACTIVE_DAYS) + " days (" + str(len(devices)) + " Windows "
                                "device(s) read), so LAPS coverage has no population here.", None, summary)
        pct = round(covered * 100.0 / len(active), 2)
        summary["lapsCoveragePercentage"] = pct
        line = (str(covered) + " of " + str(len(active)) + " active Entra-joined or hybrid-joined Windows device(s) "
                "have a Windows LAPS password backed up to Entra ID (" + str(pct) + "%)")
        if missing:
            return create_response(
                result={KEY: pct},
                validation=validation,
                fail_reasons=[line + "; without a backup: " + name_list(missing) + ". Passwords kept in on-premises "
                              "Active Directory are not visible to this read."],
                recommendations=["Enable Windows LAPS with Entra ID backup (Intune: Endpoint security > Account "
                                 "protection > Local admin password solution) for the devices named."],
                input_summary=summary,
            )
        return create_response(
            result={KEY: pct},
            validation=validation,
            pass_reasons=[line + "."],
            input_summary=summary,
        )
    except Exception as e:
        return not_measured(validation, "Transformation error: " + str(e)[:300])
