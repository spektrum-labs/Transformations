"""
Transformation: isNTLMv1Disabled
Vendor: Microsoft Defender for Endpoint (One-Click)  |  Category: Endpoint Security
Claim (EP-007): NTLMv1 and LM are refused. True: every applicable device is compliant for
"Set LAN Manager authentication level to 'Send NTLMv2 response only. Refuse LM & NTLM'"
(scid-72, LmCompatibilityLevel 5). False: at least one applicable device is not.

Source: a new One-Click method (an advanced-hunting query, POST /api/advancedqueries/run, the same API and
application permission as the existing getTamperProtectionStatus method) over
DeviceTvmSecureConfigurationAssessment, joined with DeviceTvmSecureConfigurationAssessmentKB so each row
carries its ConfigurationName:
    {"Schema": [...], "Results": [{"DeviceId", "DeviceName", "OSPlatform", "ConfigurationId",
                                   "ConfigurationName", "IsApplicable", "IsCompliant"}, ...]}
IsApplicable / IsCompliant arrive as SByte (1/0), booleans, or their strings.

A row counts only when its ConfigurationId is one this file names AND its knowledge-base name says what that
id means; any other row makes the read Not evaluated rather than being guessed at.
Scope: devices onboarded to Defender for Endpoint and assessed by Defender Vulnerability Management. Devices
that are not onboarded are not seen; device coverage is reported by the coverage checks.
Not evaluated (None with a dataCollection error): an empty, error or unrecognised body, a result at the
100,000-row advanced-hunting limit, a row this file cannot identify, a part of the claim with no assessment
row, or no applicable device.
"""
import json
from datetime import datetime, timezone

KEY = 'isNTLMv1Disabled'
CLAIM = "the LAN Manager authentication level setting (scid-72, 'Send NTLMv2 response only. Refuse LM & NTLM')"
WHAT = "the LAN Manager authentication level at 'Send NTLMv2 response only. Refuse LM & NTLM' (scid-72)"
FIX = "Set 'Network security: LAN Manager authentication level' to 'Send NTLMv2 response only. Refuse LM & NTLM' (LmCompatibilityLevel 5) on the devices named, through Intune or Group Policy."

#: The parts of the claim: a row belongs to a part when its id is listed (or the list is empty)
#: and every word appears in its lower-cased knowledge-base ConfigurationName.
PARTS = (
    {"part": 'LAN Manager authentication level', "ids": ('scid-72',), "words": ('lan manager authentication level', 'ntlmv2')},
)

#: The criterion this file answers. None means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = (KEY,)

WRAPPERS = ("apiResponse", "api_response", "response", "result", "Output")

#: The advanced-hunting API returns at most this many rows. A result this size may be cut short.
ROW_LIMIT = 100000

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


def unwrap(raw):
    """(body, validation) with the Token-Service envelope and Integration-Service wrappers removed."""
    validation = {"status": "unknown", "errors": [], "warnings": ["Legacy input format - no schema validation performed"]}
    cur = to_obj(raw)
    if isinstance(cur, dict) and "validation" in cur and "data" in cur:
        if isinstance(cur.get("validation"), dict):
            validation = cur.get("validation")
        cur = to_obj(cur.get("data"))
    for depth in range(8):
        if not isinstance(cur, dict):
            break
        if isinstance(cur.get("Results"), list) or isinstance(cur.get("Schema"), list):
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
    """A short reason when obj is an error envelope rather than an advanced-hunting result, else None."""
    if not isinstance(obj, dict):
        return None
    err = obj.get("error")
    if err is True or isinstance(err, (str, dict)):
        detail = obj.get("message") or err
        if isinstance(detail, dict):
            detail = detail.get("message") or detail.get("code") or json.dumps(detail)[:200]
        return "the query did not return results: " + str(detail)[:300]
    code = obj.get("statusCode")
    if code is None:
        code = obj.get("status_code")
    if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
        return "the query returned HTTP " + str(code)
    if "PSError" in obj:
        return "the query did not return results: " + str(obj.get("PSError"))[:300]
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
                "vendor": "Microsoft Defender for Endpoint",
                "product": "Defender Vulnerability Management (secure configuration assessment)",
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


def flag(value):
    """True / False for IsCompliant and IsApplicable (SByte 1/0, bool, or their strings), None when unknown."""
    if value is True or value is False:
        return value
    if isinstance(value, (int, float)):
        if value == 1:
            return True
        if value == 0:
            return False
        return None
    if isinstance(value, str):
        text = value.strip().lower()
        if text in ("1", "true"):
            return True
        if text in ("0", "false"):
            return False
    return None


def name_list(items):
    shown = ", ".join(items[:MAX_NAMED])
    if len(items) > MAX_NAMED:
        shown = shown + " and " + str(len(items) - MAX_NAMED) + " more"
    return shown


def config_part(config_id, config_name):
    """The part of the claim this configuration row answers, or None when the row is not one of ours.

    A row counts only when its ConfigurationId is one this file names AND its ConfigurationName (joined from
    DeviceTvmSecureConfigurationAssessmentKB by the query) says what that id is expected to mean. A known id
    whose name does not match is not read as evidence: the meaning of the id cannot be shown.
    """
    name = str(config_name or "").strip().lower()
    if name == "":
        return None
    for part in PARTS:
        if config_id in part["ids"] or len(part["ids"]) == 0:
            ok = True
            for word in part["words"]:
                if word not in name:
                    ok = False
            if ok:
                return part["part"]
    return None


def rows_of(body):
    """(rows, None) for a complete advanced-hunting result, else (None, reason)."""
    if not isinstance(body, dict):
        return None, "the response is not an advanced-hunting result"
    rows = body.get("Results")
    if not isinstance(rows, list) or not isinstance(body.get("Schema"), list):
        return None, "the response carries no Schema and Results arrays, so the query cannot be shown to have run"
    if len(rows) >= ROW_LIMIT:
        return None, ("the query returned " + str(len(rows)) + " rows, the advanced-hunting limit, so the result "
                      "may be cut short")
    for row in rows:
        if not isinstance(row, dict):
            return None, "a result row is not an object"
    return rows, None


def measure(rows):
    """Per-device readings for each part of the claim.

    Returns (devices, parts_seen, unknown_ids, unnamed) where devices maps a device to
    {"name": str, "parts": {part: [applicable, compliant]}}. Duplicate rows for one device and part
    keep the worst reading (any non-compliant applicable row makes the part non-compliant).
    """
    devices = {}
    parts_seen = {}
    unknown_ids = []
    unnamed = []
    for row in rows:
        config_id = str(row.get("ConfigurationId") or "").strip().lower()
        part = config_part(config_id, row.get("ConfigurationName"))
        if part is None:
            label = config_id + " (" + str(row.get("ConfigurationName") or "no name")[:80] + ")"
            if label not in unknown_ids:
                unknown_ids.append(label)
            continue
        parts_seen[part] = True
        device_id = str(row.get("DeviceId") or "").strip()
        device_name = str(row.get("DeviceName") or "").strip()
        if device_id == "" and device_name == "":
            unnamed.append(config_id)
            continue
        dkey = device_id or device_name
        if dkey not in devices:
            devices[dkey] = {"name": (device_name or device_id)[:80], "parts": {}}
        applicable = flag(row.get("IsApplicable"))
        compliant = flag(row.get("IsCompliant"))
        if applicable is None or (applicable and compliant is None):
            unnamed.append(config_id)
            continue
        current = devices[dkey]["parts"].get(part)
        if current is None:
            devices[dkey]["parts"][part] = [applicable, compliant if applicable else None]
        elif applicable:
            worst = compliant if current[1] is None else (current[1] and compliant)
            devices[dkey]["parts"][part] = [True, worst]
    return devices, parts_seen, unknown_ids, unnamed


def transform(input):
    # Reading input.get("data") marks this transform as new-format for Token-Service, which then hands it the
    # undrilled response as {"data": <response>, "validation": ...}, so Schema and Results stay together.
    validation = {"status": "unknown", "errors": [], "warnings": []}
    try:
        if isinstance(input, dict) and "validation" in input and "data" in input:
            if isinstance(input.get("validation"), dict):
                validation = input.get("validation")
            body = unwrap(input.get("data"))[0]
        else:
            body, validation = unwrap(input)
        if body is None:
            return not_measured(validation, "The response body is empty; nothing was read from Defender for Endpoint.")
        why = envelope_error(body)
        if why:
            return not_measured(validation, "Defender for Endpoint advanced hunting: " + why + ". This is a credential "
                                "or permission result, not a finding.",
                                "The advanced-hunting query needs the AdvancedQuery.Read.All application permission "
                                "on the WindowsDefenderATP API, which the existing tamper-protection check already uses.")
        rows, why = rows_of(body)
        if why:
            return not_measured(validation, "Defender for Endpoint advanced hunting: " + why + ".")
        devices, parts_seen, unknown_ids, unnamed = measure(rows)
        if unknown_ids:
            return not_measured(validation, "The secure-configuration assessment returned rows this check cannot "
                                "identify (" + name_list(unknown_ids) + "): the configuration id and its knowledge-base "
                                "name do not match " + CLAIM + ", so they are not read as evidence.")
        if unnamed:
            return not_measured(validation, str(len(unnamed)) + " assessment row(s) carry no device or no readable "
                                "IsApplicable / IsCompliant value, so the result is incomplete.")
        missing = [p["part"] for p in PARTS if p["part"] not in parts_seen]
        if len(rows) == 0 or missing:
            what = "no assessment row" if len(rows) == 0 else "no assessment row for " + ", ".join(missing)
            return not_measured(validation, "Defender Vulnerability Management returned " + what + " for " + CLAIM +
                                ". Defender does not measure it here (no onboarded Windows device is assessed for it, "
                                "or the assessment has not run), so its state is unknown.",
                                "Onboard Windows devices to Defender for Endpoint, or provide the device configuration "
                                "evidence another way.")
        return judge(validation, devices)
    except Exception as e:
        return not_measured(validation, "Transformation error: " + str(e)[:300])

def judge(validation, devices):
    applicable = []
    failing = []
    for dkey in devices:
        d = devices[dkey]
        any_app = False
        bad = []
        for part in d["parts"]:
            reading = d["parts"][part]
            if reading[0]:
                any_app = True
                if reading[1] is False:
                    bad.append(part)
        if any_app:
            applicable.append(d["name"])
        if bad:
            failing.append(d["name"] + " (" + ", ".join(bad) + ")" if len(PARTS) > 1 else d["name"])
    summary = {"applicableDevices": len(applicable), "nonCompliantDevices": len(failing),
               "nonCompliantDeviceNames": failing[:MAX_NAMED]}
    if len(applicable) == 0:
        return not_measured(validation, "Defender Vulnerability Management assessed " + str(len(devices)) +
                            " device(s) for " + CLAIM + " and none is applicable, so it does not measure it here.",
                            None, summary)
    if failing:
        return create_response(
            result={KEY: False},
            validation=validation,
            fail_reasons=[str(len(failing)) + " of " + str(len(applicable)) + " applicable device(s) assessed by "
                          "Defender Vulnerability Management do not have " + WHAT + ": " + name_list(failing)],
            recommendations=[FIX],
            input_summary=summary,
        )
    return create_response(
        result={KEY: True},
        validation=validation,
        pass_reasons=["All " + str(len(applicable)) + " applicable device(s) assessed by Defender Vulnerability "
                      "Management have " + WHAT + "."],
        input_summary=summary,
    )
