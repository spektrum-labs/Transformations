# isbackuptypesscheduled.py - CrashPlan
#
# Input: the output of the two-step IS workflow "isBackupTypesScheduled"
# (listActiveComputersForSchedule, then getComputerSettings iterated on computerId):
#   {
#     "computerList":     <raw body of GET /api/v1/Computer?orgId=..&active=true&pgNum=..&pgSize=100>
#                         = {"metadata": {...}, "data": {"totalCount": N, "computers": [ {computerId, guid,
#                            active, blocked, service, ...}, ... ]}},
#     "computerSettings": [ <raw body of GET /api/v1/Computer/{computerId}?incSettings=true>, ... ]
#                         each = {"metadata": {...}, "data": {computerId, ..., "settings": {
#                            "serviceBackupConfig": {"backupConfig": {"backupSets": [ ... ]}}}}}
#   }
#
# A backup set is scheduled when it has
#   - at least one destination (destinations is a non-empty list of {"@id": ...}),
#   - a run window that lets it run: backupRunWindow "@always" true, or a "Between specified times"
#     window with days and a start/end time ("Backup will run" in the console), and
#   - a positive change frequency (retentionPolicy.backupFrequency, ms; "Back up changes every").
# Legal-hold backup sets are left out (same rule as CrashPlan's own pycpg/py42 SDK).
#
# The check passes only when EVERY active, unblocked CrashPlan computer in the org has at least one
# scheduled backup set. Fail closed:
#   - empty / None / error / unparseable body                -> None (not evaluated)
#   - partial read (list shorter than totalCount, a computer
#     without its settings body, settings without backupSets) -> None
#   - no in-scope computers                                  -> None
#   - every computer read, one or more explicitly unscheduled -> False
#   - every computer read and scheduled                       -> True
# A None (not evaluated) result carries its reason in additionalInfo.dataCollection.errors with
# dataCollection.status "error", the same not-evaluated shape as safeguards/backups/keepit.
#
# Backward safety: until the definition's workflow moves to the two steps above, the live
# one-step listBackupSets call returns a 404 error envelope. That input has no computerList, so
# it reads None (not evaluated), never False and never True.
# Function names carry no leading underscore: Token-Service runs this under RestrictedPython.

import json
from datetime import datetime

CRITERIA_KEY = "isBackupTypesScheduled"
WRAPPER_KEYS = ["api_response", "response", "result", "apiResponse", "Output"]


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        for attempt in range(4):
            if "computerList" in data or "computerSettings" in data:
                break
            unwrapped = False
            for key in WRAPPER_KEYS:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": CRITERIA_KEY, "vendor": "CrashPlan", "category": "backup"}
        }
    }


def text_of(val):
    # Locked CrashPlan settings arrive as {"#text": value, "@locked": "true"}.
    if isinstance(val, dict) and "#text" in val:
        return val.get("#text")
    return val


def as_bool(val):
    val = text_of(val)
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        low = val.strip().lower()
        if low in ("true", "1", "yes"):
            return True
        if low in ("false", "0", "no"):
            return False
    return None


def as_int(val):
    val = text_of(val)
    if isinstance(val, bool):
        return None
    if isinstance(val, int):
        return val
    if isinstance(val, float):
        return int(val)
    if isinstance(val, str) and val.strip().lstrip("-").isdigit():
        return int(val.strip())
    return None


def looks_like_error(obj):
    if not isinstance(obj, dict):
        return False
    if obj.get("error") not in (None, False, "", [], {}):
        return True
    if obj.get("errorType") or obj.get("errors") not in (None, [], {}, ""):
        return True
    if str(obj.get("status", "")).lower() == "error":
        return True
    for key in ("status_code", "statusCode"):
        code = as_int(obj.get(key))
        if code is not None and code >= 400:
            return True
    return False


def envelope_data(body):
    # CrashPlan v1 bodies are {"metadata": {...}, "data": {...}}; accept an already-unwrapped record too.
    if isinstance(body, dict) and isinstance(body.get("data"), dict):
        return body["data"]
    return body


def computer_key(record):
    if not isinstance(record, dict):
        return None
    cid = record.get("computerId")
    if cid is None:
        return None
    return str(cid)


def in_scope(computer):
    if as_bool(computer.get("active")) is False:
        return False
    if as_bool(computer.get("blocked")) is True:
        return False
    service = computer.get("service")
    if isinstance(service, str) and service.strip() and service.strip().lower() != "crashplan":
        return False  # an Incydr-only agent has no backup sets
    return True


def is_legal_hold_set(backup_set):
    dests = backup_set.get("destinations")
    return isinstance(dests, dict) and "@locked" in dests and "destination" in dests


def normalize_backup_sets(raw):
    # list -> list; {"backupSet": dict|list} (locked count) -> list; {"@cleared": "true"} -> []; else None
    if isinstance(raw, list):
        return [s for s in raw if isinstance(s, dict)]
    if isinstance(raw, dict):
        if "backupSet" in raw:
            inner = raw.get("backupSet")
            if isinstance(inner, dict):
                return [inner]
            if isinstance(inner, list):
                return [s for s in inner if isinstance(s, dict)]
            return None
        if as_bool(raw.get("@cleared")) is True:
            return []
        if "@id" in raw or "name" in raw:
            return [raw]
    return None


def destination_state(backup_set):
    if "destinations" not in backup_set:
        return "unknown"
    dests = backup_set.get("destinations")
    if isinstance(dests, dict):
        if as_bool(dests.get("@cleared")) is True:
            return "none"
        inner = dests.get("destination")
        if isinstance(inner, dict):
            inner = [inner]
        if isinstance(inner, list):
            return "some" if len([d for d in inner if isinstance(d, dict) and d.get("@id")]) > 0 else "none"
        if dests.get("@id"):
            return "some"
        return "unknown"
    if isinstance(dests, list):
        ids = [d for d in dests if isinstance(d, dict) and d.get("@id")]
        if ids:
            return "some"
        return "none" if len(dests) == 0 else "unknown"
    return "unknown"


def run_window_state(backup_set):
    # -> ("always" | "window" | "never" | "unknown")
    if "backupRunWindow" not in backup_set:
        return "unknown"
    rw = backup_set.get("backupRunWindow")
    if isinstance(rw, list):
        rw = rw[0] if len(rw) > 0 else None
    if isinstance(rw, dict) and isinstance(rw.get("runWindow"), (dict, list)):
        rw = rw.get("runWindow")  # XML-style rendering: <backupRunWindow><runWindow always=..>
        if isinstance(rw, list):
            rw = rw[0] if len(rw) > 0 else None
    if not isinstance(rw, dict):
        return "unknown"
    always = as_bool(rw.get("@always", rw.get("always")))
    days = text_of(rw.get("@days", rw.get("days")))
    start = text_of(rw.get("@startTimeOfDay", rw.get("startTimeOfDay")))
    end = text_of(rw.get("@endTimeOfDay", rw.get("endTimeOfDay")))
    if isinstance(days, list):
        days = "".join([str(d) for d in days])
    if always is True:
        return "always"
    if always is False:
        if isinstance(days, str) and days.strip() and start and end:
            return "window"
        if days is not None and isinstance(days, str) and not days.strip():
            return "never"
    return "unknown"


def frequency_ms(backup_set):
    rp = backup_set.get("retentionPolicy")
    if not isinstance(rp, dict):
        return None
    return as_int(rp.get("backupFrequency"))


def evaluate_set(backup_set):
    # -> (state, window, freq_ms) where state is "scheduled" | "not_scheduled" | "unknown"
    dest = destination_state(backup_set)
    window = run_window_state(backup_set)
    freq = frequency_ms(backup_set)
    if dest == "none" or window == "never" or (freq is not None and freq <= 0):
        return "not_scheduled", window, freq
    if dest == "some" and window in ("always", "window") and freq is not None and freq > 0:
        return "scheduled", window, freq
    return "unknown", window, freq


def evaluate_computer(record):
    # -> (state, reason, windows, freqs)
    settings = record.get("settings") if isinstance(record, dict) else None
    if not isinstance(settings, dict):
        return "unknown", "no settings object (incSettings not returned)", [], []
    sbc = settings.get("serviceBackupConfig")
    bc = sbc.get("backupConfig") if isinstance(sbc, dict) else None
    if not isinstance(bc, dict) or "backupSets" not in bc:
        return "unknown", "settings carry no serviceBackupConfig.backupConfig.backupSets", [], []
    sets = normalize_backup_sets(bc.get("backupSets"))
    if sets is None:
        return "unknown", "backupSets has an unrecognised shape", [], []
    user_sets = [s for s in sets if not is_legal_hold_set(s)]
    if len(user_sets) == 0:
        return "not_scheduled", "no backup sets", [], []
    states = []
    windows = []
    freqs = []
    for s in user_sets:
        state, window, freq = evaluate_set(s)
        states.append(state)
        if state == "scheduled":
            windows.append(window)
            freqs.append(freq)
    if "scheduled" in states:
        return "scheduled", "", windows, freqs
    if "unknown" in states:
        return "unknown", "a backup set lacks destination, run-window or frequency fields", [], []
    return "not_scheduled", "no backup set has a destination, a run window and a backup frequency", [], []


def evaluate(data):
    if not isinstance(data, dict) or len(data) == 0:
        return {CRITERIA_KEY: None, "error": "no workflow output"}
    if looks_like_error(data):
        return {CRITERIA_KEY: None, "error": "the vendor call returned an error"}

    list_body = data.get("computerList")
    if not isinstance(list_body, dict) or looks_like_error(list_body):
        return {CRITERIA_KEY: None, "error": "no computer list in the workflow output"}
    list_data = envelope_data(list_body)
    computers = list_data.get("computers") if isinstance(list_data, dict) else None
    if not isinstance(computers, list):
        return {CRITERIA_KEY: None, "error": "computer list has no computers array"}
    computers = [c for c in computers if isinstance(c, dict)]
    total_count = as_int(list_data.get("totalCount"))
    if total_count is not None and total_count > len(computers):
        return {CRITERIA_KEY: None, "error": "partial computer list: read " + str(len(computers)) + " of " + str(total_count),
                "computersListed": len(computers), "totalCount": total_count}

    settings_bodies = data.get("computerSettings")
    if not isinstance(settings_bodies, list):
        return {CRITERIA_KEY: None, "error": "no per-computer settings in the workflow output",
                "computersListed": len(computers)}
    settings_by_id = {}
    for body in settings_bodies:
        if looks_like_error(body):
            return {CRITERIA_KEY: None, "error": "a per-computer settings call returned an error"}
        rec = envelope_data(body)
        key = computer_key(rec)
        if key is not None:
            settings_by_id[key] = rec

    scoped = [c for c in computers if in_scope(c)]
    out_of_scope = len(computers) - len(scoped)
    if len(scoped) == 0:
        return {CRITERIA_KEY: None, "error": "no active CrashPlan computers to evaluate",
                "computersListed": len(computers), "computersOutOfScope": out_of_scope}

    scheduled = 0
    not_scheduled_ids = []
    unknown_ids = []
    missing_ids = []
    window_types = []
    freqs = []
    for c in scoped:
        key = computer_key(c)
        rec = settings_by_id.get(key) if key is not None else None
        if rec is None:
            missing_ids.append(key if key is not None else "?")
            continue
        state, reason, w, f = evaluate_computer(rec)
        if state == "scheduled":
            scheduled += 1
            for x in w:
                if x not in window_types:
                    window_types.append(x)
            freqs.extend([x for x in f if x is not None])
        elif state == "not_scheduled":
            not_scheduled_ids.append(key)
        else:
            unknown_ids.append(key)

    summary = {
        "computersEvaluated": len(scoped),
        "computersScheduled": scheduled,
        "computersNotScheduled": len(not_scheduled_ids),
        "computersUnknown": len(unknown_ids),
        "computersMissingSettings": len(missing_ids),
        "computersOutOfScope": out_of_scope,
        "runWindowTypes": sorted(window_types),
    }
    if freqs:
        summary["shortestBackupFrequencyMinutes"] = int(min(freqs) / 60000)
        summary["longestBackupFrequencyMinutes"] = int(max(freqs) / 60000)
    if total_count is not None:
        summary["totalCount"] = total_count

    if missing_ids:
        summary[CRITERIA_KEY] = None
        summary["error"] = "partial read: " + str(len(missing_ids)) + " computer(s) have no settings body"
        return summary
    if not_scheduled_ids:
        summary[CRITERIA_KEY] = False
        summary["notScheduledComputerIds"] = not_scheduled_ids[:20]
        return summary
    if unknown_ids:
        summary[CRITERIA_KEY] = None
        summary["error"] = str(len(unknown_ids)) + " computer(s) returned settings without readable backup-set schedule fields"
        summary["unknownComputerIds"] = unknown_ids[:20]
        return summary
    summary[CRITERIA_KEY] = True
    return summary


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)

        result = evaluate(data)
        value = result.get(CRITERIA_KEY, None)
        extra = {}
        for k in result:
            if k != CRITERIA_KEY and k != "error":
                extra[k] = result[k]
        result_out = {CRITERIA_KEY: value}
        for k in extra:
            result_out[k] = extra[k]

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        findings = []
        api_errors = []
        if value is True:
            pass_reasons.append("Every active CrashPlan computer (" + str(extra.get("computersEvaluated")) +
                                ") has a backup set with a destination, a run window and a backup frequency")
            findings.append("Run window types: " + ", ".join(extra.get("runWindowTypes", [])))
        elif value is False:
            fail_reasons.append(str(extra.get("computersNotScheduled")) + " of " + str(extra.get("computersEvaluated")) +
                                " active CrashPlan computers have no scheduled backup set")
            recommendations.append("In the CrashPlan console, give each device a backup set with a destination; "
                                   "set Backup will run to Always or to specified times, and a Frequency.")
        else:
            fail_reasons.append("Could not determine backup scheduling for every computer")
            if result.get("error"):
                fail_reasons.append(result["error"])
            api_errors.append(result.get("error") or "backup scheduling could not be read for every computer")
            recommendations.append("Verify GET /api/v1/Computer and /api/v1/Computer/{computerId}?incSettings=true "
                                   "are readable by the integration's API user")

        return create_response(
            result=result_out,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=dict(result_out),
            api_errors=api_errors,
            additional_findings=findings,
        )
    except Exception as e:
        # Nothing was read, so nothing is known: None (not evaluated), never False.
        return create_response(
            result={CRITERIA_KEY: None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            api_errors=["Transformation error: " + str(e)],
            fail_reasons=["Transformation error: " + str(e)],
        )
