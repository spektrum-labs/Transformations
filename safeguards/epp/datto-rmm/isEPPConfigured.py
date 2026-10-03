"""Transformation: isEPPConfigured (Datto RMM, GET /api/v2/site/{siteUid}/devices).

Value: a whole-number percentage, floor(100 * devices RunningAndUpToDate / devices with antivirus detected (FF-04: protected = installed, configured = enforcing and current)). The pass bar lives in the requirement.
Devices judged: deviceClass "device", not deleted, lastSeen within 15 days of the newest lastSeen
(endpoint rules 2026-09-29). A body that is not a device page, a truncated list, or nothing to
measure is not evaluated (dataCollection error, no value). One client site per evaluation.
"""

from datetime import datetime, timezone

# Endpoint rules (2026-09-29): judge a device only when its lastSeen is within ACTIVE_WINDOW_DAYS
# of the newest lastSeen in the list. If the newest lastSeen is itself older than the window, the
# whole fleet is dark and every device is stale. Printers, ESXi hosts and network devices
# (deviceClass other than "device") and deleted devices are left out.
ACTIVE_WINDOW_DAYS = 15
PROTECTED = ("RunningAndUpToDate", "RunningAndNotUpToDate", "NotRunning")


def seconds(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value / 1000.0 if value > 100000000000 else float(value)
    if isinstance(value, str) and value.strip():
        text = value.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    return None


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        for _ in range(3):
            unwrapped = False
            for key in ("api_response", "response", "result", "apiResponse", "Output"):
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format - no schema validation performed"]}


def device_page(data):
    """(devices, problem): the DevicesPage's device list, or why there is none to judge."""
    if not isinstance(data, dict) or not isinstance(data.get("devices"), list):
        return None, "the response is not a Datto RMM device page (no devices list)"
    details = data.get("pageDetails") if isinstance(data.get("pageDetails"), dict) else {}
    if details.get("truncated"):
        return None, "the device list was cut off by the page limit, so the fleet was not fully read"
    return [d for d in data["devices"] if isinstance(d, dict)], None


def judged_devices(devices):
    records = [d for d in devices if str(d.get("deviceClass") or "device") == "device" and not d.get("deleted")]
    known = [s for s in (seconds(d.get("lastSeen")) for d in records) if s is not None]
    wall_cutoff = datetime.now(timezone.utc).timestamp() - ACTIVE_WINDOW_DAYS * 86400
    cutoff = max(known) - ACTIVE_WINDOW_DAYS * 86400 if known else None
    dark = bool(known) and max(known) < wall_cutoff
    if dark:
        cutoff = wall_cutoff
    kept = []
    stale = 0
    for d in records:
        seen = seconds(d.get("lastSeen"))
        if cutoff is not None and seen is not None and seen < cutoff:
            stale = stale + 1
            continue
        kept.append(d)
    scope = {"devicesReported": len(devices), "devicesJudged": len(kept), "devicesLeftOutStale": stale,
             "devicesLeftOutClassOrDeleted": len(devices) - len(records), "activeWindowDays": ACTIVE_WINDOW_DAYS,
             "fleetDark": dark}
    return kept, scope


def av_status(d):
    av = d.get("antivirus") if isinstance(d.get("antivirus"), dict) else {}
    return str(av.get("antivirusStatus") or "")


def patch_status(d):
    pm = d.get("patchManagement") if isinstance(d.get("patchManagement"), dict) else {}
    return str(pm.get("patchStatus") or "")


def response(key, value, scope, reasons, failed, api_errors, validation, extra):
    result = dict(scope)
    result.update(extra)
    result[key] = value
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_errors else "success", "errors": api_errors},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "success", "errors": [], "inputSummary": dict(scope)},
            "evaluation": {"passReasons": [] if failed else reasons, "failReasons": reasons if failed else [],
                           "recommendations": [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0",
                         "transformationId": key, "vendor": "Datto RMM", "category": "epp"},
        },
    }


def transform(input):
    data, validation = extract_input(input)
    devices, problem = device_page(data)
    if problem:
        return response("isEPPConfigured", None, {}, [problem], True, [problem], validation, {})
    kept, scope = judged_devices(devices)
    base = [d for d in kept if av_status(d) in PROTECTED]
    hits = [d for d in base if av_status(d) == "RunningAndUpToDate"]
    if not base:
        reason = "Not evaluated: no judged device has antivirus detected."
        return response("isEPPConfigured", None, scope, [reason], True, [reason], validation, {})
    pct = (len(hits) * 100) // len(base)
    reason = f"{len(hits)} of {len(base)} devices with antivirus detected ({pct}%) are running and up to date."
    return response("isEPPConfigured", pct, scope, [reason], len(hits) < len(base), [], validation,
                    {"measured": len(hits), "population": len(base)})
