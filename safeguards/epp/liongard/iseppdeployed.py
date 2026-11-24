"""Transformation: isEPPDeployed - Liongard, method getDevices (POST /api/v2/inventory-device-profiles-query).

A device profile counts as deployed when Liongard monitors it -- managed / isManaged true, or a monitoring
status of any connection state (online or offline) -- its lifecycle is active (or unset), and it is not
removed (uninstalled, decommissioned, deleted, disabled, retired, archived). Momentary online state does
not matter: a device that is offline, disconnected or asleep when the check runs is still monitored.
Counting only devices that were online made the result follow the time of day.

Endpoint rules (2026-09-29), as across the EPP transforms: when the devices carry a last-seen time
(lastSeen / lastHeartbeat / lastContact / lastCheckIn, any case), a device more than 15 days older than
the newest one in the response is stale, left out and reported as staleDeviceCount; when the newest is
itself older than 15 days the whole fleet is dark and every dated device is stale. A device without a
readable last-seen time is judged, not dropped. When no device carries one, every listed device is
judged and a finding says so.

A device with no readable status and no managed flag is not deployed (being listed is not evidence) and is
reported as unreadDeviceCount.

isEPPDeployed is True when at least 80% of the judged devices are deployed. An empty device list is
False. An unreadable body, an error envelope, a fleet where every device is stale, or a list where no judged
device carries a readable status or managed flag is not evaluated: None with
additionalInfo.dataCollection.status "error".
"""
import json
from datetime import datetime, timezone

ACTIVE_WINDOW_DAYS = 15
DEPLOYED_THRESHOLD = 80.0
REMOVED_STATES = ("uninstalled", "decommissioned", "deleted", "removed", "disabled", "retired", "archived")
LIST_KEYS = ("data", "devices", "items", "results")
SEEN_KEYS = ("lastseen", "lastseenon", "lastheartbeat", "lastheartbeaton", "lastcontact", "lastcheckin",
             "lastcheckinon", "lastcheckedin")
STATUS_KEYS = ("status", "connectionstatus", "state")
#: Monitoring states, online or offline. Any of them shows Liongard is watching the device.
MONITORED_STATES = ("green", "yellow", "red", "active", "online", "connected", "healthy", "offline",
                    "disconnected", "inactive", "idle", "asleep", "sleeping", "unreachable", "warning")
ACTIVE_LIFECYCLES = ("active", "production", "deployed", "")


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Standardized 5-section transformation response."""
    if not isinstance(validation, dict):
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    response_metadata = {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0"}
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_err_list else "success", "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": "error" if transform_err_list else "success",
                "errors": transform_err_list,
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": response_metadata,
        },
    }


def lower_keys(obj):
    return dict((str(k).lower(), v) for k, v in obj.items()) if isinstance(obj, dict) else {}


def find_list(obj):
    """(items, error) from the Liongard response, whatever wrapper Token-Service hands over."""
    cur = obj
    for depth in range(6):
        if isinstance(cur, bytes):
            cur = cur.decode("utf-8", "replace")
        if isinstance(cur, str):
            try:
                cur = json.loads(cur) if cur.strip() else None
            except Exception:
                return None, "The Liongard response is not valid JSON, so it cannot be read."
        if isinstance(cur, list):
            return cur, None
        if not isinstance(cur, dict):
            return None, None
        low = lower_keys(cur)
        if low.get("error") or str(low.get("status", "")).lower() == "error" or low.get("errors"):
            detail = low.get("errors") or low.get("message") or low.get("error") or "error"
            return None, "Liongard returned an error instead of a list: " + json.dumps(detail)[:300]
        for key in LIST_KEYS:
            if isinstance(low.get(key), list):
                return low[key], None
        nxt = None
        for key in ("response", "apiresponse", "api_response", "result", "data"):
            if isinstance(low.get(key), (dict, str, bytes)):
                nxt = low[key]
                break
        if nxt is None:
            return None, None
        cur = nxt
    return None, None


def epoch(value):
    """Seconds since 1970 from an ISO-8601 string or an epoch number (seconds or milliseconds), or None."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return value / 1000.0 if value > 100000000000 else float(value)
    text = str(value).strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text[:19]).replace(tzinfo=timezone.utc).timestamp()
    except Exception:
        return None


def last_seen(item):
    low = lower_keys(item)
    for key in SEEN_KEYS:
        if key in low:
            return epoch(low[key])
    return None


def has_seen_field(item):
    low = lower_keys(item)
    return any(key in low for key in SEEN_KEYS)


def fresh_items(items):
    """(items judged, stale count), the 15-day window on the newest last-seen time."""
    seen = [last_seen(i) for i in items]
    known = [s for s in seen if s is not None]
    if not known:
        return list(items), 0
    cutoff = max(known) - ACTIVE_WINDOW_DAYS * 86400
    wall_cutoff = datetime.now(timezone.utc).timestamp() - ACTIVE_WINDOW_DAYS * 86400
    if max(known) < wall_cutoff:
        cutoff = wall_cutoff
    fresh = []
    stale = 0
    for item, when in zip(items, seen):
        if when is not None and when < cutoff:
            stale = stale + 1
        else:
            fresh.append(item)
    return fresh, stale


def is_removed(item):
    low = lower_keys(item)
    for key in STATUS_KEYS:
        if str(low.get(key) or "").strip().lower() in REMOVED_STATES:
            return True
    return False


def is_managed(item):
    low = lower_keys(item)
    for key in ("managed", "ismanaged"):
        value = low.get(key)
        if value is True or str(value).strip().lower() == "true":
            return True
    return False


def has_evidence(item):
    """True when the device carries a status or a managed flag that can be read either way."""
    low = lower_keys(item)
    if any(str(low.get(k) or "").strip() for k in STATUS_KEYS):
        return True
    for key in ("managed", "ismanaged"):
        value = low.get(key)
        if value is True or value is False or str(value).strip().lower() in ("true", "false"):
            return True
    return False


def is_deployed(item):
    low = lower_keys(item)
    if is_removed(item):
        return False
    lifecycle = str(low.get("lifecyclestatus", low.get("lifecycle", "")) or "").strip().lower()
    if lifecycle not in ACTIVE_LIFECYCLES:
        return False
    monitored = any(str(low.get(k) or "").strip().lower() in MONITORED_STATES for k in STATUS_KEYS)
    return monitored or is_managed(item)


def not_measured(key, problem):
    return create_response(
        result={key: None},
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": key, "vendor": "Liongard", "category": "epp"},
    )


def transform(input):
    key = "isEPPDeployed"
    meta = {"transformationId": key, "vendor": "Liongard", "category": "epp"}
    try:
        items, problem = find_list(input)
        if problem is not None:
            return not_measured(key, problem)
        if items is None:
            return not_measured(key, "No Liongard device list in the response; nothing to evaluate.")
        devices = [d for d in items if isinstance(d, dict)]
        if not devices:
            return create_response(
                result={key: False, "totalCount": 0, "deployedCount": 0, "staleDeviceCount": 0},
                fail_reasons=["Liongard lists no devices, so no device is shown to be protected."],
                recommendations=["Bring endpoints under Liongard monitoring."],
                metadata=meta,
            )
        judged, stale = fresh_items(devices)
        if not judged:
            return not_measured(key, "All " + str(stale) + " Liongard devices were last seen more than "
                                + str(ACTIVE_WINDOW_DAYS) + " days ago; there is nothing to measure.")
        unread = len([d for d in judged if not has_evidence(d)])
        if unread == len(judged):
            return not_measured(key, "None of the " + str(len(judged)) + " Liongard devices carries a readable "
                                "status or managed flag, so no device is shown to be monitored; nothing to measure.")
        deployed = [d for d in judged if is_deployed(d)]
        pct = round(len(deployed) * 100.0 / len(judged), 2)
        ok = len(deployed) > 0 and pct >= DEPLOYED_THRESHOLD
        findings = []
        if unread:
            findings.append(str(unread) + " device(s) carry no readable status or managed flag and are counted as "
                            "not deployed (unreadDeviceCount).")
        if stale:
            findings.append(str(stale) + " device(s) were last seen more than " + str(ACTIVE_WINDOW_DAYS)
                            + " days before the newest and are left out (staleDeviceCount).")
        if not any(has_seen_field(d) for d in devices):
            findings.append("The device list carries no last-seen time, so every listed device is judged.")
        text = (str(len(deployed)) + " of " + str(len(judged)) + " Liongard devices are monitored (" + str(pct)
                + "%, online or not); the bar is " + str(DEPLOYED_THRESHOLD) + "%.")
        return create_response(
            result={key: ok, "totalCount": len(judged), "deployedCount": len(deployed),
                    "coveragePercentage": pct, "staleDeviceCount": stale, "unreadDeviceCount": unread},
            pass_reasons=[text] if ok else [],
            fail_reasons=[] if ok else [text],
            recommendations=[] if ok else ["Bring the unmonitored or removed devices back under Liongard monitoring."],
            additional_findings=findings,
            input_summary={"listedDevices": len(devices), "judgedDevices": len(judged), "staleDeviceCount": stale,
                           "unreadDeviceCount": unread},
            metadata=meta,
        )
    except Exception as e:
        return not_measured(key, "The Liongard device list could not be read: " + str(e))
