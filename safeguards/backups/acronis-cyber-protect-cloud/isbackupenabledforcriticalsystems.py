"""Transformation: isBackupEnabledForCriticalSystems - Acronis Cyber Protect Cloud (Resource Management API v4).
Source: workflow getMachineProtectionStatus: "machineStatuses" =
GET /api/resource_management/v4/resource_statuses?type=resource.machine (all pages), read with the
connection's API client token, so it covers every machine visible to that API client.
Each item is one resource: "context" (the resource), "aggregate" (rolled-up protection status, e.g.
"not_protected") and "policies" (one entry per applied policy: "type", "last_run", "last_success_run",
"next_run"). Machine backup is the policy type "policy.backup.machine".
Acronis has no notion of a "critical" machine, so every machine counts as critical here. This is the
platform-standard key that Backup requirements ask; the rule is the same as areBackupsEnabledForCriticalSystems.
True when every machine has a machine-backup policy whose last successful run is within the last 7 days.
False when any machine has no machine-backup policy (or is reported not_protected), or its last successful
backup is older than 7 days or never happened.
Returns None (not measured) on anything else: empty or non-JSON bodies, an error envelope, no machines in the
read, a partial read (pages left unread), or a machine whose policies or timestamps cannot be read."""
import json
from datetime import datetime, timedelta, timezone

KEY = "isBackupEnabledForCriticalSystems"
METHOD = "getMachineProtectionStatus"

VENDOR = "Acronis"
PRODUCT = "Acronis Cyber Protect Cloud"
WRAPPERS = ["apiResponse", "api_response", "response", "result", "Output", "_response_data"]
MACHINE = "resource.machine"
BACKUP_POLICY = "policy.backup.machine"
MAX_AGE_DAYS = 7


def to_obj(raw):
    """A parsed JSON value, or None for an empty or unparseable body."""
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except Exception:
            return None
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
    """A short reason when obj is an Integration-Service or Acronis error envelope, else None.
    Fixed reasons: the vendor's own error text is never echoed into the result."""
    if not isinstance(obj, dict):
        return None
    err = obj.get("error")
    if err is True or isinstance(err, (str, dict)):
        return "The Acronis call did not return data"
    code = obj.get("status_code") or obj.get("statusCode")
    if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
        return "The Acronis call returned HTTP " + str(code)
    if obj.get("status") == "Error":
        return "The Acronis call did not return data"
    if obj.get("paginationTruncated") is True:
        return "Only part of the machine list was read; the remaining pages were not read"
    return None


def step_into(cur):
    """The next level of wrapping (Token-Service data/validation or an IS wrapper), or None."""
    if "validation" in cur and "data" in cur:
        return to_obj(cur.get("data"))
    for w in WRAPPERS:
        if isinstance(cur.get(w), (dict, str, bytes)):
            return to_obj(cur.get(w))
    return None


def workflow_part(raw, key):
    """(the named part of the merged workflow body, None) or (None, reason)."""
    cur = to_obj(raw)
    for depth in range(8):
        if cur is None:
            return None, "The response body is empty or not JSON"
        if not isinstance(cur, dict):
            return None, "The response is not a JSON object"
        problem = envelope_error(cur)
        if problem is not None:
            return None, problem
        if key in cur:
            part = to_obj(cur.get(key))
            if not isinstance(part, dict):
                return None, "The " + key + " read is not a JSON object"
            problem = envelope_error(part)
            if problem is not None:
                return None, key + ": " + problem
            return part, None
        nxt = step_into(cur)
        if nxt is None:
            return None, "No " + key + " read in the response; nothing to evaluate"
        cur = nxt
    return None, "No " + key + " read found within 8 levels of wrapping"


def lower_text(value):
    return value.strip().lower() if isinstance(value, str) else None


def more_pages(coll):
    """True when the collection says pages remain unread (an Acronis paging cursor, or an IS truncation mark)."""
    paging = coll.get("paging")
    if not isinstance(paging, dict):
        return False
    cursors = paging.get("cursors")
    if not isinstance(cursors, dict):
        return False
    if cursors.get("truncated") is True:
        return True
    after = cursors.get("after")
    return isinstance(after, str) and after.strip() != ""


def parse_time(value):
    """Naive-UTC datetime from an ISO 8601 timestamp ("2026-11-15T03:07:31Z", "...31.317+02:00"). None if unreadable."""
    if not isinstance(value, str) or len(value) < 19:
        return None
    t = value.strip()
    if t[4] != "-" or t[7] != "-" or t[10] not in "Tt " or t[13] != ":" or t[16] != ":":
        return None
    try:
        base = datetime(int(t[0:4]), int(t[5:7]), int(t[8:10]), int(t[11:13]), int(t[14:16]), int(t[17:19]))
    except Exception:
        return None
    tail = t[19:]
    if tail[:1] == ".":
        i = 1
        while i < len(tail) and tail[i].isdigit():
            i = i + 1
        tail = tail[i:]
    if tail in ("", "Z", "z"):
        return base
    if tail[0] not in "+-" or len(tail) < 5:
        return None
    off = tail[1:].replace(":", "")
    if len(off) != 4 or not off.isdigit():
        return None
    minutes = int(off[0:2]) * 60 + int(off[2:4])
    sign = 1 if tail[0] == "+" else -1
    return base - timedelta(minutes=sign * minutes)


def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def name_of(item):
    ctx = item.get("context")
    if isinstance(ctx, dict):
        return str(ctx.get("name") or ctx.get("id") or "?")[:80]
    return "?"


def respond(key, method, value, reason, extra=None):
    """2.0 response. value None = not measured: dataCollection.status error, no verdict."""
    result = {key: value}
    if extra:
        for k in extra:
            result[k] = extra[k]
    measured = value is not None
    passed = value is True
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "success" if measured else "error", "errors": [] if measured else [reason]},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": {}},
            "evaluation": {"passReasons": [reason] if passed else [],
                           "failReasons": [] if passed else [reason],
                           "recommendations": [], "additionalFindings": []},
            "metadata": {"transformationId": key, "vendor": VENDOR, "product": PRODUCT, "method": method,
                         "evaluatedAt": datetime.now(timezone.utc).isoformat(), "schemaVersion": "2.0"},
        },
    }


def machine_state(item, cutoff, now):
    """"covered", "unprotected", "stale" or "unreadable" for one machine's resource_statuses item."""
    policies = item.get("policies")
    agg = item.get("aggregate")
    agg_status = lower_text(agg.get("status")) if isinstance(agg, dict) else None
    if agg_status == "not_protected":
        return "unprotected"
    if not isinstance(policies, list):
        return "unreadable"
    backups = []
    for p in policies:
        if not isinstance(p, dict):
            return "unreadable"
        if lower_text(p.get("type")) == BACKUP_POLICY:
            backups.append(p)
    if len(backups) == 0:
        return "unprotected"
    unreadable = False
    for p in backups:
        last = p.get("last_success_run")
        if last is None or last == "":
            continue
        when = parse_time(last)
        if when is None or when > now + timedelta(days=1):
            unreadable = True
            continue
        if when >= cutoff:
            return "covered"
    if unreadable:
        return "unreadable"
    return "stale"


def evaluate(input):
    coll, why = workflow_part(input, "machineStatuses")
    if why:
        return respond(KEY, METHOD, None, why)
    items = coll.get("items")
    if not isinstance(items, list):
        return respond(KEY, METHOD, None, "The resource-status read carries no items list")
    if more_pages(coll):
        return respond(KEY, METHOD, None, "Only part of the machine list was read; the remaining pages were not read")
    now = utc_now()
    cutoff = now - timedelta(days=MAX_AGE_DAYS)
    counts = {"covered": 0, "unprotected": 0, "stale": 0, "unreadable": 0}
    failing = []
    machines = 0
    for it in items:
        if not isinstance(it, dict):
            return respond(KEY, METHOD, None, "A resource-status entry is not an object")
        ctx = it.get("context")
        rtype = lower_text(ctx.get("type")) if isinstance(ctx, dict) else None
        if rtype and rtype != MACHINE:
            continue
        machines = machines + 1
        state = machine_state(it, cutoff, now)
        counts[state] = counts[state] + 1
        if state in ("unprotected", "stale"):
            failing.append(name_of(it) + ": " + ("no machine backup plan" if state == "unprotected"
                                                  else "no successful backup in " + str(MAX_AGE_DAYS) + " days"))
    extra = {"machineCount": machines, "coveredMachines": counts["covered"], "unprotectedMachines": counts["unprotected"],
             "staleMachines": counts["stale"], "unreadableMachines": counts["unreadable"], "maxBackupAgeDays": MAX_AGE_DAYS}
    if machines == 0:
        return respond(KEY, METHOD, None, "Acronis reports no machine visible to this API client; nothing to evaluate")
    if failing:
        extra["machinesWithoutRecentBackup"] = failing[:25]
        return respond(KEY, METHOD, False, str(len(failing)) + " of " + str(machines) + " machines have no machine "
                       "backup plan or no successful backup in the last " + str(MAX_AGE_DAYS) + " days", extra)
    if counts["unreadable"] > 0:
        return respond(KEY, METHOD, None, str(counts["unreadable"]) + " machines report backup policies or timestamps "
                       "that cannot be read, so full coverage cannot be shown")
    return respond(KEY, METHOD, True, "All " + str(machines) + " machines have a machine backup plan with a successful "
                   "backup in the last " + str(MAX_AGE_DAYS) + " days", extra)


def transform(input):
    # Reading input.get("data") marks this transform as new-format for Token-Service, which then hands it the
    # undrilled response as {"data": <response>, "validation": ...}, so the paging block stays intact.
    try:
        if isinstance(input, dict) and "validation" in input and not isinstance(input.get("data"), list):
            input = input.get("data")
        return evaluate(input)
    except Exception as e:
        return respond(KEY, METHOD, None, "Transformation error: " + str(e)[:300])
