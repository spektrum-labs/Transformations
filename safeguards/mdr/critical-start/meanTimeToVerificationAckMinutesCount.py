"""Transformation: meanTimeToVerificationAckMinutesCount - Critical Start MDR (ZTAP), GET {serverUrl}/api/1.5/incidents/ (getIncidents).

Minutes from an alert's creation (datetime_created) to Critical Start's SOC handing it to the customer's
organization (datetime_org_assigned), averaged over the incidents the SOC actually monitors. Incidents marked
monitored_by "not_monitored" (tuning) or "customer" are not SOC-verified, and incidents the platform auto-routed
(is_autorouted) were assigned by a rule, not an analyst, so both are left out: counting them would report the
auto-router's speed, not the analysts'.

The sampling rule, so the mean cannot be read from a flattering subset:
- A SOC-monitored incident with no organization-assignment time yet is "pending": the slowest case, not acknowledged
  at all. One whose times cannot be placed, or whose assignment precedes its creation (clock skew, re-opened), is
  "skipped". Both are counted, returned next to the mean (pendingIncidents, skippedIncidents) and named in the reason.
- When pending plus skipped outnumber the measured incidents, the mean would describe a minority, so it is not
  measured (None).
- Timestamps are read as full ISO 8601 with their UTC offset ("2026-11-05T21:15:47Z", "...+05:00", "...-0800",
  fractional seconds allowed) and compared on the UTC line, so mixed offsets cannot skew an interval. A timestamp
  with no offset cannot be placed and counts as skipped rather than being guessed as UTC.
- A partial read (the paginator stopped before the vendor's total) is still measured, reported as partial
  (completeRead False, named in the reason) and gated one notch stricter: pending plus skipped equal to the measured
  count is also not measured. Any window's measured incidents are the ones already handed over, so its mean leans
  optimistic; the pending and skipped counts beside it are what show the slow tail. Refusing every partial read
  would blind the key on any tenant larger than one page, so the stricter gate is the trade.
No analyst-handled incident with both timestamps, an error body or no incidents at all is not measured (None).
"""
import json
from datetime import datetime, timedelta

VENDOR = "Critical Start"
WRAPPERS = ["result", "response", "apiResponse", "api_response", "Output", "data", "_response_data"]


def extract_validation(input_data):
    if isinstance(input_data, dict) and "validation" in input_data and isinstance(input_data["validation"], dict):
        return input_data["validation"]
    return {"status": "unknown", "errors": [], "warnings": ["Legacy input format - no schema validation performed"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, metadata=None, transformation_errors=None, api_errors=None,
                    additional_findings=None):
    """Standardized 5-section transformation response."""
    if validation is None:
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


def error_in(cur):
    """A short error string when a vendor/IS error body is in hand, else None."""
    if cur.get("errors") or cur.get("error") is True or isinstance(cur.get("error"), (str, dict)):
        detail = cur.get("errors") or cur.get("error") or cur.get("message") or "error"
        return json.dumps(detail)[:300]
    if cur.get("errMsg") or cur.get("errNo"):
        return json.dumps(cur.get("errMsg") or cur.get("errNo"))[:300]
    code = cur.get("status_code") or cur.get("statusCode")
    if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
        return "HTTP " + str(code) + ": " + json.dumps(cur.get("message") or cur.get("detail") or "")[:200]
    return None


def find_key(obj, wanted):
    """(container_dict, error) for the first dict, through any wrapper, that carries key `wanted`."""
    cur = obj
    for depth in range(8):
        if isinstance(cur, str):
            try:
                cur = json.loads(cur)
            except Exception:
                return None, None
        if not isinstance(cur, dict):
            return None, None
        if wanted in cur:
            return cur, None
        problem = error_in(cur)
        if problem is not None:
            return None, problem
        nxt = None
        for key in WRAPPERS:
            if isinstance(cur.get(key), (dict, str)):
                nxt = cur.get(key)
                break
        if nxt is None:
            return None, None
        cur = nxt
    return None, None


def raw_body(input):
    # input.get("data") makes Token-Service pass the undrilled response in a {data, validation}
    # envelope, so the vendor's total and the paginator's truncation flag stay visible.
    if isinstance(input, dict) and "validation" in input:
        return input.get("data")
    return input


def truncated(input, box):
    """True when the Integration-Service paginator marked the merged read partial."""
    for cur in (box, raw_body(input), input):
        if isinstance(cur, dict) and cur.get("paginationTruncated") is True:
            return True
    return False


def to_int(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def read_objects(input, noun):
    """(objects, complete, problem) from a ZTAP list read: {"objects": [...], "total": N, ...}."""
    box, problem = find_key(raw_body(input), "objects")
    if problem is not None:
        return None, False, "Critical Start returned an error instead of " + noun + ": " + problem
    if box is None or not isinstance(box.get("objects"), list):
        return None, False, "No Critical Start " + noun + " list in the response; nothing to evaluate."
    items = [o for o in box["objects"] if isinstance(o, dict)]
    if len(items) != len(box["objects"]):
        return None, False, "The " + noun + " list holds entries that are not records, so it cannot be scored."
    total = to_int(box.get("total"))
    if total is None:
        return None, False, "The " + noun + " list carries no readable total, so a complete read cannot be shown."
    complete = (not truncated(input, box)) and len(items) >= total
    return items, complete, None


def not_measured(key, problem, validation):
    return create_response(
        result={key: None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": key, "vendor": VENDOR, "category": "mdr"},
    )


def utc_offset_minutes(zone):
    """Minutes east of UTC for "Z", "+HH:MM", "-HHMM" or "+HH"; None for anything else, including no offset at all."""
    if zone in ("Z", "z"):
        return 0
    if len(zone) < 3 or zone[0] not in ("+", "-"):
        return None
    digits = zone[1:].replace(":", "")
    if not digits.isdigit() or len(digits) not in (2, 4):
        return None
    hours = int(digits[0:2])
    mins = int(digits[2:4]) if len(digits) == 4 else 0
    if hours > 23 or mins > 59:
        return None
    total = hours * 60 + mins
    return -total if zone[0] == "-" else total


def parse_time(value):
    """ISO 8601 timestamp to a naive UTC datetime ("2026-11-05T21:15:47Z", "2026-11-05T16:15:47.123-05:00").
    No strptime: the Token-Service sandbox does not allow it. None when the value carries no UTC offset or cannot
    be read, so the caller counts it as skipped instead of guessing a zone."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if len(value) < 20:
        return None
    if value[4] != "-" or value[7] != "-" or value[10] not in ("T", " ") or value[13] != ":" or value[16] != ":":
        return None
    rest = value[19:]
    if rest.startswith("."):
        end = 1
        while end < len(rest) and rest[end].isdigit():
            end += 1
        rest = rest[end:]
    offset = utc_offset_minutes(rest)
    if offset is None:
        return None
    try:
        stamp = datetime(int(value[0:4]), int(value[5:7]), int(value[8:10]), int(value[11:13]), int(value[14:16]), int(value[17:19]))
    except Exception:
        return None
    return stamp - timedelta(minutes=offset)

UNMONITORED = ("not_monitored", "customer", "", "none", "null")


def soc_monitored(incident):
    value = incident.get("monitored_by")
    if value is None:
        return False
    if str(incident.get("is_autorouted")).strip().lower() == "true":
        return False
    return str(value).strip().lower() not in UNMONITORED


def transform(input):
    key = "meanTimeToVerificationAckMinutesCount"
    validation = extract_validation(input)
    try:
        incidents, complete, problem = read_objects(input, "incidents")
        if problem is not None:
            return not_measured(key, problem, validation)
        if not incidents:
            return not_measured(key, "Critical Start returned no incidents, so there is no acknowledgment time to measure.", validation)
        monitored = [i for i in incidents if soc_monitored(i)]
        minutes = []
        pending = 0
        skipped = 0
        for i in monitored:
            if i.get("datetime_org_assigned") in (None, ""):
                pending += 1
                continue
            created = parse_time(i.get("datetime_created"))
            acked = parse_time(i.get("datetime_org_assigned"))
            if created is not None and acked is not None and acked >= created:
                minutes.append((acked - created).total_seconds() / 60.0)
            else:
                skipped += 1
        if not minutes:
            unmonitored = len(incidents) - len(monitored)
            return not_measured(key, "None of the " + str(len(incidents)) + " Critical Start incidents read is SOC-monitored with both a creation and an "
                                "organization-assignment time (" + str(unmonitored) + " are not monitored by Critical Start or were auto-routed by a rule, e.g. still in tuning; "
                                + str(pending) + " are still pending hand-over; " + str(skipped) + " have unreadable or negative times); "
                                "the SOC's acknowledgment time cannot be measured.", validation)
        if pending + skipped > len(minutes) or (not complete and pending + skipped >= len(minutes)):
            return not_measured(key, "Only " + str(len(minutes)) + " of the " + str(len(monitored)) + " SOC-monitored Critical Start incidents read have a usable "
                                "hand-over time (" + str(pending) + " still pending, " + str(skipped) + " with unreadable or negative times); a mean over that "
                                "share would hide the slowest incidents, so it is not measured"
                                + ("" if complete else "; partial read of the incident list") + ".", validation)
        mean = round(sum(minutes) / len(minutes), 2)
        text = ("Critical Start's SOC handed " + str(len(minutes)) + " monitored incidents to the organization in a mean of " + str(mean)
                + " minutes after creation (" + str(len(incidents)) + " incidents read; " + str(pending) + " monitored incidents still pending hand-over, "
                + str(skipped) + " skipped for unreadable or negative times" + ("" if complete else "; partial read of the incident list") + ").")
        return create_response(
            result={key: mean, "incidentsRead": len(incidents), "analystHandledIncidents": len(monitored), "measuredIncidents": len(minutes),
                    "pendingIncidents": pending, "skippedIncidents": skipped, "completeRead": complete},
            validation=validation,
            pass_reasons=[text],
            input_summary={"incidentsRead": len(incidents), "analystHandledIncidents": len(monitored), "measuredIncidents": len(minutes),
                           "pendingIncidents": pending, "skippedIncidents": skipped,
                           "completeRead": complete, "maxMinutes": round(max(minutes), 2)},
            metadata={"transformationId": key, "vendor": VENDOR, "category": "mdr"},
        )
    except Exception as e:
        return not_measured(key, "Transformation error: " + str(e), validation)
