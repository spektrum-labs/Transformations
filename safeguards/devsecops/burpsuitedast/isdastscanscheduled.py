"""
Transformation: isDASTScanScheduled
Vendor: PortSwigger Burp Suite DAST  |  Category: Application Security

Integration-Service method listScheduleItems: POST {serverUrl}/graphql/v1 with
  query ScheduleItems { schedule_items(sort_by: start, sort_order: asc) { id scheduled_run_time
  has_run_more_than_once schedule { initial_run_time rrule } sites { id name } folders { id name }
  scan_configurations { id name } } }
Schema (portswigger.net/burp/extensibility/dast/graphql-api, read 2026-11-13): schedule_items returns
[ScheduleItem!]; ScheduleItem.scheduled_run_time is "the next time that a scan created from this schedule item
is due to run" (Timestamp, null when nothing is due); Schedule.rrule is an RFC 5545 RRULE such as
FREQ=WEEKLY;INTERVAL=1;BYDAY=MO, empty for a one-off scan.

True when at least one schedule item recurs (a non-empty RRULE with a FREQ), has a next run time, and covers at
least one site or folder. The reasons name the sites and folders and each schedule's frequency.
False when the schedule list was read and no item does: no schedules, only one-off scans, recurrences that have
ended (no next run), or schedules that cover nothing.
Null (not evaluated) when the read failed: a GraphQL `errors` list, an error or refused answer, an empty or
unrecognised body, a null schedule_items list, or, when nothing qualifies, a schedule item whose schedule, RRULE,
next run time or site and folder lists could not be read.
Only the sites the API user's groups can see are returned, so a schedule on a site outside them is not seen.
"""

import json
from datetime import datetime, timezone

VENDOR = "PortSwigger Burp Suite DAST"
CATEGORY = "Application Security"
# Integration-Service wraps a method response in one of these, and a GraphQL body is itself {"data": {...}}.
WRAPPERS = ("api_response", "response", "result", "apiResponse", "Output", "data")


def parse(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        if not value.strip():
            return None
        return json.loads(value)
    return value


def error_text(node):
    """Why a dict is an error answer rather than a GraphQL result, or None."""
    errors = node.get("errors")
    if isinstance(errors, list) and errors:
        first = errors[0]
        text = first.get("message") if isinstance(first, dict) else first
        return "Burp Suite DAST returned a GraphQL error: " + str(text)[:160]
    if node.get("error") is True or node.get("errorType") or (node.get("error") and not isinstance(node.get("error"), bool)):
        return "error answer: " + str(node.get("message") or node.get("error") or node.get("errorType"))[:160]
    for number in (node.get("statusCode"), node.get("status")):
        if isinstance(number, int) and not isinstance(number, bool) and number >= 400:
            return "HTTP " + str(number) + ": " + str(node.get("message") or "")[:160]
    if node.get("status") is False:
        return "the answer says status false: " + str(node.get("message") or "")[:160]
    return None


def find_list(data, field):
    """(items, problem): the GraphQL root field `field` (a list of objects) found under any wrapper, or why
    there is none. A GraphQL `errors` list fails the read even next to partial data."""
    node = parse(data)
    for depth in range(8):
        if not isinstance(node, dict):
            return None, "the response is empty or not a JSON object"
        problem = error_text(node)
        if problem:
            return None, problem
        if field in node:
            value = node[field]
            if not isinstance(value, list):
                return None, "the " + field + " list is missing or null"
            for item in value:
                if not isinstance(item, dict):
                    return None, "the " + field + " list holds an entry that is not an object"
            return value, None
        nxt = None
        for key in WRAPPERS:
            inner = node.get(key)
            if isinstance(inner, (str, bytes)):
                inner = parse(inner)
            if isinstance(inner, dict):
                nxt = inner
                break
        if nxt is None:
            break
        node = nxt
    if isinstance(node, dict) and (node.get("message") or node.get("detail")):
        return None, "vendor message: " + str(node.get("message") or node.get("detail"))[:160]
    return None, "no " + field + " list in the response"


def parse_time(value):
    """A Burp Suite DAST Timestamp (ISO 8601, UTC, milliseconds: 2026-11-08T14:35:12.190Z) as an aware
    datetime, or None when it is absent or unreadable."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    if "." in text:
        head, tail = text.split(".", 1)
        digits = ""
        rest = ""
        for pos in range(len(tail)):
            if tail[pos].isdigit():
                digits = digits + tail[pos]
            else:
                rest = tail[pos:]
                break
        text = head + "." + (digits[:6] if digits else "0") + rest
    try:
        stamp = datetime.fromisoformat(text)
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp


def days_ago(stamp, now):
    seconds = (now - stamp).total_seconds()
    if seconds < 0:
        return 0
    return int(seconds // 86400)


def label(obj):
    """A site, folder or scan target as people see it: its name, else its id."""
    if not isinstance(obj, dict):
        return "?"
    name = obj.get("name")
    if isinstance(name, str) and name.strip():
        return "'" + name.strip() + "'"
    return "id " + str(obj.get("id"))


def build_response(result, pass_reasons=None, fail_reasons=None, errors=None, summary=None,
                   recommendations=None, transform_id="", findings=None):
    errors = errors or []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if errors else "success", "errors": errors},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "error" if errors else "success", "errors": errors,
                               "inputSummary": summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": findings or []},
            "metadata": {"evaluatedAt": datetime.now(timezone.utc).isoformat(), "schemaVersion": "1.0",
                         "transformationId": transform_id, "vendor": VENDOR, "category": CATEGORY},
        },
    }

KEY = "isDASTScanScheduled"
TRANSFORM_ID = "isdastscanscheduled"
MAX_NAMED = 10


def frequency(rrule):
    """The FREQ part of an RRULE (WEEKLY, MONTHLY, ...), or None when there is none."""
    for part in rrule.split(";"):
        pieces = part.split("=", 1)
        if len(pieces) == 2 and pieces[0].strip().upper() == "FREQ" and pieces[1].strip():
            return pieces[1].strip().upper()
    return None


def transform(input):
    try:
        items, problem = find_list(input, "schedule_items")
        if problem:
            return build_response({KEY: None}, errors=[problem], transform_id=TRANSFORM_ID)
        qualifying = []
        unreadable = []
        one_off = 0
        ended = 0
        no_target = 0
        for item in items:
            schedule = item.get("schedule")
            if not isinstance(schedule, dict):
                unreadable.append("schedule item id " + str(item.get("id")) + " has no schedule")
                continue
            rrule = schedule.get("rrule")
            if rrule is not None and not isinstance(rrule, str):
                unreadable.append("schedule item id " + str(item.get("id")) + " has an RRULE that is not text")
                continue
            if rrule is None or not rrule.strip():
                one_off = one_off + 1
                continue
            freq = frequency(rrule)
            if freq is None:
                unreadable.append("schedule item id " + str(item.get("id")) + " has an RRULE with no FREQ")
                continue
            next_run = item.get("scheduled_run_time")
            if next_run is None:
                ended = ended + 1
                continue
            next_at = parse_time(next_run)
            if next_at is None:
                unreadable.append("schedule item id " + str(item.get("id")) + " has an unreadable next run time")
                continue
            sites = item.get("sites")
            folders = item.get("folders")
            if not isinstance(sites, list) or not isinstance(folders, list):
                unreadable.append("schedule item id " + str(item.get("id")) + " has no readable site and folder lists")
                continue
            if not sites and not folders:
                no_target = no_target + 1
                continue
            qualifying.append((item, freq, next_at))
        frequencies = sorted({entry[1] for entry in qualifying})
        result = {KEY: None, "recurringScheduleCount": len(qualifying), "scheduleItemCount": len(items),
                  "scanFrequencies": frequencies}
        summary = {"scheduleItems": len(items), "recurring": len(qualifying), "oneOff": one_off,
                   "recurrenceEnded": ended, "coversNothing": no_target, "unreadable": len(unreadable)}
        if qualifying:
            result[KEY] = True
            reasons = []
            for item, freq, next_at in qualifying[:MAX_NAMED]:
                targets = [label(s) for s in item.get("sites") or []] + \
                          ["folder " + label(f) for f in item.get("folders") or []]
                shown = ", ".join(targets[:5]) + (" +" + str(len(targets) - 5) if len(targets) > 5 else "")
                reasons.append("Recurring scan (" + freq + "), next run " + next_at.isoformat()[:10]
                               + ", covers " + shown)
            if len(qualifying) > MAX_NAMED:
                reasons.append(str(len(qualifying) - MAX_NAMED) + " more recurring schedule(s)")
            return build_response(result, pass_reasons=reasons, summary=summary, transform_id=TRANSFORM_ID)
        if unreadable:
            return build_response(result, errors=[str(len(unreadable)) + " schedule item(s) could not be read and "
                                                  "no readable one recurs: " + "; ".join(unreadable[:3])],
                                  summary=summary, transform_id=TRANSFORM_ID)
        result[KEY] = False
        if not items:
            reason = "Burp Suite DAST has no scan schedule visible to the API user"
        else:
            reason = ("None of the " + str(len(items)) + " scan schedule(s) recurs with a next run on a site or "
                      "folder (" + str(one_off) + " one-off, " + str(ended) + " recurrence ended, " +
                      str(no_target) + " covering no site or folder)")
        return build_response(result, fail_reasons=[reason], recommendations=[
            "Schedule a recurring Burp Suite DAST scan (for example weekly) for every site in scope, and make sure "
            "the API user's group can see those sites"], summary=summary, transform_id=TRANSFORM_ID)
    except Exception as error:
        return build_response({KEY: None}, errors=[str(error)], transform_id=TRANSFORM_ID)
