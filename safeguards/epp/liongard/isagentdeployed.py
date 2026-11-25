"""Transformation: isAgentDeployed - Liongard, method getAgents (POST /api/v2/view-agents).

Liongard agents (Cloud, On-Premises or Self-Managed) run the inspections. An agent counts as deployed
only on positive evidence: a status (status / agentStatus / state / connectionStatus) that shows it is
installed, online or offline (DEPLOYED_STATES), or an installed / deployed flag set true. Momentary online
state does not matter: an agent that is offline or disconnected when the check runs is still installed.
An agent whose status is a removed word (uninstalled, decommissioned, deleted, disabled, retired, archived),
any other word (Failed, Pending, ...) or a false installed flag is not deployed. An agent with no readable
status at all is not deployed either, and is reported (unreadAgentCount); being listed is not evidence.

Endpoint rules (2026-09-29), as across the EPP transforms: when the agents carry a last-seen time
(lastSeen / lastHeartbeat / lastContact / lastCheckIn, any case), an agent more than 15 days older than
the newest one in the response is stale, left out and reported as staleAgentCount; when the newest is
itself older than 15 days the whole fleet is dark and every dated agent is stale. An agent without a
readable last-seen time is judged, not dropped. When no agent carries one, every listed agent is judged
and a finding says so.

isAgentDeployed is True when at least 80% of the judged agents are deployed. An empty agent list is
False (no agent is deployed). An unreadable body, an error envelope, a fleet where every agent is stale,
or a list where no judged agent carries a readable status is not evaluated: None with
additionalInfo.dataCollection.status "error".
"""
import json
from datetime import datetime, timezone

ACTIVE_WINDOW_DAYS = 15
DEPLOYED_THRESHOLD = 80.0
REMOVED_STATES = ("uninstalled", "decommissioned", "deleted", "removed", "disabled", "retired", "archived")
LIST_KEYS = ("data", "agents", "items", "results")
SEEN_KEYS = ("lastseen", "lastseenon", "lastheartbeat", "lastheartbeaton", "lastcontact", "lastcheckin",
             "lastcheckinon", "lastcheckedin")
STATUS_KEYS = ("status", "agentstatus", "state", "connectionstatus")
#: Statuses that show the agent is installed, whether it is online at the moment or not.
DEPLOYED_STATES = ("active", "online", "connected", "healthy", "running", "installed", "deployed", "enabled",
                   "offline", "disconnected", "idle", "asleep", "sleeping", "unreachable", "warning")
INSTALLED_FLAGS = ("installed", "isinstalled", "deployed", "isdeployed")


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


TRUNCATED_KEYS = ("paginationtruncated", "truncated", "iteratetruncated")
MORE_KEYS = ("hasmore", "hasmorerows", "hasmoreitems", "hasnextpage", "moreavailable")
NEXT_KEYS = ("next", "nextpage", "nextcursor", "nextlink", "nextpagetoken", "nextpageurl", "@odata.nextlink")
TOTAL_KEYS = ("totalrows", "totalitems", "totalcount", "totalrecords", "totalresults", "total")
PAGE_KEYS = ("currentpage", "page", "pagenumber")
PAGING_BLOCKS = ("pagination", "paging", "pageinfo", "meta", "metadata", "response_metadata")


def as_count(value):
    """A non-negative whole number from an int or digit text, else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def is_set(value):
    if value is True:
        return True
    return str(value).strip().lower() in ("true", "1", "yes")


def paging_problem(levels, count):
    """Why the list read is not the whole list, '' when nothing says so. Every dict on the way to the list (and
    its pagination / paging / pageInfo / meta / metadata / response_metadata block) is checked for a truncation
    flag, a has-more flag, a next page, cursor or link, a total above the rows read, or a page short of the last."""
    blocks = []
    for level in levels:
        low = lower_keys(level)
        blocks.append(low)
        for k in PAGING_BLOCKS:
            if isinstance(low.get(k), dict):
                blocks.append(lower_keys(low.get(k)))
    for low in blocks:
        for k in TRUNCATED_KEYS + MORE_KEYS:
            if k in low and is_set(low.get(k)):
                return "only part of the list was read (" + k + " is set)"
        for k in NEXT_KEYS:
            value = low.get(k)
            if isinstance(value, (str, int, dict)) and not isinstance(value, bool) \
                    and str(value).strip() not in ("", "None", "null", "0", "{}"):
                return "only part of the list was read (a next page remains: " + k + ")"
        for k in TOTAL_KEYS:
            total = as_count(low.get(k))
            if total is not None:
                if total > count:
                    return "only part of the list was read (" + str(count) + " of " + str(total) + " rows)"
                break
        pages = as_count(low.get("totalpages"))
        if pages is not None:
            current = None
            for k in PAGE_KEYS:
                if as_count(low.get(k)) is not None:
                    current = as_count(low.get(k))
                    break
            if current is None or current < pages:
                return "only part of the list was read (page " + str(current) + " of " + str(pages) + ")"
    return ""


def find_list(obj):
    """(items, error) from the Liongard response, whatever wrapper Token-Service hands over. A list that the
    response marks as one page of a longer list (paging_problem) is an error: a partial read is not judged."""
    cur = obj
    levels = []
    for depth in range(6):
        if isinstance(cur, bytes):
            cur = cur.decode("utf-8", "replace")
        if isinstance(cur, str):
            try:
                cur = json.loads(cur) if cur.strip() else None
            except Exception:
                return None, "The Liongard response is not valid JSON, so it cannot be read."
        if isinstance(cur, list):
            problem = paging_problem(levels, len(cur))
            return (None, "The Liongard list is incomplete: " + problem) if problem else (cur, None)
        if not isinstance(cur, dict):
            return None, None
        levels.append(cur)
        low = lower_keys(cur)
        if low.get("error") or str(low.get("status", "")).lower() == "error" or low.get("errors"):
            detail = low.get("errors") or low.get("message") or low.get("error") or "error"
            return None, "Liongard returned an error instead of a list: " + json.dumps(detail)[:300]
        for key in LIST_KEYS:
            if isinstance(low.get(key), list):
                problem = paging_problem(levels, len(low[key]))
                if problem:
                    return None, "The Liongard list is incomplete: " + problem
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
    """The last-seen time as epoch seconds, or None when unreadable or more than a day after the read: a
    check-in in the future is not evidence and never anchors the 15-day window."""
    low = lower_keys(item)
    for key in SEEN_KEYS:
        if key in low:
            when = epoch(low[key])
            if when is not None and when > datetime.now(timezone.utc).timestamp() + 86400:
                return None
            return when
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


def flag_value(value):
    """True / False for a boolean-like flag, None when it is not one."""
    if value is True or value is False:
        return value
    text = str(value).strip().lower()
    if text == "true":
        return True
    if text == "false":
        return False
    return None


def agent_evidence(item):
    """'deployed' on positive evidence, 'not deployed' for a readable status or flag that does not show an
    installed agent (removed, failed, pending, any unknown word, installed false), '' when the agent carries
    no readable status or flag at all."""
    low = lower_keys(item)
    states = [str(low.get(k) or "").strip().lower() for k in STATUS_KEYS]
    states = [x for x in states if x]
    flags = [flag_value(low.get(k)) for k in INSTALLED_FLAGS if k in low]
    flags = [f for f in flags if f is not None]
    if not states and not flags:
        return ""
    if any(x in REMOVED_STATES for x in states) or False in flags:
        return "not deployed"
    if any(x in DEPLOYED_STATES for x in states) or True in flags:
        return "deployed"
    return "not deployed"


def not_measured(key, problem):
    return create_response(
        result={key: None},
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": key, "vendor": "Liongard", "category": "epp"},
    )


def transform(input):
    key = "isAgentDeployed"
    meta = {"transformationId": key, "vendor": "Liongard", "category": "epp"}
    try:
        items, problem = find_list(input)
        if problem is not None:
            return not_measured(key, problem)
        if items is None:
            return not_measured(key, "No Liongard agent list in the response; nothing to evaluate.")
        agents = [a for a in items if isinstance(a, dict)]
        if not agents:
            return create_response(
                result={key: False, "totalAgents": 0, "deployedAgents": 0, "staleAgentCount": 0},
                fail_reasons=["Liongard lists no agents, so no agent is deployed."],
                recommendations=["Deploy a Liongard agent to run inspections."],
                metadata=meta,
            )
        judged, stale = fresh_items(agents)
        if not judged:
            return not_measured(key, "All " + str(stale) + " Liongard agents were last seen more than "
                                + str(ACTIVE_WINDOW_DAYS) + " days ago; there is nothing to measure.")
        if stale and not any(last_seen(i) is not None for i in judged):
            return not_measured(key, "Every dated Liongard agent was last seen more than " + str(ACTIVE_WINDOW_DAYS)
                                + " days ago; the agents with no readable last-seen time cannot stand for the fleet.")
        evidence = [agent_evidence(a) for a in judged]
        unread = len([e for e in evidence if e == ""])
        if unread == len(judged):
            return not_measured(key, "None of the " + str(len(judged)) + " Liongard agents carries a readable status "
                                "or installed flag, so no agent is shown to be deployed; nothing to measure.")
        deployed = [a for a, e in zip(judged, evidence) if e == "deployed"]
        pct = round(len(deployed) * 100.0 / len(judged), 2)
        ok = len(deployed) > 0 and pct >= DEPLOYED_THRESHOLD
        findings = []
        if unread:
            findings.append(str(unread) + " agent(s) carry no readable status and are counted as not deployed "
                            "(unreadAgentCount).")
        if stale:
            findings.append(str(stale) + " agent(s) were last seen more than " + str(ACTIVE_WINDOW_DAYS)
                            + " days before the newest and are left out (staleAgentCount).")
        if not any(has_seen_field(a) for a in agents):
            findings.append("The agent list carries no last-seen time, so every listed agent is judged.")
        text = (str(len(deployed)) + " of " + str(len(judged)) + " Liongard agents show they are deployed ("
                + str(pct) + "%, online or not); the bar is " + str(DEPLOYED_THRESHOLD) + "%.")
        return create_response(
            result={key: ok, "totalAgents": len(judged), "deployedAgents": len(deployed),
                    "deployedPercentage": pct, "staleAgentCount": stale, "unreadAgentCount": unread},
            pass_reasons=[text] if ok else [],
            fail_reasons=[] if ok else [text],
            recommendations=[] if ok else ["Reinstall, repair or re-enable the Liongard agents that are not shown "
                                           "as installed."],
            additional_findings=findings,
            input_summary={"listedAgents": len(agents), "judgedAgents": len(judged), "staleAgentCount": stale,
                           "unreadAgentCount": unread},
            metadata=meta,
        )
    except Exception as e:
        return not_measured(key, "The Liongard agent list could not be read: " + str(e))
