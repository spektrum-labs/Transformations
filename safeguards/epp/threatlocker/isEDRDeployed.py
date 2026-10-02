"""Transformation: isEDRDeployed (ThreatLocker, method getComputers).

ThreatLocker Detect is ThreatLocker's EDR module. Each computer row carries maintenanceCapabilities, one flag per
ThreatLocker module installed on that computer (applicationControl, networkControl, storageControl, elevation,
tamper, detect). The field is not in ThreatLocker's public docs; its keys are exactly the product modules.

True when at least one judged computer has maintenanceCapabilities.detect true (the EDR module is deployed;
breadth is requiredCoveragePercentage). edrDeployedPercentage is emitted as evidence. False when no judged
computer has it. A judged computer without maintenanceCapabilities.detect makes the read not evaluated.

Input: getComputers, POST /portalapi/Computer/ComputerGetByAllParameters (View Computers permission). IS pages it
by pageNumber in the body (page size 500) and merges the pages into one array. Every computer row carries
totalRows, the organisation's computer count; the read is complete only when it holds that many distinct
computerIds. Judged computers: not deleted, lastCheckin within 15 days of the newest check-in (endpoint rules
2026-09-29); the rest are reported as staleComputerCount.

Not evaluated (value None, dataCollection "error"): an error body, no computer list, an empty list, a row
without a numeric totalRows or a computerId, a partial read (fewer distinct computers than totalRows -- the
single 500-row page the definition read before pagination is exactly this), or no computer inside the window.
"""
import json
from datetime import datetime, timedelta

KEY = "isEDRDeployed"

ACTIVE_WINDOW_DAYS = 15
COVERED_DRIVER_STATES = ["active", "offline"]
META = {"transformationId": KEY, "vendor": "ThreatLocker", "category": "epp"}


def parse(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        text = value.strip()
        return json.loads(text) if text else None
    return value


def flag(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() == "true"


def to_count(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def parse_when(value):
    try:
        # strptime imports _strptime, which the Token-Service sandbox refuses.
        return datetime.fromisoformat(str(value)[:19])
    except Exception:
        return None


def find_computers(obj):
    """(computers, error) from ComputerGetByAllParameters: a bare JSON array of computers (IS merges the pages of a
    page-number read into one array), possibly under Token-Service / IS envelopes."""
    cur = obj
    for depth in range(6):
        try:
            cur = parse(cur)
        except Exception:
            return None, None
        if isinstance(cur, list):
            return cur, None
        if not isinstance(cur, dict):
            return None, None
        if cur.get("error") is True or cur.get("errors") or cur.get("errorType"):
            return None, str(cur.get("message") or cur.get("errorMessage") or cur.get("errors") or "error")[:300]
        status = cur.get("statusCode") or cur.get("status_code")
        if isinstance(status, int) and status >= 400:
            return None, "HTTP " + str(status)
        nxt = None
        for key in ["data", "items", "result", "response", "apiResponse", "api_response", "_response_data", "Output"]:
            if isinstance(cur.get(key), (dict, list, str, bytes)):
                nxt = cur.get(key)
                break
        if nxt is None:
            return None, None
        cur = nxt
    return None, None


def complete_read(input):
    """(computers, None) for a complete read, else (None, problem). ThreatLocker stamps every computer row with
    totalRows, the organisation's computer count; a read is complete when it holds that many distinct computers."""
    raw = input.get("data") if isinstance(input, dict) and "validation" in input else input
    computers, error = find_computers(raw)
    if error is not None:
        return None, "ThreatLocker returned an error instead of the computer list: " + error
    if computers is None:
        return None, "No ThreatLocker computer list (ComputerGetByAllParameters) in the response; nothing to evaluate."
    computers = [c for c in computers if isinstance(c, dict)]
    if not computers:
        return None, "ThreatLocker returned no computers; an empty list proves nothing (check the Managed Organization Id)."
    totals = [to_count(c.get("totalRows")) for c in computers]
    if None in totals:
        return None, "A computer row carries no numeric totalRows, so a complete read cannot be shown."
    total = max(totals)
    ids = {}
    for c in computers:
        cid = c.get("computerId")
        if cid in (None, ""):
            return None, "A computer row has no computerId."
        ids[str(cid)] = True
    if len(ids) < total:
        return None, ("Read " + str(len(ids)) + " of " + str(total) + " ThreatLocker computers (more pages remain); "
                      "a partial read is not scored.")
    return computers, None


def judged_computers(computers):
    """(judged, stale count): not deleted, and lastCheckin within 15 days of the newest check-in (endpoint rules
    2026-09-29). When the newest check-in is itself older than 15 days, every dated computer is stale. A computer
    without a readable lastCheckin is judged, not dropped."""
    live = [c for c in computers if not flag(c.get("isDeleted"))]
    seen = [parse_when(c.get("lastCheckin")) for c in live]
    known = [s for s in seen if s is not None]
    if not known:
        return live, 0
    cutoff = max(known) - timedelta(days=ACTIVE_WINDOW_DAYS)
    wall = datetime.utcnow() - timedelta(days=ACTIVE_WINDOW_DAYS)
    if max(known) < wall:
        cutoff = wall
    judged = []
    stale = 0
    for c, when in zip(live, seen):
        if when is not None and when < cutoff:
            stale = stale + 1
        else:
            judged.append(c)
    return judged, stale


def name_of(c):
    return str(c.get("computerName") or c.get("hostname") or c.get("computerId") or "unknown")


def respond(value, extra=None, problem=None, pass_reasons=None, fail_reasons=None, findings=None, recommendations=None):
    result = {KEY: value}
    for k in (extra or {}):
        result[k] = extra[k]
    errors = [problem] if problem else []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if problem else "success", "errors": errors},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": extra or {}},
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": (fail_reasons or []) + errors,
                "recommendations": recommendations or [],
                "additionalFindings": findings or [],
            },
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0",
                         "transformationId": META["transformationId"], "vendor": META["vendor"],
                         "category": META["category"]},
        },
    }


def unevaluated(problem, extra=None):
    return respond(None, extra=extra, problem=problem)


def prepared(input):
    """(judged, stale, total, None) or (None, None, None, response) for the shared read rules."""
    computers, problem = complete_read(input)
    if problem:
        return None, None, None, unevaluated(problem)
    judged, stale = judged_computers(computers)
    if not judged:
        return None, None, None, unevaluated("No ThreatLocker computer checked in within " + str(ACTIVE_WINDOW_DAYS) +
                                             " days; nothing current to judge.", {"staleComputerCount": stale})
    return judged, stale, len(computers), None


def transform(input):
    try:
        judged, stale, total, early = prepared(input)
        if early:
            return early
        with_detect = []
        without = []
        for c in judged:
            caps = c.get("maintenanceCapabilities")
            if not isinstance(caps, dict) or "detect" not in caps:
                return unevaluated("Computer " + name_of(c) + " carries no maintenanceCapabilities.detect flag; Detect cannot be read.")
            if flag(caps.get("detect")):
                with_detect.append(c)
            else:
                without.append(name_of(c))
        pct = (len(with_detect) * 100) // len(judged)
        extra = {"edrDeployedPercentage": pct, "detectComputers": len(with_detect), "judgedComputers": len(judged),
                 "staleComputerCount": stale, "totalComputers": total}
        line = str(len(with_detect)) + " of " + str(len(judged)) + " current computers (" + str(pct) + "%) have ThreatLocker Detect (EDR)"
        findings = []
        if stale:
            findings.append(str(stale) + " computer(s) last checked in more than 15 days before the newest check-in are not judged")
        if with_detect:
            if without:
                findings.append("Without Detect: " + ", ".join(without[:5]) + ("..." if len(without) > 5 else ""))
            return respond(True, extra, pass_reasons=[line], findings=findings)
        return respond(False, extra, fail_reasons=[line + "; the EDR module is not deployed"], findings=findings,
                       recommendations=["Licence and enable ThreatLocker Detect on managed computers, or prove EDR with the endpoint tool that runs it."])
    except Exception as e:
        return unevaluated("Transformation error: " + str(e))
