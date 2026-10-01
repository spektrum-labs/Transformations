"""Transformation: isbackuptested - Cohesity NetBackup (NetBackup REST API). Not measured (None) on any body that proves nothing."""
import json
from datetime import datetime


def extract_validation(input_data):
    if isinstance(input_data, dict) and "validation" in input_data and isinstance(input_data["validation"], dict):
        return input_data["validation"]
    return {"status": "unknown", "errors": [], "warnings": ["Legacy input format - no schema validation performed"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
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


WRAPPERS = ["result", "response", "apiResponse", "api_response", "Output", "data", "_response_data"]


def error_in(cur):
    """A short error string when a vendor/IS error body is in hand, else None."""
    if cur.get("errors") or cur.get("error") is True or isinstance(cur.get("error"), (str, dict)):
        detail = cur.get("errors") or cur.get("error") or cur.get("message") or "error"
        return json.dumps(detail)[:300]
    code = cur.get("status_code") or cur.get("statusCode") or cur.get("status")
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
    # envelope, so the pagination block stays visible and a partial read is caught.
    if isinstance(input, dict) and "validation" in input:
        return input.get("data")
    return input


def parse_time(text):
    """Naive-UTC datetime from an ISO-8601 string, or None."""
    if not isinstance(text, str) or len(text) < 19:
        return None
    try:
        return datetime.fromisoformat(text[:19])
    except Exception:
        return None


def pct(part, whole):
    return round(100.0 * part / whole, 2) if whole else None


from datetime import timezone, timedelta

VENDOR = "NetBackup"


def not_measured(key, problem, validation):
    return create_response(
        result={key: None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": key, "vendor": VENDOR, "category": "backups"},
    )


def jsonapi(input, want_list):
    """(doc, problem): the NetBackup JSON:API document with Integration-Service wrappers removed.

    want_list: True for a collection (data is a list), False for a single resource (data.attributes)."""
    cur = raw_body(input)
    for depth in range(6):
        if isinstance(cur, str):
            text = cur.strip()
            if text.startswith("<"):
                return None, "NetBackup answered with HTML or XML, not JSON."
            try:
                cur = json.loads(text)
            except Exception:
                return None, None
        if not isinstance(cur, dict):
            return None, None
        if cur.get("errorCode") not in (None, 0, "0"):
            return None, "NetBackup error " + str(cur.get("errorCode")) + ": " + str(cur.get("errorMessage") or "")[:200]
        problem = error_in(cur)
        if problem is not None:
            return None, problem
        inner = cur.get("data")
        if want_list and isinstance(inner, list):
            return cur, None
        if not want_list and isinstance(inner, dict) and isinstance(inner.get("attributes"), dict):
            return cur, None
        nxt = None
        for key in ["apiResponse", "_response_data", "response", "result", "data"]:
            if isinstance(cur.get(key), (dict, str)):
                nxt = cur.get(key)
                break
        if nxt is None:
            return None, None
        cur = nxt
    return None, None


def as_int(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return None


def job_time(text):
    """Aware UTC datetime from a NetBackup ISO-8601 timestamp, or None."""
    if not isinstance(text, str) or len(text) < 19:
        return None
    try:
        when = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    except Exception:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when


def scan_jobs(input, job_type, days, wanted):
    """Walk a finished-jobs page sorted by -endTime.

    Returns (matches, finished_in_window, problem, partial): matches are DONE jobs of `job_type` ending
    within `days` with status 0 or 1 for which wanted(attributes) is True. partial is True when more
    pages remain and the oldest job read still lies inside the window, so a miss is not a no."""
    doc, problem = jsonapi(input, True)
    if doc is None:
        return None, None, problem or "No NetBackup job list in the response; nothing to evaluate.", False
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    matches = []
    finished = 0
    oldest = None
    for item in doc.get("data"):
        att = item.get("attributes") if isinstance(item, dict) else None
        if not isinstance(att, dict):
            return None, None, "A NetBackup job record has no attributes.", False
        if str(att.get("jobType") or "").upper() != job_type or str(att.get("state") or "").upper() != "DONE":
            continue
        when = job_time(att.get("endTime"))
        status = as_int(att.get("status"))
        if when is None or status is None:
            return None, None, "NetBackup job " + str(att.get("jobId")) + " has no endTime or status.", False
        if oldest is None or when < oldest:
            oldest = when
        if when < cutoff:
            continue
        finished += 1
        if status in (0, 1) and wanted(att):
            matches.append(att)
    meta = doc.get("meta") if isinstance(doc.get("meta"), dict) else {}
    pag = meta.get("pagination") if isinstance(meta.get("pagination"), dict) else {}
    links = doc.get("links") if isinstance(doc.get("links"), dict) else {}
    more = bool(pag.get("next")) or bool(links.get("next"))
    partial = more and (oldest is None or oldest >= cutoff)
    return matches, finished, None, partial


# Method: listRestoreJobs
#   GET {serverUrl}/netbackup/admin/jobs?filter=jobType eq 'RESTORE' and state eq 'DONE'&sort=-endTime&page[limit]=100
#   (data[].attributes {jobId, jobType, state, status, endTime, policyName, clientName}; meta.pagination.next
#   when more pages exist). Status 0 = success, 1 = partial success, >1 = failed.
# Spec: NetBackup Admin API (sort.veritas.com/public/documents/nbu/11.0/windowsandunix/productguides/html/admin/),
#   GET /admin/jobs, job attributes jobType (RESTORE), state (DONE), status, endTime.
#
# isBackupTested = True when at least one RESTORE job finished with status 0 or 1 in the last 90 days, so
# a recovery from backup was actually exercised. False when the complete 90-day read holds none.
# None on an error, a body that is not a job list, or a partial read that ends inside the window.

WINDOW_DAYS = 90


def transform(input):
    key = "isBackupTested"
    validation = extract_validation(input)
    matches, finished, problem, partial = scan_jobs(input, "RESTORE", WINDOW_DAYS, lambda att: True)
    if problem is not None:
        return not_measured(key, problem, validation)
    ok = len(matches) > 0
    if not ok and partial:
        return not_measured(key, "Only part of the last " + str(WINDOW_DAYS) + " days of restore jobs was read (more pages remain); a miss is not scored.", validation)
    text = str(len(matches)) + " NetBackup restore jobs finished successfully in the last " + str(WINDOW_DAYS) + " days (" + str(finished) + " finished)."
    return create_response(
        result={key: ok, "successfulRestores": len(matches), "finishedRestores": finished},
        validation=validation,
        pass_reasons=[text] if ok else [],
        fail_reasons=[] if ok else [text],
        recommendations=[] if ok else ["Run and complete a test restore at least every 90 days."],
        input_summary={"latestRestoreJobs": [a.get("jobId") for a in matches[:10]]},
        metadata={"transformationId": key, "vendor": VENDOR, "category": "backups"},
    )
