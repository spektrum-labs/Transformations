"""
Transformation: criticalOpenFindingsCount
Vendor: AWS Security Agent  |  Category: Application Security

Workflow getPentestPosture, legs:
  activeFindings <- listActiveFindings: POST /ListFindings {"agentSpaceId": <configured>, "status": "ACTIVE"}
  pentests, pentestDetails, pentestJobs (see isPentestRunInCICD), to name the affected application
  and to prove a test ever ran.
  https://docs.aws.amazon.com/securityagent/latest/userguide/cicd-pentest.html

The number of OPEN (status ACTIVE) CRITICAL findings raised by penetration tests in the Agent
Space. Findings from code reviews (no pentestId / pentestJobId) are not counted, nor are findings
whose confidence is FALSE_POSITIVE. RESOLVED, ACCEPTED (risk accepted) and FALSE_POSITIVE statuses
are not open. Each counted finding is named with its penetration test, target URLs and repository.

Fail closed:
- any failed read is null, never 0;
- 0 is reported only when the findings list was read completely (no nextToken) AND at least one
  penetration test run has COMPLETED -- zero findings from a test that never ran proves nothing;
- a truncated findings list with matches reports the count read as a lower bound
  (countIsLowerBound true), which can only make the result worse, never better.
"""

import json
from datetime import datetime, timezone

VENDOR = "AWS Security Agent"
CATEGORY = "Application Security"
RECENT_DAYS = 90
LEG_KEYS = ("agentSpaces", "pentests", "pentestDetails", "pentestJobs", "activeFindings")
MAX_NAMED = 10


def parse(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        value = json.loads(value) if value.strip() else None
    return value


def find_legs(data):
    """The merged workflow output: a dict carrying at least one leg key, possibly under the
    usual Integration-Service wrappers."""
    for depth in range(6):
        if not isinstance(data, dict):
            return None
        for key in LEG_KEYS:
            if key in data:
                return data
        nxt = None
        for key in ("data", "response", "result", "apiResponse", "Output"):
            if isinstance(data.get(key), dict):
                nxt = data[key]
                break
        if nxt is None:
            return None
        data = nxt
    return None


def error_text(body):
    """Why a leg body is an error, or None. Integration-Service envelopes and AWS rest-json
    error bodies ({"message": ...} / {"__type": ...}) both count."""
    if not isinstance(body, dict):
        return "not an object"
    if body.get("error") is True or body.get("errorType"):
        return "Integration-Service error " + str(body.get("statusCode") or "") + ": " + str(
            body.get("message") or body.get("errorMessage") or "")[:200]
    if body.get("__type"):
        return "AWS error " + str(body.get("__type"))[:120]
    return None


def read_page(body, list_key):
    """(items, truncated, problem) for one paginated list response."""
    problem = error_text(body)
    if problem:
        return None, False, problem
    items = body.get(list_key)
    if not isinstance(items, list):
        if body.get("message") or body.get("Message"):
            return None, False, "AWS error: " + str(body.get("message") or body.get("Message"))[:200]
        return None, False, "unrecognised response shape (no " + list_key + " list)"
    return [i for i in items if isinstance(i, dict)], bool(body.get("nextToken")), None


def read_iterated(leg, list_key, expected):
    """One response per pentest (an iterate step). Every element must be a readable page,
    and there must be one per pentest; anything else is a read that did not happen."""
    if not isinstance(leg, list):
        if isinstance(leg, dict):
            problem = error_text(leg) or "a single object where one response per pentest was expected"
            return None, False, problem
        return None, False, "not returned"
    if len(leg) != expected:
        return None, False, str(len(leg)) + " responses for " + str(expected) + " pentests"
    items, truncated = [], False
    for body in leg:
        page, more, problem = read_page(body, list_key)
        if problem:
            return None, False, problem
        items = items + page
        truncated = truncated or more
    return items, truncated, None


def parse_time(value):
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        seconds = float(value)
        if seconds > 100000000000:
            seconds = seconds / 1000.0
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (ValueError, OverflowError, OSError):
            return None
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
    return int((now - stamp).total_seconds() // 86400)


def load_estate(data):
    """Read every leg the five checks share. Returns a dict; each value is None when that leg
    could not be read, with the reason in problems[leg]."""
    estate = {"problems": {}, "pentests": None, "pentestsTruncated": False, "details": {},
              "jobs": None, "jobsTruncated": False, "findings": None, "findingsTruncated": False}
    legs = find_legs(parse(data))
    if legs is None:
        estate["problems"]["pentests"] = "no AWS Security Agent workflow output in the response"
        return estate
    if "pentests" in legs:
        pentests, more, problem = read_page(legs.get("pentests"), "pentestSummaries")
    else:
        pentests, more, problem = None, False, "not returned"
    if problem:
        estate["problems"]["pentests"] = "ListPentests: " + problem
    else:
        estate["pentests"] = [p for p in pentests if p.get("pentestId")]
        estate["pentestsTruncated"] = more
    count = len(estate["pentests"]) if estate["pentests"] is not None else 0
    if estate["pentestsTruncated"]:
        estate["problems"]["jobs"] = "ListPentests returned more pages than were read, so not every pentest's runs were read"
    if estate["pentests"] is not None and not estate["pentestsTruncated"]:
        details, more_d, problem = read_iterated(legs.get("pentestDetails"), "pentests", count)
        if problem is None:
            for item in details:
                if item.get("pentestId"):
                    estate["details"][item["pentestId"]] = item
        jobs, more_j, problem = read_iterated(legs.get("pentestJobs"), "pentestJobSummaries", count)
        if problem:
            estate["problems"]["jobs"] = "ListPentestJobsForPentest: " + problem
        else:
            estate["jobs"] = jobs
            estate["jobsTruncated"] = more_j
    if "activeFindings" in legs:
        findings, more_f, problem = read_page(legs.get("activeFindings"), "findingsSummaries")
    else:
        findings, more_f, problem = None, False, "not returned"
    if problem:
        estate["problems"]["findings"] = "ListFindings: " + problem
    else:
        estate["findings"] = findings
        estate["findingsTruncated"] = more_f
    return estate


def pentest_label(estate, pentest_id):
    """'title' (targets: ...; repositories: ...) for the pentest a job or finding belongs to."""
    title = None
    for p in estate["pentests"] or []:
        if p.get("pentestId") == pentest_id:
            title = p.get("title")
    detail = estate["details"].get(pentest_id) or {}
    title = title or detail.get("title") or str(pentest_id)
    # Integration-Service projects BatchGetPentests to top-level endpoints / integratedRepositories;
    # the raw AWS shape nests them under assets. Read either.
    assets = detail.get("assets") if isinstance(detail.get("assets"), dict) else detail
    targets = [e.get("uri") for e in (assets.get("endpoints") or []) if isinstance(e, dict) and e.get("uri")]
    repos = [r.get("providerResourceId") for r in (assets.get("integratedRepositories") or [])
             if isinstance(r, dict) and r.get("providerResourceId")]
    parts = []
    if targets:
        parts.append("targets: " + ", ".join(targets[:3]) + (" +" + str(len(targets) - 3) if len(targets) > 3 else ""))
    if repos:
        parts.append("repositories: " + ", ".join(repos[:3]) + (" +" + str(len(repos) - 3) if len(repos) > 3 else ""))
    return "'" + str(title) + "'" + (" (" + "; ".join(parts) + ")" if parts else "")


def completed_jobs(estate, job_types, now):
    """COMPLETED jobs of the given types, newest first, as (days_ago, job)."""
    out = []
    for job in estate["jobs"] or []:
        if job.get("status") != "COMPLETED":
            continue
        if job_types is not None and job.get("jobType") not in job_types:
            continue
        started = parse_time(job.get("createdAt"))
        if started is None:
            continue
        out.append((days_ago(started, now), job))
    out.sort(key=lambda pair: pair[0])
    return out


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

CRITERIA_KEY = "criticalOpenFindingsCount"
TRANSFORM_ID = "criticalopenfindingscount"
RISK_LEVEL = "CRITICAL"


def is_counted(finding):
    if finding.get("riskLevel") != RISK_LEVEL:
        return False
    if finding.get("status") not in (None, "ACTIVE"):
        return False
    if finding.get("confidence") == "FALSE_POSITIVE":
        return False
    return bool(finding.get("pentestId") or finding.get("pentestJobId"))


def transform(input):
    try:
        estate = load_estate(input)
        if estate["findings"] is None:
            return build_response({CRITERIA_KEY: None}, errors=[estate["problems"].get("findings", "not read")],
                                  transform_id=TRANSFORM_ID)
        now = datetime.now(timezone.utc)
        counted = [f for f in estate["findings"] if is_counted(f)]
        result = {CRITERIA_KEY: None, "countIsLowerBound": False}
        named = []
        for finding in counted[:MAX_NAMED]:
            opened = parse_time(finding.get("createdAt"))
            named.append(str(finding.get("name") or finding.get("findingId")) +
                         (" [" + str(finding.get("riskType")) + "]" if finding.get("riskType") else "") +
                         " in " + pentest_label(estate, finding.get("pentestId")) +
                         (", validation " + str(finding.get("validationStatus")) if finding.get("validationStatus") else "") +
                         (", open " + str(days_ago(opened, now)) + " day(s)" if opened is not None else ""))
        summary = {"activeFindingsRead": len(estate["findings"]), "counted": len(counted),
                   "truncated": estate["findingsTruncated"]}
        if counted:
            result[CRITERIA_KEY] = len(counted)
            result["countIsLowerBound"] = estate["findingsTruncated"]
            more = len(counted) - len(named)
            return build_response(result, fail_reasons=[
                str(len(counted)) + ("+" if estate["findingsTruncated"] else "") + " open " + RISK_LEVEL +
                " penetration test finding(s): " + "; ".join(named) + (" and " + str(more) + " more" if more > 0 else "")],
                findings=named, summary=summary, transform_id=TRANSFORM_ID)
        if estate["findingsTruncated"]:
            return build_response(result, errors=["ListFindings was truncated before any open " + RISK_LEVEL +
                                                  " finding was read; the count is unknown"],
                                  summary=summary, transform_id=TRANSFORM_ID)
        if estate["jobs"] is None:
            return build_response(result, errors=[estate["problems"].get("jobs") or estate["problems"].get("pentests")
                                                  or "pentest runs not read"], summary=summary, transform_id=TRANSFORM_ID)
        ran = completed_jobs(estate, None, now)
        if not ran:
            return build_response(result, errors=["No penetration test run has completed in this Agent Space, so zero "
                                                  "open findings proves nothing"], summary=summary, transform_id=TRANSFORM_ID)
        result[CRITERIA_KEY] = 0
        return build_response(result, pass_reasons=[
            "No open " + RISK_LEVEL + " penetration test findings; " + str(len(ran)) +
            " completed run(s), the latest " + str(ran[0][0]) + " day(s) ago"], summary=summary, transform_id=TRANSFORM_ID)
    except Exception as error:
        return build_response({CRITERIA_KEY: None}, errors=[str(error)], transform_id=TRANSFORM_ID)
