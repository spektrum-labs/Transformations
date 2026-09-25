"""
staleProtectionJobsCount - Veeam Backup & Replication

Enabled backup jobs whose last run is older than 7 days, missing, or did not end Success/Warning (GET /api/v1/jobs/states).

Method: getJobStates
Veeam Backup & Replication REST API reference, revision 1.2-rev0 (x-api-version: 1.2-rev0):
  https://helpcenter.veeam.com/references/vbr/13/rest/1.2-rev0/tag/SectionAbout
Every method sends x-api-version: 1.2-rev0 and the OAuth bearer from POST {serverUrl}/api/oauth2/token.
Role: Veeam Backup Viewer (read-only) is enough for every call this check makes.

Fails closed: an error envelope, an empty or unrecognised body, an unread page or a filter the server did
not apply gives None with the reason. Never a pass from missing data. Tested against the
documented response shapes only (no customer credentials yet).
"""
import json
from datetime import datetime, timedelta, timezone

KEY = "staleProtectionJobsCount"
METHOD = "getJobStates"
PRODUCT = "Veeam Backup & Replication"
FALLBACK = None

WRAPPERS = ["apiResponse", "api_response", "response", "result", "Output"]


def parse_body(raw):
    """The JSON body with Integration-Service envelopes removed. None for an empty body."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    if isinstance(raw, str):
        text = raw.strip()
        if text == "":
            return None
        raw = json.loads(text)
    for depth in range(4):
        if not isinstance(raw, dict):
            break
        nxt = None
        for w in WRAPPERS:
            if isinstance(raw.get(w), dict):
                nxt = raw.get(w)
                break
        if nxt is None:
            break
        raw = nxt
    return raw


def refusal(body):
    """A reason string when the body is empty or an error envelope rather than Veeam data, else None."""
    if body is None:
        return "The response body is empty"
    if not isinstance(body, dict):
        return "The response is not a JSON object"
    err = body.get("error")
    code = body.get("statusCode") or body.get("status_code") or body.get("errorCode")
    if isinstance(err, dict):
        code = code or err.get("statusCode") or err.get("errorCode")
    if err or code or body.get("errorType") or body.get("status") == "Error":
        detail = body.get("message") or body.get("errorMessage") or err or ""
        if isinstance(detail, dict):
            detail = detail.get("message") or json.dumps(detail)[:200]
        return ("The Veeam call did not return data (" + str(code or "error") + "): " + str(detail)[:300] +
                ". This is a credential, permission or reachability result, not a finding.")
    return None


def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def dig(obj, path):
    cur = obj
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def as_int(value):
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def as_num(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def parse_time(value):
    """UTC datetime (naive) from an ISO-8601 string; a string with no offset is read as UTC. None if unreadable."""
    if not isinstance(value, str) or len(value) < 19:
        return None
    head = value[:19]
    digits = head[0:4] + head[5:7] + head[8:10] + head[11:13] + head[14:16] + head[17:19]
    if not digits.isdigit() or head[4] != "-" or head[7] != "-" or head[10] not in "Tt " or head[13] != ":" or head[16] != ":":
        return None
    try:
        # strptime is not used: it imports a module the Token-Service sandbox refuses
        base = datetime(int(head[0:4]), int(head[5:7]), int(head[8:10]), int(head[11:13]), int(head[14:16]), int(head[17:19]))
    except Exception:
        return None
    rest = value[19:]
    i = 0
    if rest.startswith("."):
        i = 1
        while i < len(rest) and rest[i].isdigit():
            i += 1
    tz = rest[i:]
    if tz in ("", "Z", "z"):
        return base
    if len(tz) == 6 and tz[0] in "+-" and tz[3] == ":" and tz[1:3].isdigit() and tz[4:6].isdigit():
        off = timedelta(hours=int(tz[1:3]), minutes=int(tz[4:6]))
        if tz[0] == "+":
            return base - off
        return base + off
    return None


def respond(value, reason, extra=None):
    result = {KEY: value}
    if extra:
        for k in extra:
            result[k] = extra[k]
    bad = value is None or value is False
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "evaluation": {"passReasons": [] if bad else [reason], "failReasons": [reason] if bad else []},
            "metadata": {"transformationId": KEY, "vendor": "Veeam", "product": PRODUCT, "method": METHOD,
                         "evaluatedAt": datetime.now(timezone.utc).isoformat()},
        },
    }


def transform(input):
    try:
        return evaluate(input)
    except Exception as e:
        return respond(FALLBACK, "Transformation error: " + str(e)[:300], {"error": str(e)[:300]})

FINISHED = ["Success", "Warning", "Failed"]
OBJECT_TYPES = ["AmazonS3", "AmazonS3Glacier", "AmazonSnowballEdge", "S3Compatible", "AzureBlob", "AzureArchive",
                "AzureDataBox", "GoogleCloud", "IBMCloud", "WasabiCloud"]


def vbr_list(body, what):
    """(items, None) or (None, reason). A VBR collection is {"data": [...], "pagination": {"total": n, ...}}.
    A body whose data is shorter than pagination.total (an unread page) is refused."""
    why = refusal(body)
    if why:
        return None, what + ": " + why
    items = body.get("data")
    if not isinstance(items, list):
        return None, what + ": the response has no data array"
    total = as_int(dig(body, "pagination.total"))
    if total is None:
        return None, what + ": the response has no pagination.total, so completeness cannot be shown"
    if total > len(items):
        return None, what + ": read " + str(len(items)) + " of " + str(total) + "; the remaining pages were not read"
    for it in items:
        if not isinstance(it, dict):
            return None, what + ": an entry is not an object"
    return items, None


def name_of(obj):
    return str(obj.get("name") or obj.get("id") or "?")


def read_sessions(input, stype, days, what):
    """(finished sessions, None) or (None, reason). Only state Stopped sessions count as finished.
    Refuses a body that shows the server ignored the type or date filter."""
    items, why = vbr_list(parse_body(input), what)
    if why:
        return None, why
    oldest = utc_now() - timedelta(days=days + 1)
    done = []
    for s in items:
        if s.get("sessionType") != stype:
            return None, what + ": a " + str(s.get("sessionType")) + " session was returned, so the type filter was not applied"
        created = parse_time(s.get("creationTime"))
        if created is None:
            return None, what + ": session " + name_of(s) + " has no readable creationTime"
        if created < oldest:
            return None, what + ": a session older than " + str(days) + " days was returned, so the date filter was not applied"
        if s.get("state") != "Stopped":
            continue
        res = dig(s, "result.result")
        if res not in FINISHED:
            return None, what + ": finished session " + name_of(s) + " has result " + str(res)
        done.append(s)
    return done, None


def latest(sessions):
    best = None
    best_t = None
    for s in sessions:
        t = parse_time(s.get("endTime")) or parse_time(s.get("creationTime"))
        if t is not None and (best_t is None or t > best_t):
            best, best_t = s, t
    return best


def enabled_jobs(body, what):
    """(enabled backup jobs, None) or (None, reason). API revision 1.2 lists VMware vSphere backup jobs as type Backup."""
    items, why = vbr_list(body, what)
    if why:
        return None, why
    out = []
    for j in items:
        if j.get("type") != "Backup":
            continue
        dis = j.get("isDisabled")
        if not isinstance(dis, bool):
            return None, what + ": job " + name_of(j) + " has no isDisabled flag"
        if dis is False:
            out.append(j)
    return out, None


def read_targets(input):
    """(context, None) or (None, reason) from the getRepositoryTargets workflow body
    {"jobs": ..., "repositories": ..., "scaleOutRepositories": ...}."""
    body = parse_body(input)
    why = refusal(body)
    if why:
        return None, why
    jobs, why = enabled_jobs(parse_body(body.get("jobs")), "jobs (GET /api/v1/jobs)")
    if why:
        return None, why
    repos, why = vbr_list(parse_body(body.get("repositories")), "repositories (GET /api/v1/backupInfrastructure/repositories)")
    if why:
        return None, why
    sobrs, why = vbr_list(parse_body(body.get("scaleOutRepositories")),
                          "scale-out repositories (GET /api/v1/backupInfrastructure/scaleOutRepositories)")
    if why:
        return None, why
    rmap = {}
    for r in repos:
        rmap[str(r.get("id")).lower()] = r
    smap = {}
    for s in sobrs:
        smap[str(s.get("id")).lower()] = s
    return {"jobs": jobs, "repos": rmap, "sobrs": smap}, None


def resolve(ctx, job):
    """(repositories, scale-out repository or None, None) or (None, None, reason) for a job's target."""
    rid = str(dig(job, "storage.backupRepositoryId")).lower()
    if rid in ctx["repos"]:
        return [ctx["repos"][rid]], None, None
    if rid in ctx["sobrs"]:
        sobr = ctx["sobrs"][rid]
        extents = dig(sobr, "performanceTier.performanceExtents")
        if not isinstance(extents, list) or len(extents) == 0:
            return None, None, "scale-out repository " + name_of(sobr) + " lists no performance extents"
        out = []
        for e in extents:
            eid = str(e.get("id") if isinstance(e, dict) else None).lower()
            if eid not in ctx["repos"]:
                return None, None, "extent " + eid + " of " + name_of(sobr) + " is not in the repository list"
            out.append(ctx["repos"][eid])
        return out, sobr, None
    return None, None, ("job " + name_of(job) + " targets repository " + rid +
                        ", which is in neither the repository nor the scale-out repository list")


def immutable(repo):
    """True when the repository enforces immutability: hardened Linux (makeRecentBackupsImmutableDays > 0) or
    object storage with immutability enabled for a positive number of days (Glacier: immutabilityEnabled)."""
    t = repo.get("type")
    if t == "LinuxHardened":
        d = as_int(dig(repo, "repository.makeRecentBackupsImmutableDays"))
        return d is not None and d > 0
    if t == "AmazonS3Glacier":
        return dig(repo, "bucket.immutabilityEnabled") is True
    im = dig(repo, "bucket.immutability")
    if isinstance(im, dict):
        d = as_int(im.get("daysCount"))
        return im.get("isEnabled") is True and d is not None and d > 0
    return False


def encrypted(job):
    return dig(job, "storage.advancedSettings.storageData.encryption.isEnabled") is True


def evaluate(input):
    items, why = vbr_list(parse_body(input), "job states (GET /api/v1/jobs/states)")
    if why:
        return respond(None, why)
    cutoff = utc_now() - timedelta(days=7)
    live = []
    stale = []
    for s in items:
        if s.get("type") != "Backup":
            continue
        st = str(s.get("status") or "")
        if st == "":
            return respond(None, "Job " + name_of(s) + " has no status")
        if st.lower() == "disabled":
            continue
        live.append(s)
        last = parse_time(s.get("lastRun"))
        if last is None or last < cutoff or s.get("lastResult") not in ["Success", "Warning"]:
            stale.append(name_of(s) + " (last run " + str(s.get("lastRun")) + ", " + str(s.get("lastResult")) + ")")
    if len(live) == 0:
        return respond(None, "No enabled backup job was found, so the stale count is not proven")
    return respond(len(stale), str(len(stale)) + " of " + str(len(live)) + " enabled backup jobs have not run successfully in the last 7 days",
                   {"enabledBackupJobs": len(live), "staleJobs": stale[:25]})
