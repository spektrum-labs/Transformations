"""
isBackupImmutable - Veeam Backup for Microsoft 365

Every object storage repository has enableImmutability true (GET /v8/BackupRepositories objectStorage).

Method: getRepositories
Veeam Backup for Microsoft 365 REST API v8 reference:
  https://helpcenter.veeam.com/references/vbo365/8/rest/tag/SectionAbout
Every method uses the OAuth bearer from POST {serverUrl}/v8/token (grant_type=password,
disable_antiforgery_token=true). Pagination: limit=10000; a page that links to a next page is refused.

Fails closed: an error envelope, an empty or unrecognised body, an unread page or a filter the server did
not apply gives False with the reason. Never a pass from missing data. Tested against the
documented response shapes only (no customer credentials yet).
"""
import json
from datetime import datetime, timedelta, timezone

KEY = "isBackupImmutable"
METHOD = "getRepositories"
PRODUCT = "Veeam Backup for Microsoft 365"
FALLBACK = False

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

def page_list(body, what):
    """(results, None) or (None, reason). A VB365 page is {"results": [...], "limit": n, "_links": {...}}; a page
    that links to a next page was not read in full and is refused."""
    why = refusal(body)
    if why:
        return None, what + ": " + why
    items = body.get("results")
    if not isinstance(items, list):
        return None, what + ": the response has no results array"
    links = body.get("_links")
    if isinstance(links, dict) and links.get("next"):
        return None, what + ": the response links to a further page, which was not read"
    limit = as_int(body.get("limit"))
    if limit is not None and limit > 0 and len(items) >= limit:
        return None, what + ": the page is full (" + str(limit) + " items), so more may exist"
    for it in items:
        if not isinstance(it, dict):
            return None, what + ": an entry is not an object"
    return items, None


def name_of(obj):
    return str(obj.get("name") or obj.get("id") or "?")


def enabled(items, what):
    """(enabled jobs, None) or (None, reason)."""
    out = []
    for j in items:
        flag = j.get("isEnabled")
        if not isinstance(flag, bool):
            return None, what + ": job " + name_of(j) + " has no isEnabled flag"
        if flag:
            out.append(j)
    return out, None


def object_repos(input):
    """(object storage repositories, all repositories, None) or (None, None, reason)."""
    items, why = page_list(parse_body(input), "backup repositories (GET /v8/BackupRepositories)")
    if why:
        return None, None, why
    objs = [r for r in items if isinstance(r.get("objectStorage"), dict)]
    return objs, items, None


def evaluate(input):
    objs, allrepos, why = object_repos(input)
    if why:
        return respond(False, why)
    if len(objs) == 0:
        return respond(False, "No object storage repository was found (" + str(len(allrepos)) + " repositories read)")

    bad = [name_of(r) for r in objs if dig(r, "objectStorage.enableImmutability") is not True]
    if bad:
        return respond(False, str(len(bad)) + " of " + str(len(objs)) + " object storage repositories are not immutable", {"repositories": bad[:25]})
    return respond(True, "All " + str(len(objs)) + " object storage repositories have immutability enabled")
