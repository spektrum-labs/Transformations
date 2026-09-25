"""
Transformation: quorumReviewerRoleAssignedCount
Vendor: Rubrik  |  Category: Backup  |  Product: Rubrik Security Cloud (RSC)
Evaluates: Active users holding a role that can approve TPR requests.
API Source: listUsersWithRoles (POST https://<account>.my.rubrik.com/api/graphql, read-only GraphQL query)
Schema: rubrikinc/rubrik-developer-center docs/Rubrik-Security-Cloud-API/schemas/20260914.graphql
        https://developer.rubrik.com/Rubrik-Security-Cloud-API/API-Reference/queries/usersInCurrentAndDescendantOrganization/
Note: Reviewer = holds a role whose effective permissions include APPROVE_TPR_REQUEST; deactivated users excluded.
Fails closed: a refused call, a GraphQL error on the field this check reads, an incomplete page or an
unrecognised body is False (booleans) or None (numbers), with the reason. Never True from missing data.
"""
import json
from datetime import datetime, timezone

KEY = "quorumReviewerRoleAssignedCount"
METHOD = "listUsersWithRoles"
WRAPPERS = ("result", "apiResponse", "api_response", "response", "_response_data", "Output")


def extract_input(raw):
    """(body, validation). body is the GraphQL response {"data": ..., "errors": [...]} with IS/TS wrappers removed."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    if isinstance(raw, str):
        raw = json.loads(raw)
    validation = {"status": "unknown", "errors": [], "warnings": ["Legacy input format - no schema validation performed"]}
    if isinstance(raw, dict) and "validation" in raw and "data" in raw:
        validation = raw.get("validation") if isinstance(raw.get("validation"), dict) else validation
        raw = raw.get("data")
    body = raw
    for attempt in range(4):
        if not isinstance(body, dict):
            break
        nxt = None
        for key in WRAPPERS:
            if isinstance(body.get(key), dict):
                nxt = body.get(key)
                break
        if nxt is None:
            break
        body = nxt
    return body, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    errors = transformation_errors or []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "success", "errors": []},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": "error" if errors else "success",
                "errors": errors,
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": [],
            },
            "metadata": {
                "evaluatedAt": datetime.now(timezone.utc).isoformat(),
                "schemaVersion": "2.0",
                "transformationId": KEY,
                "vendor": "Rubrik",
                "category": "Backup",
            },
        },
    }


def unknown_value():
    return None


def fail(validation, reason, recommendation=None, summary=None, extra=None, value=None):
    result = {KEY: unknown_value() if value is None else value}
    if extra:
        result.update(extra)
    return create_response(result=result, validation=validation, fail_reasons=[reason],
                           recommendations=[recommendation] if recommendation else [],
                           input_summary=summary or {})


def ok(validation, value, reason, summary=None, extra=None):
    result = {KEY: value}
    if extra:
        result.update(extra)
    return create_response(result=result, validation=validation, pass_reasons=[reason], input_summary=summary or {})


def refusal(body):
    """Reason string when the body is an IS/vendor error envelope rather than a GraphQL response, else None."""
    if not isinstance(body, dict):
        return None
    if not (body.get("error") or body.get("errorType") or body.get("status") == "Error" or body.get("statusCode")):
        return None
    if isinstance(body.get("data"), dict):
        return None
    status = body.get("statusCode") or body.get("status_code") or body.get("vendorStatus")
    detail = body.get("message") or body.get("errorMessage") or body.get("error") or ""
    return "HTTP " + str(status) + ": " + str(detail)[:300]


def graphql_errors(body, fields):
    """Messages of GraphQL errors that touch any of `fields` (by top-level path) or carry no path (whole request)."""
    out = []
    errs = body.get("errors") if isinstance(body, dict) else None
    if not isinstance(errs, list):
        return out
    for e in errs:
        if not isinstance(e, dict):
            out.append(str(e)[:300])
            continue
        path = e.get("path")
        top = path[0] if isinstance(path, list) and path else None
        if top is None or top in fields:
            out.append(str(e.get("message", ""))[:300])
    return out


def root_of(body, fields):
    """The GraphQL `data` object when every field this check reads is present, else None."""
    if not isinstance(body, dict):
        return None
    root = body.get("data")
    if not isinstance(root, dict):
        root = body if all(f in body for f in fields) else None
    if root is None:
        return None
    for f in fields:
        if f not in root or root.get(f) is None:
            return None
    return root


def as_count(node):
    """Integer `count` of a connection alias; None when absent or not an integer (booleans are not counts)."""
    if not isinstance(node, dict):
        return None
    c = node.get("count")
    if isinstance(c, bool) or not isinstance(c, int) or c < 0:
        return None
    return c


def page_complete(conn):
    """True when a connection's nodes are the whole set. IS pagination merges pages, keeps page-1 pageInfo with endCursor
    nulled, and adds truncated when maxPages stopped it."""
    if not isinstance(conn, dict) or not isinstance(conn.get("nodes"), list):
        return False
    info = conn.get("pageInfo")
    if not isinstance(info, dict):
        return False
    if info.get("truncated") is True:
        return False
    if info.get("hasNextPage") is False:
        return True
    return info.get("hasNextPage") is True and info.get("endCursor") is None


def read(input, fields, what):
    """(root, validation, failure). failure is a ready response when the body cannot answer this check."""
    body, validation = extract_input(input)
    why = refusal(body)
    if why:
        return None, validation, fail(validation, "The Rubrik call did not return data - " + why +
                                      ". This is a credential or reachability result, not a finding; the control's state is unknown.",
                                      "Check the Rubrik Security Cloud URL and service account in the integration settings.",
                                      {"endpointReachable": False})
    errs = graphql_errors(body, fields)
    if errs:
        return None, validation, fail(validation, "Rubrik Security Cloud returned a GraphQL error for " + what + ": " + "; ".join(errs),
                                      "Grant the service account read access to " + what + " (RSC Settings > Users and Roles).",
                                      {"graphqlErrors": errs})
    root = root_of(body, fields)
    if root is None:
        return None, validation, fail(validation, what + " response not recognised - the GraphQL data for " + ", ".join(fields) +
                                      " is missing.", "Inspect the raw integration response.", {"endpointReachable": None})
    return root, validation, None


def transform(input):
    try:
        return evaluate(input)
    except Exception as exc:
        return create_response(
            result={KEY: unknown_value()},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(exc)],
            fail_reasons=["Transformation raised an unexpected error: " + str(exc)],
            recommendations=["Report this to the Spektrum integrations team with the raw API response."],
        )


RESTORE_OPS = ("RESTORE", "RESTORE_TO_ORIGIN", "INSTANT_RECOVER", "EXPORT", "EXPORT_SNAPSHOTS", "EXPORT_FILES", "DOWNLOAD",
               "GRANULAR_RECOVERY", "SELF_SERVICE_RESTORE", "CATEGORY_RECOVERY")
ACCESS_ADMIN_OPS = ("MANAGE_ACCESS", "MANAGE_USER", "MANAGE_ROLE", "MANAGE_AUTH_DOMAIN")


def operations(role):
    ops = set()
    perms = role.get("effectiveRbacPermissions") if isinstance(role, dict) else None
    if not isinstance(perms, list):
        return None
    for p in perms:
        if isinstance(p, dict) and isinstance(p.get("operations"), list):
            for o in p.get("operations"):
                ops.add(o)
    return ops

def evaluate(input):
    root, validation, failure = read(input, ["usersInCurrentAndDescendantOrganization"], "users (usersInCurrentAndDescendantOrganization)")
    if failure:
        return failure
    conn = root.get("usersInCurrentAndDescendantOrganization")
    if not page_complete(conn):
        return fail(validation, "The user list is incomplete (more pages than were read), so the reviewer count would be a guess.", None,
                    {"pageInfo": conn.get("pageInfo") if isinstance(conn, dict) else None})
    reviewers = 0
    for u in conn.get("nodes"):
        if not isinstance(u, dict) or u.get("status") == "DEACTIVATED":
            continue
        roles = u.get("roles") if isinstance(u.get("roles"), list) else []
        for r in roles:
            ops = operations(r)
            if ops is not None and "APPROVE_TPR_REQUEST" in ops:
                reviewers = reviewers + 1
                break
    summary = {"users": len(conn.get("nodes")), "reviewers": reviewers}
    return ok(validation, reviewers, str(reviewers) + " of " + str(len(conn.get("nodes"))) + " users hold a role that can approve Quorum Authorization requests.", summary)
