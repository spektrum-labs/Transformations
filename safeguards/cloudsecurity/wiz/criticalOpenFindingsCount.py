"""
Transformation: criticalOpenFindingsCount
Vendor: Wiz  |  Category: Cloud Security

Integration-Service method: a GraphQL POST to https://api.<data center>.app.wiz.io/graphql that reads the
`issues` connection, selecting for each issue its `severity` and `status` and the connection's `pageInfo`
(the stored getIssues query does; the filtered method proposed for this check selects the same fields).
Value: the number of issues in the read whose severity is CRITICAL and whose status is OPEN or IN_PROGRESS.
RESOLVED and REJECTED issues are not open and are not counted. The transform judges every node itself, so it
gives the same answer on a read that was filtered to critical open issues as on an unfiltered one.

UNVERIFIED (no real tenant read yet): the vendor's schema reference sits behind a login. The issue fields
`severity` and `status` and the status names are the ones the stored getIssues query selects and that Wiz's
own console uses; the filtered query's filterBy shape is not confirmed against a tenant.

Fail closed (Not evaluated, never a pass, never 0): a GraphQL `errors` list (even next to partial data), an error or
refused (401/403) answer, an empty, unrecognised or non-JSON body, an `issues` connection with no node list, a
read that is not complete (pageInfo missing, or hasNextPage true: this read holds one page, so a count of it
could be short), or any node without a readable severity and status all give null.
"""

import json
from datetime import datetime, timezone

VENDOR = "Wiz"
CATEGORY = "Cloud Security"
KEY = "criticalOpenFindingsCount"
OPEN_STATUSES = ("OPEN", "IN_PROGRESS")
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
    code = node.get("statusCode")
    status = node.get("status")
    errors = node.get("errors")
    if isinstance(errors, list) and errors:
        first = errors[0]
        text = first.get("message") if isinstance(first, dict) else first
        return "the vendor returned a GraphQL error: " + str(text)[:160]
    if node.get("error") is True or node.get("errorType") or (node.get("error") and not isinstance(node.get("error"), bool)):
        return "error answer: " + str(node.get("message") or node.get("error") or node.get("errorType"))[:160]
    for number in (code, status):
        if isinstance(number, int) and not isinstance(number, bool) and number >= 400:
            return "HTTP " + str(number) + ": " + str(node.get("message") or "")[:160]
    if status is False:
        return "the vendor answered status false: " + str(node.get("message") or "")[:160]
    return None


def find_connection(data):
    """(connection, problem): the `issues` connection found under any wrapper, or why there is none."""
    node = data
    for depth in range(6):
        if not isinstance(node, dict):
            return None, "the response is empty or not a JSON object"
        problem = error_text(node)
        if problem:
            return None, problem
        if "issues" in node:
            if not isinstance(node["issues"], dict):
                return None, "the issues connection is missing or null"
            return node["issues"], None
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
    return None, "no issues connection in the response"


def open_critical(input):
    """(read, problem): the issue nodes of a COMPLETE read and how many are open critical, or why nothing was measured."""
    connection, problem = find_connection(parse(input))
    if problem:
        return None, problem
    nodes = connection.get("nodes")
    if not isinstance(nodes, list):
        return None, "the issues connection has no node list"
    page = connection.get("pageInfo")
    more = page.get("hasNextPage") if isinstance(page, dict) else None
    if not isinstance(more, bool):
        return None, "the read does not say whether it is complete (no pageInfo.hasNextPage), so it is not scored"
    if more:
        return None, "the read holds one page of " + str(len(nodes)) + " issues and more exist, so a count of it could be short"
    count = 0
    for node in nodes:
        if not isinstance(node, dict):
            return None, "the issue list holds an entry that is not an object"
        severity = node.get("severity")
        status = node.get("status")
        if not isinstance(severity, str) or not isinstance(status, str) or not severity.strip() or not status.strip():
            return None, "an issue has no readable severity and status, so the count was not measured"
        if severity.strip().upper() == "CRITICAL" and status.strip().upper() in OPEN_STATUSES:
            count = count + 1
    return {"issuesRead": len(nodes), "count": count}, None


def build_response(result, pass_reasons=None, fail_reasons=None, errors=None, summary=None,
                   recommendations=None, transform_id=""):
    errors = errors or []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if errors else "success", "errors": errors},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "error" if errors else "success", "errors": errors,
                               "inputSummary": summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.now(timezone.utc).isoformat(), "schemaVersion": "1.0",
                         "transformationId": transform_id, "vendor": VENDOR, "category": CATEGORY},
        },
    }


def transform(input):
    try:
        read, problem = open_critical(input)
        if problem:
            return build_response({KEY: None}, errors=[problem], transform_id=KEY)
        count = read["count"]
        summary = {"issuesRead": read["issuesRead"], KEY: count}
        if count > 0:
            return build_response({KEY: count}, fail_reasons=[
                str(count) + " open critical issues in the " + str(read["issuesRead"]) + " issues read"], summary=summary,
                recommendations=["Work the open critical issues in Wiz, starting with the ones on internet-exposed resources."],
                transform_id=KEY)
        return build_response({KEY: 0}, pass_reasons=[
            "No open critical issues in the " + str(read["issuesRead"]) + " issues read"], summary=summary, transform_id=KEY)
    except Exception as error:
        return build_response({KEY: None}, errors=[str(error)[:300]], transform_id=KEY)
