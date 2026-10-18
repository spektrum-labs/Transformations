"""
Transformation: securityRatingScore
Vendor: SecurityScorecard  |  Category: Cyber Risk Quantification (CRQ)

Integration-Service method getCompanyDetails: GET {apiBaseUrl}/companies/{companyDomain}.
Source: the vendor's public API reference, securityscorecard.readme.io, operation "Get a company
information and scorecard summary", whose response CompanySummary holds name, domain, grade (A to F, or "?"
while the vendor is still calculating) and score (an integer from 0 to 100, undefined while calculating).
Value: the vendor's current `score` for the one company domain the integration is configured for. Higher is better.
This transform reports the figure; the bar it must clear is the requirement's, not this file's.

Fail closed (Not evaluated, never a pass, never 0): an error or refused (401/403) answer, an empty, unrecognised
or non-JSON body, a body without the company's domain, a grade that is not A to F (including "?"), a missing score or one
that is not a whole number from 0 to 100 all give null. A body that only happens to hold a `score` field, with no
domain and no grade, is not a scorecard and gives null.
"""

import json
from datetime import datetime, timezone

VENDOR = "SecurityScorecard"
CATEGORY = "Cyber Risk Quantification (CRQ)"
KEY = "securityRatingScore"
GRADES = ("A", "B", "C", "D", "F")
# Integration-Service wraps a method response in one of these; the vendor's own body is the bare object.
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
    """Why a dict is an error answer rather than the vendor's scorecard, or None."""
    code = node.get("statusCode")
    status = node.get("status")
    problem = node.get("error")
    if problem is True or node.get("errorType") or (problem and "grade" not in node and "score" not in node):
        detail = problem if isinstance(problem, (str, dict)) else (node.get("statusCode") or node.get("errorType"))
        return "error answer: " + str(detail)[:160]
    for number in (code, status):
        if isinstance(number, int) and not isinstance(number, bool) and number >= 400:
            return "HTTP " + str(number) + ": " + str(node.get("message") or "")[:160]
    if status is False:
        return "the vendor answered status false: " + str(node.get("message") or "")[:160]
    return None


def find_summary(data):
    """(summary, problem): the CompanySummary found under any wrapper, or why there is none."""
    node = data
    for depth in range(6):
        if not isinstance(node, dict):
            return None, "the response is empty or not a JSON object"
        problem = error_text(node)
        if problem:
            return None, problem
        if "score" in node or "grade" in node:
            return node, None
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
    return None, "no company scorecard in the response"


def company_score(input):
    """(summary, problem): the scorecard of a coherent answer, or why nothing was measured."""
    node, problem = find_summary(parse(input))
    if problem:
        return None, problem
    domain = node.get("domain")
    if not isinstance(domain, str) or not domain.strip():
        return None, "the response names no company domain, so it is not a company scorecard"
    grade = node.get("grade")
    if grade == "?":
        return None, "the vendor is still calculating this company's grade, so nothing was measured"
    if grade not in GRADES:
        return None, "the response has no grade from A to F, so it is not a finished scorecard"
    score = node.get("score")
    if isinstance(score, bool) or not isinstance(score, int) or score < 0 or score > 100:
        return None, "the response has no whole-number score from 0 to 100, so it was not measured"
    return node, None


def build_response(result, findings=None, errors=None, summary=None, transform_id=""):
    errors = errors or []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if errors else "success", "errors": errors},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "error" if errors else "success", "errors": errors,
                               "inputSummary": summary or {}},
            "evaluation": {"passReasons": [], "failReasons": [], "recommendations": [],
                           "additionalFindings": findings or []},
            "metadata": {"evaluatedAt": datetime.now(timezone.utc).isoformat(), "schemaVersion": "1.0",
                         "transformationId": transform_id, "vendor": VENDOR, "category": CATEGORY},
        },
    }


def transform(input):
    try:
        card, problem = company_score(input)
        if problem:
            return build_response({KEY: None}, errors=[problem], transform_id=KEY)
        summary = {"domain": card["domain"], "grade": card["grade"], KEY: card["score"]}
        return build_response({KEY: card["score"]}, findings=[
            "SecurityScorecard rates " + card["domain"] + " " + str(card["score"]) + " out of 100 (grade " + card["grade"] + ")"],
            summary=summary, transform_id=KEY)
    except Exception as error:
        return build_response({KEY: None}, errors=[str(error)[:300]], transform_id=KEY)
