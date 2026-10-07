# criticalopenfindingscount.py - Rapid7 InsightCloudSec (Cloud Security, ff4fd43e)
#
# Method: getComplianceScorecard (see compliancepercentage.py).
# Docs:   severity integers 1 Info, 2 Low, 3 Medium, 4 High, 5 Critical (Generate Compliance Scorecard Report,
#         insight_filters.severity). custom_severity, when set, overrides severity.
# Rule:   sum of impacted_resources over every cloud for each Insight whose effective severity is 5, within the
#         selected compliance pack. Findings outside the pack are not counted.

import json
from datetime import datetime, timedelta


def parse(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        value = json.loads(text)
    return value


def envelope_error(value):
    """An Integration-Service or vendor error envelope, as text; None when the value is not one."""
    if not isinstance(value, dict):
        return None
    err = value.get("error")
    if err:
        return "API error: " + str(err)[:200]
    if str(value.get("status", "")).lower() == "error":
        return "API error: " + str(value.get("message") or value.get("detail") or "status Error")[:200]
    code = value.get("status_code", value.get("statusCode"))
    if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
        return "API error: HTTP " + str(code)
    return None


def body_of(input, marker):
    """The vendor body: input["data"] (new TS format), then IS/TS envelopes, until marker(body) is true.
    Returns (body, None) or (None, reason)."""
    value = parse(input)
    if isinstance(input, dict) and "validation" in input and "data" in input:
        value = parse(input.get("data"))
    for depth in range(5):
        problem = envelope_error(value)
        if problem:
            return None, problem
        if marker(value):
            return value, None
        if not isinstance(value, dict):
            return None, "No InsightCloudSec response body"
        nxt = None
        for wrapper in ["apiResponse", "_response_data", "response", "result"]:
            if wrapper in value:
                nxt = parse(value.get(wrapper))
                break
        if nxt is None:
            return None, "Response is not the expected InsightCloudSec body"
        value = nxt
    return None, "Response is not the expected InsightCloudSec body"


def as_count(value):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def response(key, value, extra=None, errors=None, passes=None, fails=None):
    """errors -> dataCollection.status "error": Token-Service records the criterion Unevaluated."""
    out = {key: value}
    if extra:
        out.update(extra)
    return {
        "transformedResponse": out,
        "additionalInfo": {
            "dataCollection": {"status": "error" if errors else "success", "errors": errors or []},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": extra or {}},
            "evaluation": {"passReasons": passes or [], "failReasons": fails or [],
                           "recommendations": [], "additionalFindings": []},
            "metadata": {"transformationId": key, "vendor": "Rapid7", "product": "InsightCloudSec",
                         "category": "Cloud Security", "schemaVersion": "1.0",
                         "evaluatedAt": datetime.utcnow().isoformat() + "Z"},
        },
    }


def scorecard_body(value):
    return (isinstance(value, dict) and isinstance(value.get("page_data"), dict)
            and isinstance(value.get("data"), dict) and isinstance(value["data"].get("scorecard"), list))


def scorecard_rows(input):
    """Every Insight row of the compliance-pack scorecard, each with its per-cloud series.
    Returns (rows, None) or (None, reason). Fails unless every row page and every cloud column was read."""
    body, problem = body_of(input, scorecard_body)
    if problem:
        return None, problem
    rows = body["data"]["scorecard"]
    row_page = body["page_data"].get("row")
    col_page = body["page_data"].get("column")
    if not isinstance(row_page, dict) or not isinstance(col_page, dict):
        return None, "Scorecard page_data has no row/column block"
    row_total = as_count(row_page.get("total_count"))
    col_pages = as_count(col_page.get("total_pages"))
    if row_total is None or col_pages is None:
        return None, "Scorecard page_data has no total_count/total_pages"
    if len(rows) != row_total:
        return None, "Read " + str(len(rows)) + " of " + str(row_total) + " scorecard Insights (paging incomplete)"
    if col_pages > 1:
        return None, "Scorecard has " + str(col_pages) + " pages of clouds; only the first was read"
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("series"), list):
            return None, "A scorecard row has no series"
        for cell in row["series"]:
            if not isinstance(cell, dict):
                return None, "A scorecard cell is not an object"
            if as_count(cell.get("impacted_resources")) is None or as_count(cell.get("total_resources")) is None:
                return None, "A scorecard cell has no impacted_resources/total_resources count"
    return rows, None


def transform(input):
    """Count of resources impacted by Critical (severity 5) Insights in the selected compliance pack.
    None (Unevaluated) on no data, an error, incomplete paging, or a row without a severity."""
    key = "criticalOpenFindingsCount"
    try:
        rows, problem = scorecard_rows(input)
        if problem:
            return response(key, None, errors=[problem])
        count = 0
        critical_insights = 0
        for row in rows:
            sev = row.get("custom_severity")
            if as_count(sev) is None:
                sev = row.get("severity")
            if as_count(sev) is None:
                return response(key, None, errors=["A scorecard row has no severity"])
            if sev == 5:
                impacted = 0
                for cell in row["series"]:
                    impacted = impacted + cell["impacted_resources"]
                if impacted:
                    critical_insights = critical_insights + 1
                count = count + impacted
        extra = {"criticalInsightsWithFindings": critical_insights, "insightCount": len(rows)}
        if count:
            return response(key, count, extra, fails=[str(count) + " resources fail " + str(critical_insights) + " Critical Insights"])
        return response(key, 0, extra, passes=["No resource fails a Critical Insight in the pack"])
    except Exception as e:
        return response(key, None, errors=["Transformation error: " + str(e)[:200]])
