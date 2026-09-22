"""
Transformation: isSafeLinksEnabled
Vendor: Proofpoint (Threat Protection / Core Email Protection)  |  Category: Email Security
Evaluates: URL Defense is rewriting inbound links, proven by the share of URL-bearing messages that were rewritten in the messages-protected report.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        for key in ["api_response", "response", "result", "apiResponse", "rawResponse"]:
            if key in data and isinstance(data.get(key), dict):
                data = data[key]
                break
    return data, {"status": "unknown", "errors": [], "warnings": []}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": validation,
            "transformation": {"status": "error" if (transformation_errors or []) else "success",
                               "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": "isSafeLinksEnabled", "vendor": "Proofpoint", "category": "Email Security"},
        },
    }
def find_breakdown(rows, name):
    for r in rows:
        if isinstance(r, dict) and str(r.get("breakdownName", "")).lower() == name:
            return r
    return None


def evaluate(data):
    if not isinstance(data, dict):
        return {"isSafeLinksEnabled": False, "reason": "Unexpected response type"}
    rows = data.get("statsByBreakdownValue")
    if not isinstance(rows, list):
        return {"isSafeLinksEnabled": False, "reason": "messages-protected report returned no breakdown"}
    url = find_breakdown(rows, "url")
    if not url:
        return {"isSafeLinksEnabled": False, "reason": "No url breakdown present in messages-protected report"}
    total = url.get("breakdownMessagesTotal") or 0
    non_rewritten = url.get("messagesWithNonRewrittenUrls") or 0
    permitted_clicks = url.get("messagesWithPermittedClicks") or 0
    if total <= 0:
        return {"isSafeLinksEnabled": False, "reason": "No URL-bearing messages observed in the window"}
    rewritten = total - non_rewritten
    rate = round((rewritten * 100.0) / total, 2)
    return {"isSafeLinksEnabled": rate >= 95.0,
            "urlMessagesTotal": total, "messagesWithRewrittenUrls": rewritten,
            "messagesWithNonRewrittenUrls": non_rewritten,
            "messagesWithPermittedClicks": permitted_clicks,
            "urlRewriteRatePct": rate}


def transform(input):
    key = "isSafeLinksEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        res = evaluate(data)
        value = res.get(key, False)
        extra = {k: v for k, v in res.items() if k != key and k != "reason"}
        if value:
            pr = [f"URL Defense rewrote {extra.get('messagesWithRewrittenUrls')} of {extra.get('urlMessagesTotal')} URL-bearing messages ({extra.get('urlRewriteRatePct')}%), with {extra.get('messagesWithPermittedClicks')} permitted clicks"]
            fr = []
        else:
            pr = []
            fr = [res.get("reason", f"URL rewrite rate {extra.get('urlRewriteRatePct')}% is below the 95% threshold")]
        return create_response({key: value, **extra}, validation, pr, fr,
                               [] if value else ["Enable URL Defense rewriting for all inbound mail flows"],
                               {key: value, **extra})
    except Exception as e:
        return create_response({key: False}, None, [], ["Transformation error"], [], {}, [str(e)])
