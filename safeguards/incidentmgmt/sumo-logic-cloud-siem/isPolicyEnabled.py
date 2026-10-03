"""Transformation: isPolicyEnabled - Sumo Logic Cloud SIEM, method getEnabledRules.

getEnabledRules is GET /api/sec/v1/rules?q=enabled:true&limit=1. Its data.total is the exact number of
enabled Cloud SIEM detection rules. True when that count is at least 1, False when Cloud SIEM answers
with a real zero. None when the body is an error, an auth envelope, unrelated JSON, or when the server
did not apply the enabled filter (a returned rule with enabled != true).
"""
import json
from datetime import datetime


KEY = "isPolicyEnabled"


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


def raw_body(input):
    # input.get("data") makes Token-Service pass the undrilled response in a {data, validation}
    # envelope, so the Cloud SIEM {total, objects} block stays visible.
    if isinstance(input, dict) and "validation" in input:
        return input.get("data")
    return input


def find_page(obj):
    """(page, error) where page is Cloud SIEM's {total, objects} list block."""
    cur = obj
    for depth in range(6):
        if isinstance(cur, str):
            try:
                cur = json.loads(cur)
            except Exception:
                return None, None
        if not isinstance(cur, dict):
            return None, None
        if isinstance(cur.get("objects"), list) and "total" in cur:
            return cur, None
        errors = cur.get("errors")
        if (isinstance(errors, list) and errors) or cur.get("error") is True:
            detail = errors or cur.get("message") or cur.get("errorMessage") or "error"
            return None, json.dumps(detail)[:300]
        nxt = None
        for key in ["data", "apiResponse", "result", "response", "api_response", "Output"]:
            if isinstance(cur.get(key), (dict, str)):
                nxt = cur.get(key)
                break
        if nxt is None:
            return None, None
        cur = nxt
    return None, None


def not_measured(problem, validation):
    return create_response(
        result={KEY: None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": KEY, "vendor": "Sumo Logic", "category": "Security Operations"},
    )


def transform(input):
    validation = extract_validation(input)
    page, error = find_page(raw_body(input))
    if error is not None:
        return not_measured("Cloud SIEM returned an error instead of a rule list: " + error, validation)
    if page is None:
        return not_measured("No Cloud SIEM rule list (data.total, data.objects) in the response; nothing to evaluate.", validation)
    total = page.get("total")
    if isinstance(total, bool) or not isinstance(total, int) or total < 0:
        return not_measured("The rule list carries no numeric data.total, so the enabled rule count is unknown.", validation)
    rules = [r for r in page.get("objects") if isinstance(r, dict)]
    if total > 0 and not rules:
        return not_measured("data.total is " + str(total) + " but no rule was returned; the read is inconsistent.", validation)
    for rule in rules:
        if rule.get("enabled") is not True:
            return not_measured("A returned rule is not enabled, so the enabled:true filter was not applied; "
                                "the total cannot be read as an enabled count.", validation)
    enabled = total > 0
    text = str(total) + " Cloud SIEM detection rule(s) are enabled."
    return create_response(
        result={KEY: enabled, "enabledRuleCount": total},
        validation=validation,
        pass_reasons=[text] if enabled else [],
        fail_reasons=[] if enabled else ["No Cloud SIEM detection rule is enabled."],
        recommendations=[] if enabled else ["Enable the Cloud SIEM detection rules that match your log sources."],
        input_summary={"enabledRuleCount": total, "rulesReturned": len(rules)},
        metadata={"transformationId": KEY, "vendor": "Sumo Logic", "category": "Security Operations"},
    )
