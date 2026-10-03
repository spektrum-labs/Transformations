"""Transformation: securityHealthCheckScore - Salesforce (Tooling API Security Health Check). Not measured (None) on any body that proves nothing."""
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


VENDOR = "Salesforce"


def not_measured(key, problem, validation):
    return create_response(
        result={key: None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": key, "vendor": VENDOR, "category": "partner"},
    )


def complete_records(input, sobject):
    """(records, None) for a complete Tooling API query result, else (None, problem).

    Complete means: Salesforce's query envelope (records + totalSize + done) with done true and
    every record present, each typed as `sobject` in attributes.type.
    """
    box, problem = find_key(raw_body(input), "records")
    if problem is not None:
        return None, "Salesforce returned an error instead of a query result: " + problem
    if box is None or not isinstance(box.get("records"), list):
        return None, "No Salesforce query result in the response; nothing to evaluate."
    total = box.get("totalSize")
    if isinstance(total, bool) or not isinstance(total, int) or box.get("done") is not True:
        return None, "The query result has no totalSize or is not done (more records remain); a partial read is not scored."
    records = [r for r in box["records"] if isinstance(r, dict)]
    if len(records) < total:
        return None, "Read " + str(len(records)) + " of " + str(total) + " records; a partial read is not scored."
    for r in records:
        attrs = r.get("attributes") if isinstance(r.get("attributes"), dict) else {}
        if attrs.get("type") not in (None, sobject):
            return None, "The query returned " + str(attrs.get("type")) + " records, not " + sobject + "."
    return records, None


def transform(input):
    key = "securityHealthCheckScore"
    validation = extract_validation(input)
    records, problem = complete_records(input, "SecurityHealthCheck")
    if problem is not None:
        return not_measured(key, problem, validation)
    if len(records) != 1:
        return not_measured(key, "Expected one SecurityHealthCheck record, got " + str(len(records)) + ".", validation)
    raw = records[0].get("Score")
    score = None
    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        score = float(raw)
    elif isinstance(raw, str):
        try:
            score = float(raw.strip())
        except Exception:
            score = None
    if score is None or score < 0 or score > 100:
        return not_measured(key, "The SecurityHealthCheck record carries no Score between 0 and 100.", validation)
    text = "Salesforce Health Check score is " + str(score) + " of 100 against the Salesforce baseline standard."
    return create_response(
        result={key: score},
        validation=validation,
        pass_reasons=[text] if score >= 80 else [],
        fail_reasons=[] if score >= 80 else [text],
        recommendations=[] if score >= 80 else ["Fix the high-risk settings listed in Setup > Health Check."],
        input_summary={"score": score},
        metadata={"transformationId": key, "vendor": VENDOR, "category": "partner"},
    )
