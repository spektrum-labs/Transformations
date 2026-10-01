"""Transformation: staleSensorCount - Symantec Endpoint Protection (SEPM REST API v1 /computers). Not measured (None) on any body that proves nothing."""
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


VENDOR = "Symantec Endpoint Protection"
STALE_DAYS = 15


def not_measured(key, problem, validation):
    return create_response(
        result={key: None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": key, "vendor": VENDOR, "category": "epp"},
    )


def complete_clients(input):
    """(clients, None) for a complete SEPM /computers read, else (None, problem).

    Complete means: SEPM's `content` array with a numeric `totalElements`, and at least that many
    clients read (Integration-Service merges every pageIndex page into `content`).
    """
    box, problem = find_key(raw_body(input), "content")
    if problem is not None:
        return None, "SEPM returned an error instead of a client list: " + problem
    if box is None or not isinstance(box.get("content"), list):
        return None, "No SEPM client list in the response; nothing to evaluate."
    total = box.get("totalElements")
    if isinstance(total, bool) or not isinstance(total, int) or total < 0:
        return None, "The client list carries no totalElements, so a complete read cannot be shown."
    clients = [c for c in box["content"] if isinstance(c, dict)]
    if len(clients) < total:
        return None, "Read " + str(len(clients)) + " of " + str(total) + " SEPM clients; a partial read is not scored."
    return clients, None


def epoch_ms(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, str) and value.strip().isdigit():
        value = int(value.strip())
    if isinstance(value, (int, float)) and value > 0:
        return value
    return None


def client_windows(clients):
    """(fresh, stale) clients: fresh = lastUpdateTime within STALE_DAYS of the newest one in the read."""
    stamps = [(c, epoch_ms(c.get("lastUpdateTime"))) for c in clients]
    known = [t for c, t in stamps if t is not None]
    if not known:
        return [], list(clients)
    newest = max(known)
    window = STALE_DAYS * 86400000
    fresh = [c for c, t in stamps if t is not None and newest - t <= window]
    stale = [c for c, t in stamps if t is None or newest - t > window]
    return fresh, stale


def flag(value):
    """SEPM on/off fields are numeric (1 = on); some proxies hand them over as strings."""
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return value if isinstance(value, int) else None


def transform(input):
    key = "staleSensorCount"
    validation = extract_validation(input)
    clients, problem = complete_clients(input)
    if problem is not None:
        return not_measured(key, problem, validation)
    fresh, stale = client_windows(clients)
    count = len(stale)
    text = (str(count) + " of " + str(len(clients)) + " SEP clients have not checked in within " + str(STALE_DAYS)
            + " days of the newest check-in (or never reported a check-in time).")
    return create_response(
        result={key: count, "totalClients": len(clients), "activeClients": len(fresh)},
        validation=validation,
        pass_reasons=[text] if count == 0 else [],
        fail_reasons=[text] if count else [],
        recommendations=["Reconnect or retire SEP clients that stopped checking in."] if count else [],
        input_summary={"totalClients": len(clients), "staleClients": count},
        metadata={"transformationId": key, "vendor": VENDOR, "category": "epp"},
    )
