"""Transformation: expiredButActiveCardCount - acre Access Control (Physical Security), GET /api/f/{instanceKey}/people.

Counts enabled card assignments (IsDisabled not true) whose ExpiresOn is a real date in the past. A card that has expired
but is still enabled is a credential that outlived its holder's need for it. A never-expires value (no date, or a sentinel
more than 25 years out) is not expired. The count is measured only on a complete read of the people list that holds at
least one enabled card. The count is reported only when every ExpiresOn was readable, else the answer is not measured
(None): a count beside an unreadable date is only a lower bound.
"""
import json
import re
from datetime import datetime, timezone, timedelta

VENDOR = "Acre Security"
WRAPPERS = ["result", "response", "apiResponse", "api_response", "Output", "data", "_response_data"]


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


def not_measured(key, problem, validation):
    return create_response(
        result={key: None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": key, "vendor": VENDOR, "category": "Physical Security"},
    )


def error_in(cur):
    """A short error string when a vendor/IS error body is in hand, else None."""
    if cur.get("errors") or cur.get("error") is True or isinstance(cur.get("error"), (str, dict)):
        detail = cur.get("errors") or cur.get("error") or cur.get("Message") or cur.get("message") or "error"
        return json.dumps(detail)[:300]
    code = cur.get("status_code") or cur.get("statusCode")
    if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
        return "HTTP " + str(code) + ": " + json.dumps(cur.get("message") or cur.get("detail") or "")[:200]
    return None


def find_people(input):
    """(people, problem, truncated): the list of PersonInfo records, through any wrapper, or why there is none.

    `truncated` is True when Integration-Service marked the read partial (paginationTruncated / truncated).
    """
    cur = input.get("data") if isinstance(input, dict) and "validation" in input else input
    truncated = False
    for depth in range(8):
        if isinstance(cur, str):
            try:
                cur = json.loads(cur)
            except Exception:
                return None, None, truncated
        if isinstance(cur, list):
            return cur, None, truncated
        if not isinstance(cur, dict):
            return None, None, truncated
        if cur.get("paginationTruncated") is True or cur.get("truncated") is True:
            truncated = True
        for name in ("people", "persons"):
            if isinstance(cur.get(name), list):
                return cur[name], None, truncated
        problem = error_in(cur)
        if problem is not None:
            return None, problem, truncated
        nxt = None
        for wrapper in WRAPPERS:
            if isinstance(cur.get(wrapper), (dict, list, str)):
                nxt = cur.get(wrapper)
                break
        if nxt is None:
            return None, None, truncated
        cur = nxt
    return None, None, truncated


def field_value(record, *names):
    """Field casing varies between the REST payload and the BSON projection."""
    for n in names:
        if n in record:
            return record[n]
        alt = n[0].lower() + n[1:]
        if alt in record:
            return record[alt]
    return None


def has_field(record, name):
    return name in record or (name[0].lower() + name[1:]) in record


def enabled_cards(input):
    """(cards, people_count, problem): every enabled card assignment of a complete people read, or why not."""
    people, problem, truncated = find_people(input)
    if problem is not None:
        return None, 0, "acre returned an error instead of the people list: " + problem
    if people is None:
        return None, 0, "No acre people list in the response; nothing to evaluate."
    records = [p for p in people if isinstance(p, dict)]
    if len(records) != len(people):
        return None, 0, "The people list holds entries that are not person records, so it cannot be scored."
    if truncated:
        return None, len(records), "Read stopped at the page limit (" + str(len(records)) + " people); a partial read is not scored."
    cards = []
    for p in records:
        assigned = field_value(p, "CardAssignments")
        if not isinstance(assigned, list):
            continue
        for card in assigned:
            if isinstance(card, dict) and field_value(card, "IsDisabled") is not True:
                cards.append(card)
    if not cards:
        return None, len(records), "acre returned no enabled card assignment, so there is nothing to count."
    return cards, len(records), None


def parse_dt(value):
    """Parse an ISO 8601 timestamp using fromisoformat only (strptime is blocked in the sandbox).

    .NET serialises DateTime with seven fractional digits and a trailing Z, so both are normalised first.
    Anything unparseable returns None.
    """
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    if len(text) > 10 and text[10] == " ":
        text = text[:10] + "T" + text[11:]
    if text.endswith("Z") or text.endswith("z"):
        text = text[:-1] + "+00:00"
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def utc_now():
    return datetime.now(timezone.utc)


def transform(input):
    key = "expiredButActiveCardCount"
    validation = extract_validation(input)
    cards, people_count, problem = enabled_cards(input)
    if problem is not None:
        return not_measured(key, problem, validation)
    now = utc_now()
    horizon = now + timedelta(days=365 * 25 + 6)
    expired = 0
    unreadable = 0
    for card in cards:
        raw = field_value(card, "ExpiresOn")
        if raw is None or raw == "":
            continue
        parsed = parse_dt(raw)
        if parsed is None:
            unreadable = unreadable + 1
        elif parsed.year <= 1 or parsed > horizon:
            continue
        elif parsed < now:
            expired = expired + 1
    if unreadable > 0:
        # a count beside unreadable dates is only a lower bound, and an inclusive lessThan would pass on it
        return not_measured(key, str(unreadable) + " enabled card(s) carry an ExpiresOn that cannot be read, so the count of expired cards (at least "
                            + str(expired) + ") cannot be shown exactly.", validation)
    text = (str(expired) + " of " + str(len(cards)) + " enabled card assignments have an expiry date in the past and are still enabled.")
    return create_response(
        result={key: expired, "enabledCardCount": len(cards), "peopleEvaluated": people_count, "cardsNotMeasured": unreadable},
        validation=validation,
        pass_reasons=[text] if expired == 0 else [],
        fail_reasons=[text] if expired else [],
        recommendations=["Disable the expired cards, or extend their expiry if the holder still needs access."] if expired else [],
        input_summary={"enabledCardCount": len(cards), "peopleEvaluated": people_count},
        metadata={"transformationId": key, "vendor": VENDOR, "category": "Physical Security"},
    )
