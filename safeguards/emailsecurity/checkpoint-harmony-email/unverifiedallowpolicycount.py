"""
Transformation: unverifiedAllowPolicyCount
Vendor: Check Point Harmony Email & Collaboration (Infinity Portal API)
Method: getAntiPhishingAllowList (GET /app/hec-api/v1.0/exceptions/whitelist)

Count of anti-phishing allow-list (whitelist) exceptions. The API has no review field, so every entry counts. Unreadable input returns None, which fails the check.
Fails closed: an empty, error or unrecognised body proves nothing.
A partial page (a non-empty responseEnvelope.scrollId, or a recordsNumber above the page) is never
counted as the whole list: the count is the vendor's own recordsNumber when that total is larger than
the page, and None (Not evaluated) when it is not, since the page length is only a lower bound.
An entry that is not an object cannot be read and is never skipped: the count is None.
"""

import json
from datetime import datetime

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('unverifiedAllowPolicyCount',)


def criteria_unmeasured(result):
    """True when every criterion this file answers that the result carries is None.

    Token-Service grades a None criterion as FAILED unless additionalInfo.dataCollection.status
    is "error". The status is read per response, so it is set only when no criterion in the
    result was measured; marking a partly measured result would hide the measured ones.
    """
    present = [k for k in NONE_MEANS_NOT_EVALUATED if k in result]
    return len(present) > 0 and all(result[k] is None for k in present)


def transform_unmarked(input):
    criteriaKey = "unverifiedAllowPolicyCount"

    def create_response(value, pass_reasons=None, fail_reasons=None, input_summary=None,
                        api_errors=None, transformation_errors=None):
        return {
            "transformedResponse": {criteriaKey: value},
            "additionalInfo": {
                "dataCollection": {"status": "error" if api_errors else "success",
                                   "errors": api_errors or []},
                "validation": {"status": "unknown", "errors": [], "warnings": []},
                "transformation": {"status": "error" if transformation_errors else "success",
                                   "errors": transformation_errors or [],
                                   "inputSummary": input_summary or {}},
                "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                               "recommendations": [], "additionalFindings": []},
                "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z",
                             "schemaVersion": "1.0", "transformationId": criteriaKey,
                             "vendor": "Check Point Harmony Email & Collaboration",
                             "method": "getAntiPhishingAllowList"},
            },
        }

    def http_status(value):
        """An HTTP status as a number: a number, or text such as "401" or " 403 ". Booleans, blank
        or non-numeric text and any other type are None, which is not an error."""
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            return value
        if isinstance(value, str):
            digits = value.strip()
            if digits.isascii() and digits.isdigit():
                return int(digits)
        return None

    def marker_error(obj):
        """Fixed reason when this one object says the call failed (error, errors, or an HTTP
        status of 400 or more in status, statusCode or status_code), else None. The vendor's own
        response text is never copied into the reason."""
        if obj.get("error") or obj.get("errors"):
            return "Harmony Email & Collaboration answered with an error; nothing is measured."
        for field in ("status", "statusCode", "status_code"):
            code = http_status(obj.get(field))
            if code is not None and code >= 400:
                return "Harmony Email & Collaboration answered with an HTTP error; nothing is measured."
        return None

    def hec_body(data):
        """The HEC API answers {"responseEnvelope": {...}, "responseData": [...]}. Unwrap
        Integration-Service wrappers until that shape is found. Returns (body, error): body is
        None when the shape is not found; error is a fixed reason when a wrapper around the body
        carries an error marker, in which case nothing inside it is trusted."""
        for attempt in range(4):
            if isinstance(data, str):
                try:
                    data = json.loads(data)
                except Exception:
                    return None, None
            if not isinstance(data, dict):
                return None, None
            if isinstance(data.get("responseData"), list):
                return data, None
            err = marker_error(data)
            if err:
                return None, err
            nxt = None
            for key in ("apiResponse", "response", "result", "data", "rawResponse"):
                if isinstance(data.get(key), (dict, str)):
                    nxt = data[key]
                    break
            if nxt is None:
                return None, None
            data = nxt
        return None, None

    def envelope_error(body):
        """Fixed reason when the response body says the call failed, else None."""
        env = body.get("responseEnvelope")
        if isinstance(env, dict):
            code = env.get("responseCode")
            if code is not None and str(code) not in ("200", "0"):
                return "Harmony Email & Collaboration answered with an error status; nothing is measured."
        return marker_error(body)

    def records_total(body):
        """The vendor's recordsNumber as a whole number, else None. None also covers a total that is
        stated but cannot be read (see total_unreadable)."""
        env = body.get("responseEnvelope")
        value = env.get("recordsNumber") if isinstance(env, dict) else None
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value if value >= 0 else None
        if isinstance(value, str):
            digits = value.strip()
            if digits.isdecimal():
                return int(digits)
        return None

    def total_unreadable(body):
        """True when the vendor states a recordsNumber that cannot be read as a whole number, so
        whether the page is complete is unknown. A missing, null or blank total states nothing."""
        env = body.get("responseEnvelope")
        value = env.get("recordsNumber") if isinstance(env, dict) else None
        if value is None or (isinstance(value, str) and value.strip().lower() in ("", "none", "null")):
            return False
        return records_total(body) is None

    def more_pages(body):
        """"more" when the response says records remain beyond this page: a scrollId that is not
        empty (the stored raw form writes null as "None"), or a recordsNumber larger than the page.
        "unknown" when it states a recordsNumber that cannot be read, so nobody knows whether the page
        is complete. "" when the page is complete. Anything but "" cannot prove a total."""
        env = body.get("responseEnvelope")
        for holder in (env if isinstance(env, dict) else {}, body):
            token = holder.get("scrollId")
            if token and str(token).strip().lower() not in ("", "none", "null"):
                return "more"
        total = records_total(body)
        if total is not None and total > len(body["responseData"]):
            return "more"
        if total_unreadable(body):
            return "unknown"
        return ""

    try:
        if isinstance(input, bytes):
            input = input.decode("utf-8")
        body, err = hec_body(input)
        if err:
            return create_response(None, fail_reasons=[err], api_errors=[err])
        if body is None:
            return create_response(None, fail_reasons=["No Harmony Email & Collaboration response "
                                   "(responseData) in the input; nothing is proven"],
                                   api_errors=["Unrecognised or error response"])
        err = envelope_error(body)
        if err:
            return create_response(None, fail_reasons=[err], api_errors=[err])
        records = body["responseData"]
        entries = [r for r in records if isinstance(r, dict)]
        summary = {"allowListEntries": len(entries)}
        unreadable = len(records) - len(entries)
        if unreadable:
            # an entry that cannot be read may be an allow-list exception: the count is not proven
            reason = (str(unreadable) + (" entry" if unreadable == 1 else " entries") +
                      " in the response could not be read, so the allow-list count is not proven")
            return create_response(None, fail_reasons=[reason], api_errors=[reason],
                                   input_summary=dict(summary, unreadableEntries=unreadable))
        count = len(entries)
        partial = more_pages(body)
        if partial == "unknown":
            # the vendor states a total that cannot be read: nobody knows whether this page is complete
            reason = ("The vendor's record total could not be read, so whether the page is complete is unknown "
                      "and the allow-list count is not proven")
            return create_response(None, fail_reasons=[reason], api_errors=[reason],
                                   input_summary=dict(summary, recordsNumberUnreadable=True))
        if partial:
            # One page of several. Only a total the vendor states, larger than the page, is a count;
            # the page length is a lower bound and is never reported as the total.
            total = records_total(body)
            if total is None or total <= len(records):
                return create_response(None, fail_reasons=["The response is a partial page and states no total "
                                       "larger than the page, so the allow-list count is not proven"],
                                       api_errors=["Partial page: the allow-list count is not proven"],
                                       input_summary=dict(summary, partialPage=True))
            count = total
            summary["recordsNumber"] = total
        if count:
            return create_response(count, fail_reasons=[str(count) + " anti-phishing allow-list "
                                   "(whitelist) exception(s) bypass inspection; the API carries no review or "
                                   "verification field, so each one counts as unverified"], input_summary=summary)
        return create_response(0, pass_reasons=["No anti-phishing allow-list (whitelist) exception is configured"],
                               input_summary=summary)
    except Exception as e:
        return create_response(None, fail_reasons=["Transformation error"],
                               transformation_errors=[str(e)])


def transform(input):
    """transform_unmarked(), with a None criterion reported as not evaluated.

    Token-Service grades a None criterion as FAILED unless additionalInfo.dataCollection.status
    is "error". This file's responses do not set that status, so it is set here, carrying the
    file's own reason for the None.
    """
    out = transform_unmarked(input)
    if not isinstance(out, dict):
        return out
    inner = out.get("transformedResponse", out)
    if not isinstance(inner, dict) or not criteria_unmeasured(inner):
        return out
    info = out.get("additionalInfo")
    info = info if isinstance(info, dict) else {}
    collection = info.get("dataCollection")
    if isinstance(collection, dict) and str(collection.get("status") or "").lower() == "error":
        return out
    evaluation = info.get("evaluation")
    reasons = evaluation.get("failReasons") if isinstance(evaluation, dict) else None
    why = [str(r) for r in reasons if r] if isinstance(reasons, list) else []
    for k in ("reason", "error", "unevaluated"):
        if out.get(k) and str(out.get(k)) not in why:
            why = why + [str(out.get(k))]
    errors = collection.get("errors") if isinstance(collection, dict) else None
    why = why + [str(e) for e in errors if e] if isinstance(errors, list) else why
    marked = dict(collection if isinstance(collection, dict) else {}, status="error",
                  errors=why or ["The response could not answer this check, so it was not evaluated."])
    return dict(out, additionalInfo=dict(info, dataCollection=marked))
