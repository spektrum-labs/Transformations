"""
Transformation: confirmedLicensePurchased (from endpoint product assignments)
Vendor: Sophos Central - MDR
Category: Licensing
Method: getEndpoints (GET /endpoint/v1/endpoints)

Confirms an active Sophos MDR licence from evidence in the tenant, not from whether a
response arrived. MDR here is the managed service only, counted the same way as mdr_transform.py
and epp_transform.py in this folder: the "mtr" product (Managed Threat Response) or an explicit
mdrManaged true. The "xdr" product is the self-service XDR licence, not a managed service, so a
tenant with only the XDR licence has no MDR licence. The licence is confirmed when at least one
endpoint carries that evidence.

A read that proves nothing is Not evaluated (None with a data-collection error), never False:
an error, refusal or HTTP 4xx/5xx body (also when the status sits beside a response/result
wrapper, at any level), a failed input validation, an empty, null or unreadable body, an empty endpoint list,
a list with no endpoint record, and an exception. So is a partial
read (pages left unread) that shows no MDR endpoint: the licence may sit on an endpoint nobody
has seen. False is only the answer to a complete, readable endpoint list in which no endpoint
carries the MDR product.
"""

import json
from datetime import datetime


# The reason text is fixed: the vendor's own error text is never copied into the result.
STATUS_KEYS = ["status_code", "statusCode", "httpStatus", "status"]
ERROR_REASON = "Not evaluated: Sophos returned an error instead of an endpoint list; nothing was measured."
NO_ENDPOINTS_REASON = "Not evaluated: no endpoints returned"
NO_LIST_REASON = "Not evaluated: no endpoint list in the response; nothing was measured."
PARTIAL_REASON = (
    "Not evaluated: the endpoint list is only part of the fleet (it has further pages that were not read, "
    "or it starts after the first page) and no MDR endpoint is in the part that was read, so a missing "
    "licence cannot be confirmed; nothing was measured."
)
VALIDATION_REASON = "Not evaluated: the response failed input validation; nothing was measured."
EXCEPTION_REASON = "Not evaluated: the transformation could not read the response; nothing was measured."
RECOMMENDATION = "Check that the Sophos Central credential can read endpoints"
WRAPPER_KEYS = ["api_response", "response", "result", "apiResponse", "Output"]


def error_reason(body):
    """A fixed-text reason when a dict is an error or refusal body, else None."""
    if not isinstance(body, dict):
        return None
    if body.get("error") or body.get("errors") or body.get("vendorErrorAsResponse"):
        return ERROR_REASON
    for name in STATUS_KEYS:
        code = body.get(name)
        if isinstance(code, str) and code.strip().isdecimal():
            code = int(code.strip())
        if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
            return "Not evaluated: Sophos answered the endpoint read with HTTP " + str(code) + "; nothing was measured."
    return None


def wrapper_error(body):
    """A fixed-text reason when the body as received, or any level of a response/result wrapper chain, is an error body.

    The transform unwraps up to three wrapper levels before it reads the endpoint list; an error status or error body
    that sits beside a wrapper is dropped with that level, so every level is checked on the way down.
    """
    current = body
    for attempt in range(4):
        reason = error_reason(current)
        if reason is not None:
            return reason
        if not isinstance(current, dict):
            return None
        inner = None
        for key in WRAPPER_KEYS:
            if key in current and isinstance(current.get(key), (dict, list)):
                inner = current[key]
                break
        if inner is None:
            return None
        current = inner
    return None


def list_problem(items):
    """Why a list of endpoint records proves nothing, or None when it holds at least one record."""
    if len(items) == 0:
        return NO_ENDPOINTS_REASON
    has_record = False
    for entry in items:
        if isinstance(entry, dict):
            if entry.get("error") or entry.get("errors"):
                return ERROR_REASON
            has_record = True
    if not has_record:
        return NO_LIST_REASON
    return None


def read_problem(data, items):
    """Why a body is not a readable endpoint list (fixed text), or None when it is one.

    items is the endpoint list found in the body (None when there is none). A readable list of
    endpoints, even one with no MDR endpoint, is a read that can prove a negative; whether it is
    complete is a separate question (see unread_pages).
    """
    if isinstance(data, dict):
        reason = error_reason(data)
        if reason is not None:
            return reason
    if items is None:
        return NO_LIST_REASON
    return list_problem(items)


def page_cursor(value):
    """A pagination cursor, or None. Stored replays stringify null as "None" or "null"."""
    if value is None or value is False:
        return None
    text = str(value).strip()
    if text.lower() in ("", "none", "null", "false"):
        return None
    return text


def page_int(value):
    """A whole-number page field, or None. Stored replays stringify numbers: 4, 4.0, "4" and "4.0" are all 4."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        number = float(str(value).strip())
        if number != number or number in (float("inf"), float("-inf")):
            return None
        whole = int(number)
        if whole != number:
            return None
        return whole
    except Exception:
        return None


def page_field_unreadable(value):
    """True when a page total or item total is present but is not a whole number (null, an empty string and the stringified nulls are absent)."""
    if value is None:
        return False
    if isinstance(value, str) and value.strip().lower() in ("", "none", "null"):
        return False
    return page_int(value) is None


def marked_true(value):
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


def unread_pages(data, item_count):
    """PARTIAL_REASON when the endpoint list may be only part of the fleet, else None.

    Same rules as the Sophos coverage transforms in this folder (mdr_transform.py, epp_transform.py).
    A next-page cursor still set, a truncation marker, more items than were returned, more pages
    than one page of endpoints, or a page that does not start at the beginning (fromKey set) all
    mean part of the fleet was not read. More than one page (pages.total above 1) is partial unless
    pages.items says how many items the whole list holds and that is exactly the number returned. A
    page total or item total that is present but not a whole number shows nothing either, so it is
    partial too; 4.0 and "4.0" are read as 4. A pages field that is present but not an object, and a
    next key at the top of the body, are partial too. A full first page with no cursor is not treated
    as partial: a complete read of a large fleet looks the same.
    """
    if marked_true(data.get("truncated")):
        return PARTIAL_REASON
    if page_cursor(data.get("nextKey")) is not None:
        return PARTIAL_REASON
    pages = data.get("pages")
    if not isinstance(pages, dict):
        # An absent pages field (null, an empty string, a stringified null) says nothing and is complete; a pages
        # field that is present but is not an object (text, a number, a list) cannot be read, so the list may be only part.
        if page_cursor(pages) is None:
            return None
        return PARTIAL_REASON
    if marked_true(pages.get("truncated")):
        return PARTIAL_REASON
    if page_cursor(pages.get("nextKey")) is not None:
        return PARTIAL_REASON
    if page_cursor(pages.get("fromKey")) is not None:
        return PARTIAL_REASON
    if page_field_unreadable(pages.get("items")) or page_field_unreadable(pages.get("total")):
        return PARTIAL_REASON
    total_items = page_int(pages.get("items"))
    if total_items is not None and total_items > item_count:
        return PARTIAL_REASON
    total_pages = page_int(pages.get("total"))
    if total_pages is not None and total_pages > 1 and total_items != item_count:
        return PARTIAL_REASON
    return None


def transform(input):
    criteriaKey = "confirmedLicensePurchased"
    # The managed-service product code only ("mtr", Managed Threat Response), as in mdr_transform.py and
    # epp_transform.py. The "xdr" product is the self-service XDR licence, never MDR evidence.
    managed_product_code = "mtr"

    def extract_input(input_data):
        if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
            return input_data["data"], input_data["validation"]
        data = input_data
        if isinstance(data, dict):
            wrapper_keys = WRAPPER_KEYS
            for attempt in range(3):
                unwrapped = False
                for key in wrapper_keys:
                    if key in data and isinstance(data.get(key), (dict, list)):
                        data = data[key]
                        unwrapped = True
                        break
                if not unwrapped or not isinstance(data, dict):
                    break
        return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}

    def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                        recommendations=None, input_summary=None, transformation_errors=None,
                        api_errors=None, additional_findings=None):
        if validation is None:
            validation = {"status": "unknown", "errors": [], "warnings": []}
        return {
            "transformedResponse": result,
            "additionalInfo": {
                "dataCollection": {
                    "status": "error" if (api_errors or []) else "success",
                    "errors": api_errors or []
                },
                "validation": {
                    "status": validation.get("status", "unknown"),
                    "errors": validation.get("errors", []),
                    "warnings": validation.get("warnings", [])
                },
                "transformation": {
                    "status": "error" if (transformation_errors or []) else "success",
                    "errors": transformation_errors or [],
                    "inputSummary": input_summary or {}
                },
                "evaluation": {
                    "passReasons": pass_reasons or [],
                    "failReasons": fail_reasons or [],
                    "recommendations": recommendations or [],
                    "additionalFindings": additional_findings or []
                },
                "metadata": {
                    "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                    "schemaVersion": "1.0",
                    "transformationId": "confirmedLicensePurchased",
                    "vendor": "Sophos Central",
                    "category": "Licensing"
                }
            }
        }

    def not_evaluated(validation, reason, input_summary=None):
        # None plus a data-collection error: the evaluator records the criterion as Not evaluated.
        return create_response(
            result={criteriaKey: None},
            validation=validation,
            fail_reasons=[reason],
            api_errors=[reason],
            recommendations=[RECOMMENDATION],
            input_summary=input_summary
        )

    def endpoint_items(data):
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in ("items", "endpoints", "data"):
                value = data.get(key)
                if isinstance(value, list):
                    return value
        return None

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return not_evaluated(validation, VALIDATION_REASON)

        # An error status or error body that sits beside a wrapper (response, result, ...) is dropped when the
        # wrapper is unwrapped, so the body as received and every wrapper level are checked.
        outer = wrapper_error(input)
        if outer is not None:
            return not_evaluated(validation, outer)

        items = endpoint_items(data)
        problem = read_problem(data, items)
        if problem is not None:
            summary = None
            if problem == NO_ENDPOINTS_REASON:
                summary = {"totalEndpoints": 0, "mdrEndpoints": 0}
            return not_evaluated(validation, problem, summary)

        mdr_endpoints = 0
        codes_seen = []
        for endpoint in items:
            if not isinstance(endpoint, dict):
                continue
            codes = [p.get("code") for p in (endpoint.get("assignedProducts") or []) if isinstance(p, dict)]
            for code in codes:
                if code and code not in codes_seen:
                    codes_seen.append(code)
            managed = str(endpoint.get("mdrManaged")).strip().lower() == "true"
            if managed_product_code in codes or managed:
                mdr_endpoints = mdr_endpoints + 1

        licensed = mdr_endpoints > 0
        summary = {"totalEndpoints": len(items), "mdrEndpoints": mdr_endpoints, "productCodes": sorted(codes_seen)}

        if licensed:
            return create_response(
                result={criteriaKey: True},
                validation=validation,
                pass_reasons=[f"Sophos MDR licence confirmed: {mdr_endpoints} of {len(items)} endpoints carry the managed MDR product (mtr) or are MDR-managed"],
                input_summary=summary
            )

        # No MDR endpoint in what was read. That is a negative only when everything was read.
        if isinstance(data, dict):
            partial = unread_pages(data, len(items))
            if partial is not None:
                return not_evaluated(validation, partial, summary)

        return create_response(
            result={criteriaKey: False},
            validation=validation,
            fail_reasons=[f"None of the {len(items)} endpoints carry the Sophos managed MDR product (mtr) or are MDR-managed"],
            recommendations=["Confirm the Sophos MDR subscription is active and assigned to endpoints"],
            input_summary=summary
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[EXCEPTION_REASON],
            api_errors=[EXCEPTION_REASON]
        )
