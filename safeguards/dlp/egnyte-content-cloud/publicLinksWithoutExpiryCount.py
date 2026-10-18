"""
Transformation: publicLinksWithoutExpiryCount
Vendor: Egnyte Content Cloud  |  Category: Data Security
Source: GET /pubapi/v2/links
Value: the number of live share links reachable without an account (accessibility
'anyone' or 'password') that carry neither an expiry date nor a click limit. Such a link
keeps working until someone deletes it. The criterion asks for 0.
Not measured (null): anything that is not the links response (empty body, error or auth
envelope, unrelated JSON), a link whose accessibility is unreadable, or a read that does
not cover every link.
"""
import json
from datetime import datetime

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('publicLinksWithoutExpiryCount',)


def criteria_unmeasured(result):
    """True when every criterion this file answers that the result carries is None.

    Token-Service grades a None criterion as FAILED unless additionalInfo.dataCollection.status
    is "error". The status is read per response, so it is set only when no criterion in the
    result was measured; marking a partly measured result would hide the measured ones.
    """
    present = [k for k in NONE_MEANS_NOT_EVALUATED if k in result]
    return len(present) > 0 and all(result[k] is None for k in present)


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Create the standardized 5-section transformation response."""
    # A None criterion was not measured. Token-Service grades None as FAILED unless
    # dataCollection.status is "error", which needs a non-empty api_errors, so carry the
    # reason across when the caller did not.
    if not api_errors and isinstance(result, dict) and criteria_unmeasured(result):
        api_errors = (list(fail_reasons or []) or list(transformation_errors or [])
                      or ["The response could not answer this check, so it was not evaluated."])
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
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


UNAUTHENTICATED = ("anyone", "password")
FULL_PAGE_SIZES = (100, 500)


def links_truncated(data, links):
    """True when the body cannot show it holds every link.

    A total (total_count on v1, or any total the collector adds) larger than the rows
    read is a partial read. GET /pubapi/v2/links carries no total: its count is the
    number of links in this response, at most 500 per call. A response whose count
    equals its rows and is exactly a full page (100 or 500) may have more behind it.
    """
    for key in ("total_count", "totalResults", "total"):
        total = data.get(key)
        if isinstance(total, int) and not isinstance(total, bool):
            return total > len(links)
    count = data.get("count")
    return (isinstance(count, int) and not isinstance(count, bool)
            and count == len(links) and len(links) in FULL_PAGE_SIZES)


def has_expiry(link):
    date = link.get("expiry_date")
    if isinstance(date, str) and date.strip():
        return True
    clicks = link.get("expiry_clicks")
    return isinstance(clicks, int) and not isinstance(clicks, bool)


def evaluate(data):
    links = data.get("links") if isinstance(data, dict) else None
    count = data.get("count") if isinstance(data, dict) else None
    result = {"publicLinksWithoutExpiryCount": None}
    # Only the links response is evidence: a links array together with its numeric count.
    # An empty body, a 401 or 403 envelope and an unrelated body all lack one or the other.
    if not isinstance(links, list) or not isinstance(count, int) or isinstance(count, bool):
        return result, [], [
            "The response is not the Egnyte links list (no links array with a count), so "
            "it is indistinguishable from an authentication failure or an unrelated body. "
            "Links without expiry are not measured."
        ], [
            "Confirm the OAuth token carries the Egnyte.link scope and that GET "
            "/pubapi/v2/links returns links and count for this domain."
        ], {"linksReturned": None}
    records = [link for link in links if isinstance(link, dict)]
    unreadable = [l.get("id") or l.get("path") or "unnamed" for l in records if not l.get("accessibility")]
    if len(records) != len(links) or unreadable:
        return result, [], [
            "%d link(s) could not be classified (not an object, or no accessibility), so "
            "the count would be a guess. Not measured." % (len(links) - len(records) + len(unreadable))
        ], [], {"linksReturned": len(links)}
    if links_truncated(data, links):
        return result, [], [
            "%d links were read and the response does not show that this is every link in "
            "the domain. Links without expiry are not measured on a partial read." % len(links)
        ], ["Page through offset so every link is read."], {"linksReturned": len(links)}
    open_links = [l for l in records if str(l.get("accessibility")).lower() in UNAUTHENTICATED]
    no_expiry = [
        {"path": l.get("path") or l.get("id") or "unnamed", "accessibility": l.get("accessibility"),
         "createdBy": l.get("created_by"), "createdOn": l.get("creation_date")}
        for l in open_links if not has_expiry(l)
    ]
    result = {
        "publicLinksWithoutExpiryCount": len(no_expiry),
        "linksEvaluated": len(records),
        "unauthenticatedLinkCount": len(open_links),
        "publicLinksWithoutExpiry": no_expiry[:25],
    }
    passes, fails, recs = [], [], []
    if not no_expiry:
        passes.append(
            "None of the %d link(s) open to anyone or protected only by a password lacks an "
            "expiry (%d link(s) read)." % (len(open_links), len(records))
        )
    else:
        fails.append(
            "%d of %d link(s) open to anyone or protected only by a password have neither an "
            "expiry date nor a click limit, so they stay usable until deleted."
            % (len(no_expiry), len(open_links))
        )
        recs.append(
            "Set an expiry date or click limit on the listed links, or delete them, and set a "
            "default link expiration in the domain's link settings."
        )
    return result, passes, fails, recs, {"linksReturned": len(links)}


def transform(input):
    data, validation = extract_input(input)
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except ValueError:
            data = None
    data = data if isinstance(data, dict) else {}
    result, pass_reasons, fail_reasons, recommendations, input_summary = evaluate(data)
    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "publicLinksWithoutExpiryCount",
            "vendor": "Egnyte",
            "category": "Data Security",
        },
    )
