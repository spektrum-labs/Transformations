"""
Transformation: isPublicSharingRestricted
Vendor: Egnyte Content Cloud  |  Category: Data Security
Source: GET /pubapi/v2/links
Pass: no live share link is set to 'Anyone' accessibility. An Anyone link is an
unauthenticated URL to customer content that survives offboarding and is not tied to a
recipient.
"""
import json
import re
from datetime import datetime, timezone


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


def pick_list(data, *keys):
    """The collection may arrive at a named key, or as the whole payload."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for k in keys:
            value = data.get(k)
            if isinstance(value, list):
                return value
        for k in ("items", "value", "results", "resources"):
            value = data.get(k)
            if isinstance(value, list):
                return value
    return []


def pct(numerator, denominator):
    if not denominator:
        return None
    return round((numerator / denominator) * 100, 2)


def field_value(record, *names):
    """Field casing varies between the REST payload and the BSON projection."""
    for n in names:
        if n in record:
            return record[n]
        alt = n[0].lower() + n[1:]
        if alt in record:
            return record[alt]
    return None


def parse_dt(value):
    """Parse an ISO 8601 timestamp using fromisoformat only.

    strptime is unusable here: it imports _strptime inside CPython, which the
    transformation sandbox blocks, and the ImportError is not a ValueError, so it
    escapes a normal except and fails the whole check. .NET serialises DateTime
    with seven fractional digits and a trailing Z, which older fromisoformat
    rejects, so both are normalised first. Anything still unparseable returns
    None, and callers treat None as not measured.
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


OPEN = "anyone"
FULL_PAGE_SIZES = (100, 500)


def links_truncated(data, links):
    """True when the body cannot show it holds every link.

    A total (total_count on v1, or any total the collector adds) larger than the rows
    read is a partial read. GET /pubapi/v2/links carries no total: its count is the
    number of links in this response, at most 500 per call. A response whose count
    equals its rows and is exactly a full page (100 or 500) may have more behind it.
    """
    if not isinstance(data, dict):
        return False
    for key in ("total_count", "totalResults", "total"):
        total = data.get(key)
        if isinstance(total, int) and not isinstance(total, bool):
            return total > len(links)
    count = data.get("count")
    return (isinstance(count, int) and not isinstance(count, bool)
            and count == len(links) and len(links) in FULL_PAGE_SIZES)


def evaluate(data):
    links = pick_list(data, "links")
    count = data.get("count") if isinstance(data, dict) else None
    # An empty links array and a 401, a 403 or an unrelated body all look the same.
    # Only a payload that demonstrably came from the links endpoint - a numeric count,
    # or at least one link object - is evidence. Anything else is not measured.
    reached_endpoint = isinstance(count, int) or bool(links)
    public, domain, recipients, password, unreadable = [], [], [], [], []
    for link in links:
        if not isinstance(link, dict):
            continue
        label = link.get("path") or link.get("id") or "unnamed"
        access = str(link.get("accessibility") or "").lower()
        if not access:
            unreadable.append(label)
        elif access == OPEN:
            public.append({"path": label, "type": link.get("type"), "createdOn": link.get("creation_date")})
        elif access == "domain":
            domain.append(label)
        elif access == "password":
            password.append(label)
        else:
            recipients.append(label)
    measured = len(links) - len(unreadable)
    result = {
        "isPublicSharingRestricted": reached_endpoint and not public and (measured > 0 or count == 0),
        "endpointReached": reached_endpoint,
        "publicLinkCount": len(public),
        "linksEvaluated": measured,
        "restrictedLinkPercentage": pct(measured - len(public), measured),
        "publicLinks": public[:25],
        "domainRestrictedLinkCount": len(domain),
        "recipientRestrictedLinkCount": len(recipients),
        "passwordProtectedLinkCount": len(password),
        "linksNotMeasured": unreadable,
    }
    passes, fails, recs = [], [], []
    if not reached_endpoint:
        fails.append(
            "The response carries no link list and no link count, so it is indistinguishable "
            "from an authentication failure or an unrelated body. Public sharing is not "
            "measured, and absence of evidence is not treated as a pass."
        )
        recs.append(
            "Confirm the OAuth token carries the Egnyte.link scope and that GET "
            "/pubapi/v2/links returns a count field for this domain."
        )
    elif not links:
        passes.append(
            "The domain reported a link count of 0, so no share links exist and there is no "
            "public sharing surface."
        )
        result["isPublicSharingRestricted"] = True
    elif measured == 0:
        fails.append(
            "Links were returned but none reported an accessibility value, so public "
            "sharing could not be measured."
        )
    elif not public:
        passes.append(
            "All %d live share link(s) are restricted to a domain, named recipients or a "
            "password. None is open to anyone with the URL." % measured
        )
    else:
        fails.append(
            "%d of %d live share link(s) are set to 'Anyone', exposing content to any "
            "holder of the URL without authentication." % (len(public), measured)
        )
        recs.append(
            "Change the listed links to Domain, Recipients or Password accessibility, or "
            "expire them. Then restrict Anyone links in the domain link policy so they "
            "cannot be created again."
        )
    if isinstance(count, int) and count > len(links):
        recs.append(
            "The link list is paginated: %d of %d links were read. Page through offset so "
            "the count covers the whole domain." % (len(links), count)
        )
    if links_truncated(data, links):
        result["isPublicSharingRestricted"] = None
        passes = []
        fails = [
            "%d links were read and the response does not show that this is every link in "
            "the domain. Public sharing is not measured on a partial read." % len(links)
        ]
        recs = ["Page through offset so every link is read."]
    return result, passes, fails, recs, {"linksReturned": len(links), "reportedCount": count},


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}
    result, pass_reasons, fail_reasons, recommendations, input_summary = evaluate(data)
    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isPublicSharingRestricted",
            "vendor": "Egnyte",
            "category": "Data Security",
        },
    )
