"""
Transformation: isEndpointCoverageValid
Vendor: Red Canary
Category: Cloud Security / Endpoint Coverage

Validates that endpoint coverage meets the required threshold.

    coverage = live endpoints Red Canary reports as monitored / live endpoints * 100
    isEndpointCoverageValid = coverage >= COVERAGE_VALID_THRESHOLD (95)

Live means not decommissioned. A live endpoint with no readable monitoring status counts as not
covered, so it lowers coverage and never raises it.

2026-10-05: the check used to pass when ANY endpoint was monitored (one monitored endpoint in
dozens read "coverage valid"). A tool speaks only for what it protects, so partial coverage now fails. The threshold
matches the MDR requiredCoveragePercentage criterion (greaterThan 95, inclusive) and
isMDRConfigured (>= 95). A census with no live endpoint is Unevaluated, not a finding.
"""

import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
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
                "transformationId": "isEndpointCoverageValid",
                "vendor": "Red Canary",
                "category": "Cloud Security"
            }
        }
    }


# ---- fail-closed guard (2026-10-01) ------------------------------------------------------------
# A read that does not show a measured, complete endpoint census proves nothing either way, so the
# criterion is returned as None with dataCollection.status "error". Token-Service reads that as
# Unevaluated: never a pass and never a finding. It covers a missing or empty body, a vendor or
# platform error envelope, a payload this transformation does not recognise, a read that came back
# with zero endpoints, and a read shorter than the census it reports (truncated).
#
# Why zero endpoints is not a measurement: the integration pages GET /openapi/v3/endpoints, and
# when Red Canary rate-limits a page part-way through (HTTP 429 after the retries) the platform
# hands this transformation an empty body with no error on it. Zero endpoints from that read is a
# failed read, not a tenant with MDR switched off, and a tenant that really runs no endpoints has
# nothing for an endpoint check to measure.

#: the integration reads at most 100 pages of Red Canary's 50-endpoint pages; a census this long may
#: have stopped at that cap rather than at the last endpoint
ENDPOINT_READ_CAP = 5000

#: the share of live endpoints (percent) Red Canary must report as monitored for coverage to be
#: valid; compared exactly (monitored * 100 >= threshold * live), never on a rounded figure
COVERAGE_VALID_THRESHOLD = 95

#: attributes a Red Canary v3 endpoint record carries; one of them marks a record as an endpoint
ENDPOINT_FIELDS = ("monitoring_status", "endpoint_status", "is_decommissioned", "hostname",
                   "display_identifier", "platform", "registration_time", "last_checkin_time")


def parse_body(data):
    """A JSON string or bytes body parsed; anything else unchanged. Unparseable text stays text."""
    if isinstance(data, bytes):
        try:
            data = data.decode("utf-8")
        except Exception:
            return data
    if isinstance(data, str):
        try:
            return json.loads(data)
        except Exception:
            return data
    return data


def error_problem(data):
    """Describe why `data` is a vendor or platform error rather than evidence, or return None."""
    if data is None:
        return "Red Canary returned no body"
    if isinstance(data, (str, bytes)):
        return "Red Canary returned a body that is not JSON"
    if not isinstance(data, dict):
        return None
    for name in ("statusCode", "status_code", "httpStatus", "vendorStatus"):
        code = data.get(name)
        if isinstance(code, str) and code.strip().isdigit():
            code = int(code.strip())
        if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
            return "Red Canary returned HTTP " + str(code)
    err = data.get("error") or data.get("errors") or data.get("vendorError")
    if err:
        if isinstance(err, list):
            err = err[0]
        if isinstance(err, dict):
            err = err.get("message") or err.get("detail") or err.get("title") or err.get("type") or "error"
        return "Red Canary returned an error: " + str(err)[:200]
    if str(data.get("status", "")).strip().lower() == "error":
        return "the integration reported an error status"
    return None


def as_count(value):
    """An integer count from an int or a numeric string (Red Canary sends counts as strings)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip() if value is not None else ""
    if text.isdigit():
        return int(text)
    return None


def is_endpoint_record(item):
    """True when `item` reads as a Red Canary endpoint (v3 nests its fields under attributes)."""
    if not isinstance(item, dict):
        return False
    if str(item.get("type") or "").strip().lower() == "endpoint":
        return True
    attrs = item.get("attributes")
    fields = attrs if isinstance(attrs, dict) else item
    for name in ENDPOINT_FIELDS:
        if name in fields:
            return True
    return False


def endpoint_census(data):
    """(endpoints, meta, problem): the records of a complete endpoints read, or why there are none.

    Token-Service hands a legacy transformation the drilled endpoint LIST; the enveloped
    {"meta", "links", "data"} body is read as well.
    """
    problem = error_problem(data)
    if problem:
        return None, {}, problem
    meta = {}
    endpoints = None
    if isinstance(data, list):
        endpoints = data
    elif isinstance(data, dict):
        for name in ("data", "endpoints", "value"):
            if isinstance(data.get(name), list):
                endpoints = data.get(name)
                break
        if isinstance(data.get("meta"), dict):
            meta = data.get("meta")
    if endpoints is None:
        return None, meta, ("The response carries no endpoints collection: the endpoints read "
                            "cannot be shown to have run, so nothing was measured")
    if len(endpoints) == 0:
        return None, meta, ("Red Canary returned 0 endpoints. A read that fails part-way returns an "
                            "empty body, so zero endpoints is not evidence either way")
    recognised = 0
    for ep in endpoints:
        if is_endpoint_record(ep):
            recognised = recognised + 1
    if recognised == 0:
        return None, meta, ("The response carries no Red Canary endpoint records: nothing was "
                            "measured")
    if str(meta.get("truncated") or "").strip().lower() == "true":
        return None, meta, ("The endpoints read stopped at the page cap: the census is incomplete, "
                            "so nothing was measured")
    reported = as_count(meta.get("total_items"))
    if reported is not None and reported > len(endpoints):
        return None, meta, ("The endpoints read is incomplete: Red Canary reports " + str(reported)
                            + " endpoint(s) and " + str(len(endpoints)) + " were returned")
    if len(endpoints) >= ENDPOINT_READ_CAP:
        return None, meta, ("The endpoints read returned " + str(len(endpoints)) + " endpoints, "
                            "the integration's page cap: the census may be incomplete")
    return endpoints, meta, None


def unevaluated(keys, problem, validation=None, input_summary=None, transformation_errors=None):
    """Every key as None plus a dataCollection error: reads Unevaluated, never True or False."""
    result = {}
    for key in keys:
        result[key] = None
    return create_response(
        result=result,
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        transformation_errors=transformation_errors,
        input_summary=input_summary,
    )


def transform(input):
    criteriaKey = "isEndpointCoverageValid"

    try:
        data, validation = extract_input(parse_body(input))

        if isinstance(validation, dict) and validation.get("status") == "failed":
            return unevaluated([criteriaKey], "Input validation failed: nothing was measured", validation)

        census, census_meta, problem = endpoint_census(data)
        if problem:
            return unevaluated([criteriaKey], problem, validation,
                               input_summary={"totalEndpoints": None})

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        coverage_valid = False
        total_endpoints = 0
        monitored_endpoints = 0
        unmonitored_endpoints = 0
        unknown_endpoints = 0
        decommissioned_endpoints = 0

        # endpoint_census has already refused an empty, error, unrecognised or cut-short read, so
        # this is the whole census and meta.total_items (when present) is not larger than it
        for endpoint in census:
            if not isinstance(endpoint, dict):
                continue
            # Red Canary v3 nests fields under "attributes": monitoring_status is
            # "monitored"/"unmonitored". Flat shapes are still read.
            attrs = endpoint.get('attributes') if isinstance(endpoint.get('attributes'), dict) else endpoint
            if str(attrs.get('is_decommissioned')).strip().lower() == 'true':
                decommissioned_endpoints += 1
                continue
            total_endpoints += 1
            is_monitored = attrs.get('is_monitored', attrs.get('monitored',
                           attrs.get('sensor_installed', None)))
            status = str(attrs.get('monitoring_status') or attrs.get('status') or attrs.get('state') or '').lower()

            if is_monitored is True or status in ('active', 'monitored', 'online', 'healthy'):
                monitored_endpoints += 1
            elif is_monitored is False or status in ('inactive', 'unmonitored', 'offline', 'unhealthy'):
                unmonitored_endpoints += 1
            else:
                # No readable status: NOT counted as monitored, so it can only lower coverage.
                unknown_endpoints += 1

        if total_endpoints == 0:
            return unevaluated(
                [criteriaKey],
                "Every endpoint Red Canary returned (" + str(decommissioned_endpoints) + ") is "
                "decommissioned: there is no live endpoint to measure coverage over",
                validation,
                input_summary={"totalEndpoints": 0, "decommissionedEndpoints": decommissioned_endpoints})

        coverage_percentage = round((monitored_endpoints / total_endpoints) * 100, 1)
        coverage_valid = monitored_endpoints * 100 >= COVERAGE_VALID_THRESHOLD * total_endpoints
        summary = (f"{monitored_endpoints} of {total_endpoints} live endpoints monitored "
                   f"({coverage_percentage}% coverage; {COVERAGE_VALID_THRESHOLD}% required)")

        if coverage_valid:
            pass_reasons.append("Endpoint coverage is valid: " + summary)
        else:
            fail_reasons.append("Endpoint coverage is below the required threshold: " + summary)
            recommendations.append(
                "Return the unmonitored endpoints to monitoring in the Red Canary portal (Endpoints, "
                "filter monitoring status: unmonitored), or decommission those no longer in service")

        not_covered = unmonitored_endpoints + unknown_endpoints
        if not_covered > 0:
            additional_findings.append(
                f"{not_covered} live endpoint(s) are not currently monitored"
                + (f" ({unknown_endpoints} report no readable monitoring status)" if unknown_endpoints else "")
            )

        return create_response(
            result={
                criteriaKey: coverage_valid,
                "totalEndpoints": total_endpoints,
                "monitoredEndpoints": monitored_endpoints,
                "unmonitoredEndpoints": unmonitored_endpoints,
                "unknownStatusEndpoints": unknown_endpoints,
                "decommissionedEndpoints": decommissioned_endpoints,
                "coveragePercentage": coverage_percentage,
                "coverageThreshold": COVERAGE_VALID_THRESHOLD
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalEndpoints": total_endpoints,
                "monitoredEndpoints": monitored_endpoints,
                "unmonitoredEndpoints": unmonitored_endpoints,
                "decommissionedEndpoints": decommissioned_endpoints,
                "coveragePercentage": coverage_percentage
            }
        )

    except Exception as e:
        message = "Transformation error: " + str(e)[:200]
        return unevaluated([criteriaKey], message, {"status": "error", "errors": [], "warnings": []},
                           transformation_errors=[message])
