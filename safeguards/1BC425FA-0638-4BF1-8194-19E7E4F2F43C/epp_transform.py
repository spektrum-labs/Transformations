"""
Transformation: epp_transform (comprehensive)
Vendor: MDR / Endpoint Protection Platform
Category: Endpoint Security

Evaluates safeguard types coverage based on endpoints response data
and assigns a score from 0 to 100 for each safeguard type.

Only endpoints seen within 15 days of the newest lastSeenAt in the response are
scored (endpoint rules 2026-09-29); the rest are reported as staleEndpointCount.

An error, refusal, empty or unreadable endpoint read is Not evaluated (every key None with a
data-collection error), never a failed check. So is a partial read (a next-page cursor or a
truncation marker is present), and so is a body with no endpoint list: a figure, a "none found"
or a count taken from part of the fleet is not a total. The configured key (isEPPConfigured) is
derived from the endpoint list alone: Sophos documents no such field, so a flag in the body is never
read, never kept and never overrides what the list shows.
"""

import json
from datetime import datetime, timedelta


ACTIVE_WINDOW_DAYS = 15


# A read that proves nothing is Not evaluated, never False. An error body, an HTTP 4xx/5xx body, a
# failed input validation, an empty, null or unrecognised body, an empty endpoint list and an
# exception all return every key as None with dataCollection.status "error", which the evaluator
# shows as Not evaluated, as do a partial read (pages left unread) and a body with no endpoint list.
# A complete endpoint list that holds no managed endpoint still reads 0 / False.
# The reason text is fixed: the vendor's own error text is never copied into the result.
RESULT_KEYS = [
    "Endpoint Protection", "Endpoint Security", "Server Protection", "MDR", "Network Protection",
    "Cloud Security", "Mobile Protection", "Email Security", "Phishing Protection",
    "Zero Trust Network Access", "Encryption", "isEPPEnabled", "isEPPDeployed",
    "isEPPLoggingEnabled", "isEPPEnabledForCriticalSystems", "isEDRDeployed",
    "isEndpointSecurityEnabled", "staleEndpointCount", "isMDREnabled", "isMDRLoggingEnabled",
    "requiredCoveragePercentage", "requiredConfigurationPercentage", "isEPPConfigured",
    "isEPPMisconfigured",
]
STATUS_KEYS = ["status_code", "statusCode", "httpStatus", "status"]
ERROR_REASON = "Not evaluated: Sophos returned an error instead of an endpoint list; nothing was measured."
NO_ENDPOINTS_REASON = "Not evaluated: no endpoints returned"
NO_LIST_REASON = "Not evaluated: no endpoint list in the response; nothing was measured."
PARTIAL_REASON = (
    "Not evaluated: the endpoint list is only part of the fleet (it has further pages that were not read, "
    "or it starts after the first page), so a coverage figure from part of the list is not a total; "
    "nothing was measured."
)
VALIDATION_REASON = "Not evaluated: the response failed input validation; nothing was measured."
EXCEPTION_REASON = "Not evaluated: the transformation could not read the response; nothing was measured."


def not_measured_result():
    result = {}
    for key in RESULT_KEYS:
        result[key] = None
    return result


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


def read_problem(data):
    """Why a body is not a complete, readable endpoint list (fixed text), or None when it is one.

    A complete list of endpoints, even one with no managed endpoint, is a read that proves a
    negative and is scored as before. A list that is only part of the fleet is not (see
    unread_pages). A body with no endpoint list, whatever else it carries (a configured flag
    included), has nothing to score.
    """
    if isinstance(data, list):
        return list_problem(data)
    if isinstance(data, dict):
        reason = error_reason(data)
        if reason is not None:
            return reason
        items = data.get("items")
        if isinstance(items, list):
            problem = list_problem(items)
            if problem is not None:
                return problem
            return unread_pages(data, len(items))
        return NO_LIST_REASON
    return NO_LIST_REASON


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

    A next-page cursor still set, a truncation marker, more items than were returned, more pages
    than one page of endpoints, or a page that does not start at the beginning (fromKey set) all
    mean part of the fleet was not read. More than one page (pages.total above 1) is partial unless
    pages.items says how many items the whole list holds and that is exactly the number returned (a
    body whose pages were joined): a page total says nothing about how many items a page holds, so it
    cannot show the list is whole, with or without a page size. A page total or item total that is present
    but not a whole number ("many", "4.5", a boolean) shows nothing either, so it is partial too; 4.0 and "4.0"
    are read as 4. A pages field that is present but not an object, and a next key at the top of the body, are partial too. Anything computed from the part
    that was read (a percentage, a "none found" False, a count) rests on endpoints nobody has
    seen, so it is not reported. A full first page with no cursor is not treated as partial: a
    complete read of a large fleet looks the same.
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


def parse_seen(value):
    try:
        # strptime imports _strptime, which the Token-Service sandbox refuses.
        return datetime.fromisoformat(str(value)[:19])
    except Exception:
        return None


def active_endpoints(items):
    """Split endpoints into (active, stale_count) using the newest lastSeenAt as the clock."""
    endpoints = [e for e in items if isinstance(e, dict)]
    seen = [parse_seen(e.get("lastSeenAt")) for e in endpoints]
    known = [s for s in seen if s is not None]
    if not known:
        return endpoints, 0
    cutoff = max(known) - timedelta(days=ACTIVE_WINDOW_DAYS)
    wall_cutoff = datetime.utcnow() - timedelta(days=ACTIVE_WINDOW_DAYS)
    if max(known) < wall_cutoff:
        # Dark fleet: the newest check-in is itself older than the window, so every endpoint is stale.
        cutoff = wall_cutoff
    active = []
    stale = 0
    for endpoint, when in zip(endpoints, seen):
        if when is not None and when < cutoff:
            stale = stale + 1
        else:
            active.append(endpoint)
    return active, stale


def transform(input):
    def extract_input(input_data):
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
                    "transformationId": "epp_transform",
                    "vendor": "MDR Provider",
                    "category": "Endpoint Security"
                }
            }
        }

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result=not_measured_result(),
                validation=validation,
                fail_reasons=[VALIDATION_REASON],
                api_errors=[VALIDATION_REASON]
            )

        problem = read_problem(data)
        if problem is not None:
            return create_response(
                result=not_measured_result(),
                validation=validation,
                fail_reasons=[problem],
                api_errors=[problem]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # Initialize counters
        # Token-Service preprocessing may deliver the endpoints as a bare list
        # (when the API response's `data` field is itself a list) or as a dict
        # containing `items`. Handle both so counts aren't silently zeroed.
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = data.get("items") or []
            if not isinstance(items, list):
                items = []
        else:
            items = []
        items, stale_endpoints = active_endpoints(items)
        total_endpoints = len(items)
        total_computers = 0
        total_servers = 0
        total_mobile_devices = 0
        total_cloud_endpoints = 0

        # Use simple variables to avoid "augmented assignment of object items" in restricted Python
        ep_count = 0
        es_count = 0
        server_protection_count = 0
        mdr_count = 0
        xdr_count = 0  # self-service XDR licence: information only, not MDR coverage
        network_protection_count = 0
        cloud_security_count = 0
        mobile_protection_count = 0
        email_security_count = 0
        phishing_protection_count = 0
        ztna_count = 0
        encryption_count = 0

        for endpoint in items:
            assigned_products = {product["code"]: product for product in endpoint.get("assignedProducts", [])}
            services = {service["name"]: service for service in endpoint.get("health", {}).get("services", {}).get("serviceDetails", [])}
            endpoint_type = endpoint.get("type")

            # Count total number of computers, servers, mobile devices, and cloud endpoints
            if endpoint_type == "computer":
                total_computers = total_computers + 1
            elif endpoint_type == "server":
                total_servers = total_servers + 1
            elif endpoint_type == "mobile":
                total_mobile_devices = total_mobile_devices + 1

            if "cloud" in endpoint:
                total_cloud_endpoints = total_cloud_endpoints + 1

            # 1. Endpoint Protection
            if endpoint_type == "computer" and "endpointProtection" in assigned_products:
                ep_count = ep_count + 1

            # 1.1 Endpoint Security
            if endpoint_type == "computer" and "endpointProtection" in assigned_products:
                es_count = es_count + 1

            # 2. Server Protection
            if endpoint_type == "server" and "endpointProtection" in assigned_products:
                server_protection_count = server_protection_count + 1

            # 3. MDR (Managed Detection and Response)
            # Count only the managed-service product code ("mtr", Managed Threat Response)
            # or an explicit mdrManaged true. The "xdr" product is the self-service XDR
            # licence, not a managed service, so it is counted on its own as information
            # and is never added to the MDR figure. A missing or null mdrManaged is not MDR.
            if "mtr" in assigned_products:
                mdr_count = mdr_count + 1
            elif str(endpoint.get("mdrManaged")).strip().lower() == "true":
                mdr_count = mdr_count + 1
            if "xdr" in assigned_products:
                xdr_count = xdr_count + 1

            # 4. Network Protection
            if any("Network Threat Protection" in service_name for service_name in services):
                network_protection_count = network_protection_count + 1

            # 5. Cloud Security
            if endpoint.get("cloud", {}).get("provider") and "endpointProtection" in assigned_products:
                cloud_security_count = cloud_security_count + 1

            # 6. Mobile Protection
            if endpoint_type == "mobile" and "mobileProtection" in assigned_products:
                mobile_protection_count = mobile_protection_count + 1

            # 7. Email Security
            if "emailSecurity" in assigned_products:
                email_security_count = email_security_count + 1

            # 8. Phishing Protection
            if "interceptX" in assigned_products:
                phishing_protection_count = phishing_protection_count + 1

            # 9. Zero Trust Network Access
            ztna_product = assigned_products.get("ztna")
            if ztna_product and ztna_product.get("status") == "installed":
                ztna_count = ztna_count + 1

            # 10. Encryption
            if endpoint.get("encryption", {}).get("volumes"):
                encryption_count = encryption_count + 1

        safeguard_counters = {
            "Endpoint Protection": ep_count,
            "Endpoint Security": es_count,
            "Server Protection": server_protection_count,
            "MDR": mdr_count,
            "XDR (self-service, information only)": xdr_count,
            "Network Protection": network_protection_count,
            "Cloud Security": cloud_security_count,
            "Mobile Protection": mobile_protection_count,
            "Email Security": email_security_count,
            "Phishing Protection": phishing_protection_count,
            "Zero Trust Network Access": ztna_count,
            "Encryption": encryption_count
        }

        # Initialize coverage scores
        coverage_scores = {}

        # Calculate scores
        coverage_scores["Endpoint Protection"] = round(
            (safeguard_counters["Endpoint Protection"] / total_computers) * 100
            if total_computers > 0 else 0
        )

        coverage_scores["Endpoint Security"] = round(
            (safeguard_counters["Endpoint Security"] / total_computers) * 100
            if total_computers > 0 else 0
        )

        coverage_scores["Server Protection"] = round(
            (safeguard_counters["Server Protection"] / total_servers) * 100
            if total_servers > 0 else 0
        )

        coverage_scores["MDR"] = round(
            (safeguard_counters["MDR"] / total_endpoints) * 100
            if total_endpoints > 0 else 0
        )

        coverage_scores["Network Protection"] = round(
            (safeguard_counters["Network Protection"] / total_endpoints) * 100
            if total_endpoints > 0 else 0
        )

        coverage_scores["Cloud Security"] = round(
            (safeguard_counters["Cloud Security"] / total_cloud_endpoints) * 100
            if total_cloud_endpoints > 0 else 0
        )

        coverage_scores["Mobile Protection"] = round(
            (safeguard_counters["Mobile Protection"] / total_mobile_devices) * 100
            if total_mobile_devices > 0 else 0
        )

        coverage_scores["Email Security"] = round(
            (safeguard_counters["Email Security"] / total_endpoints) * 100
            if total_endpoints > 0 else 0
        )

        coverage_scores["Phishing Protection"] = round(
            (safeguard_counters["Phishing Protection"] / total_endpoints) * 100
            if total_endpoints > 0 else 0
        )

        coverage_scores["Zero Trust Network Access"] = round(
            (safeguard_counters["Zero Trust Network Access"] / total_endpoints) * 100
            if total_endpoints > 0 else 0
        )

        coverage_scores["Encryption"] = round(
            (safeguard_counters["Encryption"] / total_endpoints) * 100
            if total_endpoints > 0 else 0
        )

        # Endpoint Protection boolean flags
        coverage_scores["isEPPEnabled"] = coverage_scores["Endpoint Protection"] > 0
        coverage_scores["isEPPDeployed"] = coverage_scores["Endpoint Protection"] > 0
        coverage_scores["isEPPLoggingEnabled"] = coverage_scores["Endpoint Protection"] > 0
        coverage_scores["isEPPEnabledForCriticalSystems"] = coverage_scores["Endpoint Protection"] > 0
        coverage_scores["isEDRDeployed"] = coverage_scores["Endpoint Protection"] > 0

        # Endpoint Security
        coverage_scores["isEndpointSecurityEnabled"] = coverage_scores["Endpoint Security"] > 0

        coverage_scores["staleEndpointCount"] = stale_endpoints

        # MDR
        coverage_scores["isMDREnabled"] = coverage_scores["MDR"] > 0
        coverage_scores["isMDRLoggingEnabled"] = coverage_scores["MDR"] > 0
        coverage_scores["requiredCoveragePercentage"] = coverage_scores["Endpoint Protection"]
        coverage_scores["requiredConfigurationPercentage"] = coverage_scores["Endpoint Protection"]

        # "Configured" must reflect real deployment, so it is derived from the endpoint list alone:
        # at least one protected endpoint. Sophos documents no configured field, so a flag in the
        # body is never read (it could only override what the list shows).
        coverage_scores["isEPPConfigured"] = (
            total_endpoints > 0 and coverage_scores["Endpoint Protection"] > 0
        )

        # Inverted key (true = the insecure condition). Its RTA entry reads this file through the
        # isEPPConfigured method but nothing emitted it, so the row had no value. An empty or unreadable
        # read never gets here (it is Not evaluated above). A complete list whose every endpoint is stale
        # leaves no protected endpoint, so configured is False and this is True, the same measured negative as
        # the other keys; a None here would travel with a success status and be graded as a failure.
        coverage_scores["isEPPMisconfigured"] = not coverage_scores["isEPPConfigured"]

        # Build pass/fail reasons (use concatenation to avoid list mutation in restricted Python)
        epp_coverage = coverage_scores.get('Endpoint Protection', 0)
        if coverage_scores["isEPPEnabled"]:
            if epp_coverage > 0:
                pass_reasons = pass_reasons + [f"Endpoint protection active: {epp_coverage}% of devices protected"]
            else:
                pass_reasons = pass_reasons + ["Endpoint protection configured but no devices currently protected"]
                recommendations = recommendations + ["Verify endpoint agent deployment status"]
        else:
            fail_reasons = fail_reasons + ["Endpoint protection not deployed or not reporting data"]
            recommendations = recommendations + ["Deploy endpoint protection to all computers"]

        server_coverage = coverage_scores.get("Server Protection", 0)
        if server_coverage > 0:
            pass_reasons = pass_reasons + [f"Server protection active: {server_coverage}% of servers protected"]

        mdr_coverage = coverage_scores.get("MDR", 0)
        if coverage_scores["isMDREnabled"]:
            if mdr_coverage > 0:
                pass_reasons = pass_reasons + [f"MDR active: {mdr_coverage}% coverage"]
            else:
                pass_reasons = pass_reasons + ["MDR configured but no devices currently monitored"]

        return create_response(
            result=coverage_scores,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "totalEndpoints": total_endpoints,
                "staleEndpoints": stale_endpoints,
                "totalComputers": total_computers,
                "totalServers": total_servers,
                "totalMobileDevices": total_mobile_devices,
                "totalCloudEndpoints": total_cloud_endpoints,
                "safeguardCounters": safeguard_counters
            }
        )

    except Exception as e:
        return create_response(
            result=not_measured_result(),
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[EXCEPTION_REASON],
            api_errors=[EXCEPTION_REASON]
        )
