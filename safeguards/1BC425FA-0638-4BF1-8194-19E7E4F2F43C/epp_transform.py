"""
Transformation: epp_transform (comprehensive)
Vendor: Sophos Central (MDR / Endpoint Protection Platform)
Category: Endpoint Security
Method: getEndpoints (GET /endpoint/v1/endpoints)

Evaluates safeguard types coverage based on endpoints response data
and assigns a score from 0 to 100 for each safeguard type.

Only endpoints seen within 15 days of the newest lastSeenAt in the response are
scored (endpoint rules 2026-09-29); the rest are reported as staleEndpointCount.
A product counts only when its assignedProducts entry reads status "installed".

Fail closed (2026-10-07, back-ported from the CrowdStrike copy): a read that is not a
complete Sophos endpoint list -- no body, an error envelope, no endpoint records, or a
list the connector stopped paging before the end -- is Unevaluated for every key.
"""

import json
from datetime import datetime, timedelta


ACTIVE_WINDOW_DAYS = 15

#: share of active computers and servers that must carry the installed xdr product for isEDRDeployed
EDR_DEPLOYED_THRESHOLD = 95.0


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


def installed_codes(endpoint):
    """Product codes Sophos reports as installed; an assigned but notInstalled product protects nothing."""
    return [p.get("code") for p in (endpoint.get("assignedProducts") or [])
            if isinstance(p, dict) and p.get("status") == "installed"]


def flag_true(value):
    """True only for an explicit true; None, absent or unparseable is not a yes."""
    return value is True or str(value).strip().lower() == "true"


def percentage(count, total):
    return round((count / total) * 100) if total > 0 else 0


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
    # Derived from the values as well as from api_errors: a result in which nothing was measured
    # reads as a collection error even on a path that forgot to say so.
    measured = any(value is not None for value in (result or {}).values())
    collection_errors = api_errors or ([] if measured else ["Nothing was measured"])
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if collection_errors else "success",
                "errors": collection_errors
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
                "vendor": "Sophos Central",
                "category": "Endpoint Security"
            }
        }
    }


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return unevaluated("Input validation failed: nothing was measured", validation)

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # Token-Service preprocessing may deliver the endpoints as a bare list
        # (when the API response's `data` field is itself a list) or as a dict
        # containing `items`.
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = data.get("items") or []
            if not isinstance(items, list):
                items = []
        else:
            items = []

        # Fail closed: a body that is not a complete endpoint list proves nothing about the estate,
        # so every key is None with a dataCollection error (Unevaluated), never False and never True.
        problem = no_endpoint_evidence(data, items)
        if problem:
            return unevaluated(problem, validation)

        items, stale_endpoints = active_endpoints([e for e in items if is_endpoint_record(e)])
        total_endpoints = len(items)
        total_computers = 0
        total_servers = 0
        total_mobile_devices = 0
        total_cloud_endpoints = 0

        # Use simple variables to avoid "augmented assignment of object items" in restricted Python
        ep_count = 0
        es_count = 0
        server_protection_count = 0
        edr_count = 0
        mdr_count = 0
        network_protection_count = 0
        cloud_security_count = 0
        mobile_protection_count = 0
        email_security_count = 0
        phishing_protection_count = 0
        ztna_count = 0
        encryption_count = 0

        for endpoint in items:
            codes = installed_codes(endpoint)
            health = endpoint.get("health") if isinstance(endpoint.get("health"), dict) else {}
            health_services = health.get("services") if isinstance(health.get("services"), dict) else {}
            services = [s.get("name") for s in (health_services.get("serviceDetails") or [])
                        if isinstance(s, dict) and s.get("name")]
            endpoint_type = endpoint.get("type")
            cloud = endpoint.get("cloud") if isinstance(endpoint.get("cloud"), dict) else {}

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
            if endpoint_type == "computer" and "endpointProtection" in codes:
                ep_count = ep_count + 1

            # 1.1 Endpoint Security
            if endpoint_type == "computer" and "endpointProtection" in codes:
                es_count = es_count + 1

            # 2. Server Protection
            if endpoint_type == "server" and "endpointProtection" in codes:
                server_protection_count = server_protection_count + 1

            # 2.1 EDR: the Sophos xdr product installed on a computer or server
            if endpoint_type in ("computer", "server") and "xdr" in codes:
                edr_count = edr_count + 1

            # 3. MDR (Managed Detection and Response). mdrManaged is not in Sophos's documented
            # endpoint schema; it counts only when it is explicitly true. It used to count whenever
            # it was anything other than "false", so None and unknown values read as MDR-managed.
            if "mtr" in codes or "xdr" in codes or flag_true(endpoint.get("mdrManaged")):
                mdr_count = mdr_count + 1

            # 4. Network Protection
            if any("Network Threat Protection" in str(service_name) for service_name in services):
                network_protection_count = network_protection_count + 1

            # 5. Cloud Security
            if cloud.get("provider") and "endpointProtection" in codes:
                cloud_security_count = cloud_security_count + 1

            # 6. Mobile Protection
            if endpoint_type == "mobile" and "mobileProtection" in codes:
                mobile_protection_count = mobile_protection_count + 1

            # 7. Email Security
            if "emailSecurity" in codes:
                email_security_count = email_security_count + 1

            # 8. Phishing Protection
            if "interceptX" in codes:
                phishing_protection_count = phishing_protection_count + 1

            # 9. Zero Trust Network Access
            if "ztna" in codes:
                ztna_count = ztna_count + 1

            # 10. Encryption
            encryption = endpoint.get("encryption") if isinstance(endpoint.get("encryption"), dict) else {}
            if encryption.get("volumes"):
                encryption_count = encryption_count + 1

        safeguard_counters = {
            "Endpoint Protection": ep_count,
            "Endpoint Security": es_count,
            "Server Protection": server_protection_count,
            "EDR": edr_count,
            "MDR": mdr_count,
            "Network Protection": network_protection_count,
            "Cloud Security": cloud_security_count,
            "Mobile Protection": mobile_protection_count,
            "Email Security": email_security_count,
            "Phishing Protection": phishing_protection_count,
            "Zero Trust Network Access": ztna_count,
            "Encryption": encryption_count
        }

        coverage_scores = {}
        coverage_scores["Endpoint Protection"] = percentage(ep_count, total_computers)
        coverage_scores["Endpoint Security"] = percentage(es_count, total_computers)
        coverage_scores["Server Protection"] = percentage(server_protection_count, total_servers)
        coverage_scores["MDR"] = percentage(mdr_count, total_endpoints)
        coverage_scores["Network Protection"] = percentage(network_protection_count, total_endpoints)
        coverage_scores["Cloud Security"] = percentage(cloud_security_count, total_cloud_endpoints)
        coverage_scores["Mobile Protection"] = percentage(mobile_protection_count, total_mobile_devices)
        coverage_scores["Email Security"] = percentage(email_security_count, total_endpoints)
        coverage_scores["Phishing Protection"] = percentage(phishing_protection_count, total_endpoints)
        coverage_scores["Zero Trust Network Access"] = percentage(ztna_count, total_endpoints)
        coverage_scores["Encryption"] = percentage(encryption_count, total_endpoints)

        # Endpoint Protection boolean flags
        coverage_scores["isEPPEnabled"] = coverage_scores["Endpoint Protection"] > 0
        coverage_scores["isEPPDeployed"] = coverage_scores["Endpoint Protection"] > 0

        # The next three were aliases of isEPPDeployed. Each now answers its own question or None.
        #
        # isEDRDeployed: the share of active computers and servers with the xdr product installed,
        # against EDR_DEPLOYED_THRESHOLD. It proves the XDR component is on the endpoint, not that
        # the threat protection policy setting that sends XDR data to Sophos is turned on; the
        # endpoint list does not carry policy settings.
        edr_population = total_computers + total_servers
        if edr_population == 0:
            coverage_scores["edrDeployedPercentage"] = None
            coverage_scores["isEDRDeployed"] = None
        else:
            coverage_scores["edrDeployedPercentage"] = round(edr_count * 100.0 / edr_population, 2)
            coverage_scores["isEDRDeployed"] = coverage_scores["edrDeployedPercentage"] >= EDR_DEPLOYED_THRESHOLD

        # isEPPEnabledForCriticalSystems: every active server has endpointProtection installed. It was
        # computed from the computers-only count, so no server could ever affect it. With no active
        # server in the list there is nothing to judge (a server without the Sophos agent is not in
        # the list either), so it is None, never True.
        if total_servers == 0:
            coverage_scores["isEPPEnabledForCriticalSystems"] = None
        else:
            coverage_scores["isEPPEnabledForCriticalSystems"] = server_protection_count == total_servers

        # isEPPLoggingEnabled: the endpoint list carries nothing about logging, telemetry or data
        # upload, so this file cannot answer it. None on every path; the integration's RTA row for
        # this key has to go (the requirement becomes document-only) -- see the C3 validation record.
        coverage_scores["isEPPLoggingEnabled"] = None

        # Endpoint Security
        coverage_scores["isEndpointSecurityEnabled"] = coverage_scores["Endpoint Security"] > 0

        coverage_scores["staleEndpointCount"] = stale_endpoints

        # MDR
        coverage_scores["isMDREnabled"] = coverage_scores["MDR"] > 0
        coverage_scores["isMDRLoggingEnabled"] = coverage_scores["MDR"] > 0
        coverage_scores["requiredCoveragePercentage"] = coverage_scores["Endpoint Protection"]
        coverage_scores["requiredConfigurationPercentage"] = coverage_scores["Endpoint Protection"]

        # "Configured" reflects real deployment: at least one protected endpoint. The body's own
        # isEPPConfigured was honoured here once; Sophos never sends it, and a criterion read out of
        # the body it judges proves nothing.
        coverage_scores["isEPPConfigured"] = total_endpoints > 0 and coverage_scores["Endpoint Protection"] > 0

        # Inverted key (true = the insecure condition). Its RTA entry reads this file through the
        # isEPPConfigured method. A read with no active endpoint proves nothing either way, so it is
        # None (never False, which would be a pass).
        coverage_scores["isEPPMisconfigured"] = (not coverage_scores["isEPPConfigured"]) if total_endpoints > 0 else None

        # Build pass/fail reasons (use concatenation to avoid list mutation in restricted Python)
        epp_coverage = coverage_scores.get('Endpoint Protection', 0)
        if coverage_scores["isEPPEnabled"]:
            pass_reasons = pass_reasons + [f"Endpoint protection active: {epp_coverage}% of computers protected"]
        else:
            fail_reasons = fail_reasons + ["Endpoint protection not installed on any active computer"]
            recommendations = recommendations + ["Deploy endpoint protection to all computers"]

        if coverage_scores["isEDRDeployed"] is True:
            pass_reasons = pass_reasons + [
                f"EDR deployed: xdr installed on {edr_count} of {edr_population} active computers and servers "
                f"({coverage_scores['edrDeployedPercentage']}%)"]
        elif coverage_scores["isEDRDeployed"] is False:
            fail_reasons = fail_reasons + [
                f"EDR not deployed widely enough: xdr installed on {edr_count} of {edr_population} active computers "
                f"and servers ({coverage_scores['edrDeployedPercentage']}%, threshold {EDR_DEPLOYED_THRESHOLD}%)"]
            recommendations = recommendations + ["Assign Intercept X Advanced with XDR to every computer and server"]
        else:
            fail_reasons = fail_reasons + ["isEDRDeployed not measured: no active computer or server in the list"]

        if coverage_scores["isEPPEnabledForCriticalSystems"] is True:
            pass_reasons = pass_reasons + [f"Server protection installed on all {total_servers} active servers"]
        elif coverage_scores["isEPPEnabledForCriticalSystems"] is False:
            fail_reasons = fail_reasons + [
                f"Server protection installed on {server_protection_count} of {total_servers} active servers"]
            recommendations = recommendations + ["Install Sophos server protection on every server"]
        else:
            fail_reasons = fail_reasons + ["isEPPEnabledForCriticalSystems not measured: no active server in the list"]

        fail_reasons = fail_reasons + [
            "isEPPLoggingEnabled not measured: the Sophos endpoint list does not report logging or telemetry"]

        mdr_coverage = coverage_scores.get("MDR", 0)
        if coverage_scores["isMDREnabled"]:
            pass_reasons = pass_reasons + [f"MDR active: {mdr_coverage}% coverage"]

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
        message = "Transformation error: " + str(e)[:200]
        return unevaluated(message, {"status": "error", "errors": [], "warnings": []},
                           transformation_errors=[message])


# ---- fail-closed guard (2026-10-07, after epp/crowdstrike/epp_transform.py 2026-10-02) ----------
# An empty or unreadable read used to come back as measured False with dataCollection "success":
# every coverage key read 0%, which graded as a real failure nobody had measured. A read that is not
# a complete endpoint list is now Unevaluated for every key.

#: keys this transformation answers from an endpoint list
ENDPOINT_KEYS = ("Endpoint Protection", "Endpoint Security", "Server Protection", "MDR", "Network Protection",
                 "Cloud Security", "Mobile Protection", "Email Security", "Phishing Protection",
                 "Zero Trust Network Access", "Encryption", "isEPPEnabled", "isEPPDeployed",
                 "isEPPLoggingEnabled", "isEPPEnabledForCriticalSystems", "isEDRDeployed", "edrDeployedPercentage",
                 "isEndpointSecurityEnabled", "staleEndpointCount", "isMDREnabled", "isMDRLoggingEnabled",
                 "requiredCoveragePercentage", "requiredConfigurationPercentage", "isEPPConfigured",
                 "isEPPMisconfigured")

#: fields a Sophos endpoint record (GET /endpoint/v1/endpoints) carries; one marks a record as an endpoint
ENDPOINT_FIELDS = ("assignedProducts", "health", "hostname", "lastSeenAt", "os", "tamperProtectionEnabled",
                   "tamperProtectionSupported", "associatedPerson", "ipv4Addresses")


def is_endpoint_record(item):
    """True when `item` reads as a Sophos endpoint record."""
    if not isinstance(item, dict):
        return False
    for name in ENDPOINT_FIELDS:
        if name in item:
            return True
    return False


def vendor_error(data):
    """Why `data` is a Sophos or platform error envelope, or None."""
    if not isinstance(data, dict):
        return None
    for name in ("statusCode", "status_code", "httpStatus"):
        code = data.get(name)
        if isinstance(code, str) and code.strip().isdigit():
            code = int(code.strip())
        if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
            return "Sophos returned HTTP " + str(code)
    if str(data.get("status")).strip().lower() == "error":
        return "Sophos read failed: " + str(data.get("message") or data.get("errorType") or "error")[:200]
    errors = data.get("errors") or data.get("error") or data.get("errorMessage")
    if errors:
        first = errors[0] if isinstance(errors, list) else errors
        if isinstance(first, dict):
            first = first.get("message") or first.get("code") or "error"
        detail = data.get("message")
        return "Sophos returned an error: " + str(first)[:100] + (": " + str(detail)[:100] if detail else "")
    return None


def unread_pages(data):
    """Why the endpoint list is partial, or None. Integration-Service marks a read it stopped paging at
    maxPages with pages.truncated; a body with a live pages.nextKey has pages nobody fetched."""
    pages = data.get("pages") if isinstance(data, dict) else None
    if not isinstance(pages, dict):
        return None
    if flag_true(pages.get("truncated")):
        return ("The endpoint list was truncated after " + str(pages.get("scannedCount")) +
                " endpoints: a sample is not the estate")
    next_key = pages.get("nextKey")
    if next_key is not None and str(next_key).strip().lower() not in ("", "none", "null"):
        return "The endpoint list has unread pages (pages.nextKey is set): a sample is not the estate"
    return None


def no_endpoint_evidence(data, items):
    """Why this read proves nothing about the estate, or None when it is a usable endpoint list."""
    if not isinstance(data, (dict, list)) or not data:
        return "Sophos returned no body: nothing was measured"
    problem = vendor_error(data)
    if problem:
        return problem
    if not items:
        return ("Sophos returned no endpoints. A failed or partial read returns an empty list, "
                "so zero endpoints is not evidence either way")
    recognised = 0
    for item in items:
        if is_endpoint_record(item):
            recognised = recognised + 1
    if recognised == 0:
        return "The response carries no Sophos endpoint records: nothing was measured"
    return unread_pages(data)


def unevaluated(problem, validation=None, transformation_errors=None):
    """Every key as None plus a dataCollection error: reads Unevaluated, never True or False."""
    result = {}
    for key in ENDPOINT_KEYS:
        result[key] = None
    return create_response(
        result=result,
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        transformation_errors=transformation_errors,
    )
