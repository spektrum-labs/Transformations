"""
Transformation: isDNSFilteringEnabled
Vendor: DNSFilter
Category: Network Security / DNS Filtering

Passes when the organisation has at least one live DNSFilter network (site). Every DNSFilter
network points at a filtering policy, and roaming clients and relays register against one, so
a live network is where filtering is configured. Whether that policy blocks anything is
isDNSPolicyConfigured's question; whether traffic actually flows is isDNSLoggingEnabled's.

Reads GET /v1/networks?organization_id=... (Integration-Service method getNetworks). The body
is JSON:API: {"data": [{"id": ..., "type": "networks", "attributes": {...}}], "meta": {...}}.
Token-Service strips the `data` wrapper, so the list usually arrives bare; a raw body keeps it
under `data`. DNSFilter networks carry no status field. A network with `deleted_at` set is not
counted (the previous version counted every record, and passed even when it judged them all
inactive). `ip_count` is reported as evidence (networksWithIps, totalIpCount): a network with
no registered IP filters only through roaming clients or relays, which this read does not see.

An empty list is a measured False: the organisation has no network to filter through. A body
with no readable network list is not measured (None with a dataCollection error).

Runs in Token-Service's RestrictedPython sandbox: no map(), no names starting with `_`.
"""

import json
from datetime import datetime


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
                "transformationId": "isDNSFilteringEnabled",
                "vendor": "DNSFilter",
                "category": "Network Security"
            }
        }
    }


def networks_of(data):
    """The network list: the body itself, or its `data` / `networks` list for a raw body. None when absent."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("data", "networks"):
            if isinstance(data.get(key), list):
                return data[key]
    return None


def attributes_of(network):
    """A network's fields: under `attributes` (JSON:API), or the network itself when already flattened."""
    if not isinstance(network, dict):
        return None
    attributes = network.get("attributes")
    return attributes if isinstance(attributes, dict) else network


def why_unreadable(data):
    if not isinstance(data, dict):
        return "body is " + ("null" if data is None else "not an object or a list")
    if not data:
        return "body is empty"
    for key in ("error", "errors", "message"):
        if key in data:
            return f"vendor {key}: {str(data[key])[:200]}"
    return "body is not a network list (keys: " + ", ".join(sorted(str(k) for k in data)[:10]) + ")"


def ip_count_of(attributes):
    """`ip_count` as a non-negative whole number, else 0 (it is evidence only, never the verdict)."""
    count = attributes.get("ip_count")
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        return 0
    return count


def transform(input):
    criteriaKey = "isDNSFilteringEnabled"
    validation = {"status": "unknown", "errors": [], "warnings": []}

    def not_measured(reason, input_summary=None, transformation_errors=None):
        return create_response(
            result={criteriaKey: None, "totalNetworks": None, "activeNetworks": None,
                    "networksWithIps": None, "totalIpCount": None},
            validation=validation,
            api_errors=[reason],
            fail_reasons=["DNSFilter networks could not be read"],
            recommendations=["Re-run the check; if it persists, confirm the DNSFilter API key can read the organisation's networks"],
            input_summary=input_summary,
            transformation_errors=transformation_errors
        )

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            errors = validation.get("errors", []) or ["schema rejected the body"]
            return not_measured("Input validation failed: " + "; ".join(str(e) for e in errors))

        networks = networks_of(data)
        if networks is None:
            return not_measured(f"DNSFilter returned no readable network list: {why_unreadable(data)}")

        live = 0
        deleted = 0
        unreadable = 0
        with_ips = 0
        total_ips = 0
        for network in networks:
            attributes = attributes_of(network)
            if attributes is None:
                unreadable += 1
                continue
            if attributes.get("deleted_at"):
                deleted += 1
                continue
            live += 1
            ips = ip_count_of(attributes)
            total_ips += ips
            if ips > 0:
                with_ips += 1

        summary = {"totalNetworks": len(networks), "activeNetworks": live, "deletedNetworks": deleted,
                   "unreadableNetworks": unreadable, "networksWithIps": with_ips, "totalIpCount": total_ips}
        result = {criteriaKey: live > 0, "totalNetworks": len(networks), "activeNetworks": live,
                  "networksWithIps": with_ips, "totalIpCount": total_ips}

        if live > 0:
            findings = []
            if with_ips == 0:
                findings.append("No live network has a registered IP address, so filtering depends on roaming clients or relays, which this check does not read")
            if deleted:
                findings.append(f"{deleted} deleted network(s) were not counted")
            if unreadable:
                findings.append(f"{unreadable} network record(s) could not be read and were not counted")
            return create_response(
                result=result,
                validation=validation,
                pass_reasons=[f"DNSFilter has {live} live network(s), {with_ips} with registered IP addresses ({total_ips} in total)"],
                additional_findings=findings,
                input_summary=summary
            )

        if unreadable:
            return not_measured(f"DNSFilter networks could not be measured: {unreadable} network record(s) could not be read",
                                input_summary=summary)

        return create_response(
            result=result,
            validation=validation,
            fail_reasons=["DNSFilter has no live network for this organisation" + (f" ({deleted} deleted)" if deleted else "")],
            recommendations=["Add a network (site) in DNSFilter with a filtering policy, and register its IP addresses or deploy roaming clients to it"],
            input_summary=summary
        )

    except Exception as e:
        validation = {"status": "error", "errors": [], "warnings": []}
        return not_measured(f"Transformation error: {str(e)}", transformation_errors=[str(e)])
