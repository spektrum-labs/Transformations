"""
Transformation: isRealTimeProtectionEnabled
Vendor: Sophos Central (Intercept X / Endpoint)  |  Category: Endpoint Security
Method: getEndpoints (GET /endpoint/v1/endpoints)

Real-time (on-access) scanning in Sophos is performed by a dedicated scanner service
that each agent reports in health.services.serviceDetails:
  Windows  "Sophos File Scanner", "Sophos File Scanner Service", "File Detection"
  macOS    "Sophos Anti-Virus"
  Linux    "Sophos Linux AntiVirus", "Sophos Anti-Virus"
Names measured on 174 live endpoints across two production tenants on 2026-09-24.

An endpoint counts as real-time protected when it has the endpointProtection product
installed, reports at least one scanner service, and every scanner service it reports
is "running". A protected endpoint that reports no scanner service is NOT counted as
protected: absence of evidence is not evidence.

Only endpoints seen within 7 days of the newest lastSeenAt in the response are judged,
because a service report is only as current as the endpoint's last check-in. Stale
endpoints are counted and returned, not silently dropped.

What this proves: the on-access scanner is deployed and running on every active
protected endpoint. What it does not prove: the threat-protection policy's individual
on-access toggles (those live in /endpoint/v1/policies, which this method does not read).

Verdict: true when at least one active protected endpoint exists and all of them are
real-time protected. The requirement token compares isEquals true.
"""
import json
from datetime import datetime, timedelta


SCANNER_SERVICES = (
    "Sophos File Scanner",
    "Sophos File Scanner Service",
    "File Detection",
    "Sophos Anti-Virus",
    "Sophos Linux AntiVirus",
)
ACTIVE_WINDOW_DAYS = 7


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
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
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isRealTimeProtectionEnabled", "vendor": "Sophos", "category": "Endpoint Security"}
        }
    }


def endpoint_items(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        items = data.get("items")
        if isinstance(items, list):
            return items
    return None


def api_error_message(data):
    if isinstance(data, dict) and (data.get("error") is True or str(data.get("error")).lower() == "true"):
        return str(data.get("errorMessage") or data.get("message") or "Sophos API returned an error")
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
    active = []
    stale = 0
    for endpoint, when in zip(endpoints, seen):
        if when is not None and when < cutoff:
            stale = stale + 1
        else:
            active.append(endpoint)
    return active, stale


def has_endpoint_protection(endpoint):
    for product in endpoint.get("assignedProducts") or []:
        if isinstance(product, dict) and product.get("code") == "endpointProtection":
            return product.get("status") == "installed"
    return False


def scanner_running(endpoint):
    services = ((endpoint.get("health") or {}).get("services") or {}).get("serviceDetails") or []
    scanners = [s for s in services if isinstance(s, dict) and s.get("name") in SCANNER_SERVICES]
    if not scanners:
        return False
    return all(s.get("status") == "running" for s in scanners)


def transform(input):
    criteriaKey = "isRealTimeProtectionEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation,
                                   fail_reasons=["Input validation failed"])

        error = api_error_message(data)
        items = endpoint_items(data)
        if error or items is None:
            reason = error or "Endpoints response not recognised - no items list present"
            return create_response(result={criteriaKey: False}, validation=validation,
                                   api_errors=[reason], fail_reasons=[reason],
                                   recommendations=["Verify the Sophos endpoints API (/endpoint/v1/endpoints) is reachable for this tenant"])

        active, stale = active_endpoints(items)
        protected = [e for e in active if has_endpoint_protection(e)]
        missing = [e.get("hostname") or e.get("id") or "unknown" for e in protected if not scanner_running(e)]
        ok = len(protected) - len(missing)
        pct = round((ok / len(protected)) * 100) if protected else 0
        value = len(protected) > 0 and len(missing) == 0

        summary = {
            "protectedEndpoints": len(protected),
            "realTimeProtectedEndpoints": ok,
            "realTimeProtectedPercentage": pct,
            "endpointsWithoutRealTimeScanning": missing[:20],
            "staleEndpointsExcluded": stale,
        }
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if not protected:
            fail_reasons.append("No active endpoint has Sophos endpoint protection installed")
            recommendations.append("Deploy the Sophos endpoint agent to endpoints")
        elif value:
            pass_reasons.append(f"The on-access scanner is running on all {len(protected)} active protected endpoint(s)")
        else:
            fail_reasons.append(f"{len(missing)} of {len(protected)} active protected endpoint(s) do not report a running on-access scanner")
            recommendations.append("Restore the Sophos file scanner service on: " + ", ".join(str(h) for h in missing[:20]))

        return create_response(result={criteriaKey: value, **summary}, validation=validation,
                               pass_reasons=pass_reasons, fail_reasons=fail_reasons,
                               recommendations=recommendations, input_summary={criteriaKey: value, **summary})
    except Exception as e:
        return create_response(result={criteriaKey: False},
                               validation={"status": "error", "errors": [], "warnings": []},
                               transformation_errors=[str(e)], fail_reasons=[f"Transformation error: {str(e)}"])
