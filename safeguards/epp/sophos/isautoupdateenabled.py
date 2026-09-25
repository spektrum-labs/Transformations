"""
Transformation: isAutoUpdateEnabled
Vendor: Sophos Central (Intercept X / Endpoint)  |  Category: Endpoint Security
Method: getEndpoints (GET /endpoint/v1/endpoints)

Sophos Central agents update themselves; the effect is visible in the coreAgent
version each endpoint reports in assignedProducts. Versions are "<year>.<release>.x.y"
(measured 2026-09-24 on 174 live endpoints across two production tenants: 2026.2.1.3.0
on Windows, 2026.2.0.8 on macOS, 2026.2.0.2 on Linux for every endpoint seen that week).

An active endpoint (seen within 7 days of the newest lastSeenAt in the response) counts
as updating when its coreAgent release line (<year>.<release>) equals the newest release
line reported for its platform in the tenant. The newest line must also be no more than
one calendar year behind the newest lastSeenAt, so a fleet frozen together on an old
release does not pass by agreeing with itself.

What this proves: updates are landing on every active endpoint. What it does not prove:
the update-management policy toggle itself, or threat-definition (data) freshness, which
the endpoints API does not report.

Verdict: true when at least one active endpoint reports a coreAgent and all of them are
on the newest release line. The requirement token compares isEquals true.
"""
import json
from datetime import datetime, timedelta


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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isAutoUpdateEnabled", "vendor": "Sophos", "category": "Endpoint Security"}
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




def release_line(version):
    """Version "2026.2.1.3.0" gives (2026, 2); None when the version cannot be read."""
    parts = str(version or "").split(".")
    if len(parts) < 2 or not parts[0].isdigit() or not parts[1].isdigit():
        return None
    return (int(parts[0]), int(parts[1]))


def core_agent_version(endpoint):
    for product in endpoint.get("assignedProducts") or []:
        if isinstance(product, dict) and product.get("code") == "coreAgent" and product.get("status") == "installed":
            return product.get("version")
    return None


def transform(input):
    criteriaKey = "isAutoUpdateEnabled"
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
        seen = [parse_seen(e.get("lastSeenAt")) for e in active]
        seen = [s for s in seen if s is not None]
        current_year = max(seen).year if seen else None

        agents = []
        for endpoint in active:
            line = release_line(core_agent_version(endpoint))
            if line is not None:
                platform = str((endpoint.get("os") or {}).get("platform") or "unknown")
                agents.append((platform, line, endpoint.get("hostname") or endpoint.get("id") or "unknown"))

        newest = {}
        for platform, line, host in agents:
            if platform not in newest or line > newest[platform]:
                newest[platform] = line

        old_lines = [platform for platform, line in newest.items()
                     if current_year is not None and line[0] < current_year - 1]
        behind = [host for platform, line, host in agents
                  if line != newest[platform] or platform in old_lines]
        value = len(agents) > 0 and len(behind) == 0

        summary = {
            "activeEndpointsWithAgent": len(agents),
            "endpointsOnNewestRelease": len(agents) - len(behind),
            "newestReleaseByPlatform": {p: f"{l[0]}.{l[1]}" for p, l in newest.items()},
            "endpointsBehind": behind[:20],
            "staleEndpointsExcluded": stale,
        }
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if not agents:
            fail_reasons.append("No active endpoint reports a Sophos core agent version, so automatic updating could not be confirmed")
            recommendations.append("Check that the Sophos Central credential can read endpoints")
        elif value:
            pass_reasons.append(f"All {len(agents)} active endpoint(s) run the newest Sophos agent release for their platform")
        else:
            if old_lines:
                fail_reasons.append("The newest agent release on " + ", ".join(sorted(old_lines)) + " is more than a year old")
            fail_reasons.append(f"{len(behind)} of {len(agents)} active endpoint(s) are not on the newest Sophos agent release for their platform")
            recommendations.append("Check the update-management policy and update status for: " + ", ".join(str(h) for h in behind[:20]))

        return create_response(result={criteriaKey: value, **summary}, validation=validation,
                               pass_reasons=pass_reasons, fail_reasons=fail_reasons,
                               recommendations=recommendations, input_summary={criteriaKey: value, **summary})
    except Exception as e:
        return create_response(result={criteriaKey: False},
                               validation={"status": "error", "errors": [], "warnings": []},
                               transformation_errors=[str(e)], fail_reasons=[f"Transformation error: {str(e)}"])
