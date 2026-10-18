"""
Transformation: isEPPConfigured
Vendor: Sophos  |  Category: Endpoint Security

Distinct from isEPPEnabled. isEPPEnabled keys off whether the endpointProtection
product is ASSIGNED to a computer (coverage > 0). isEPPConfigured keys off
whether that protection is actually CONFIGURED AND WORKING on the machines that
have it: the agent is installed, the endpoint reports healthy, and its
protection services are running.

Without this split the two criteria collapse to the same boolean, because
"product assigned" implies "an endpoint exists" - so a tenant whose agents are
installed but unhealthy (services stopped, tamper protection off, health "bad")
would still pass isEPPConfigured. Reading the per-endpoint `health` block fixes
that: such a tenant passes isEPPEnabled (installed) but fails isEPPConfigured
(not healthy).

Sophos GET /endpoint/v1/endpoints returns:
  { "items": [ { "type", "health": {"overall", "services": {"status",
    "serviceDetails": [{"name","status"}]}}, "tamperProtectionEnabled",
    "assignedProducts": [{"code","status"}] } ], "pages": {...} }
Token-Service preprocessing may hand the transform the bare items list instead
of the wrapper, so both shapes are accepted.

Value: a whole-number percentage, floor(100 * configured / protected).
protected = computers AND servers with endpointProtection installed; configured =
those reporting healthy protection (health.overall == "good", services running,
tamper protection not off). The pass bar lives in the requirement. Only endpoints
seen within 15 days of the newest lastSeenAt in the response are judged (endpoint
rules 2026-09-29); the rest are reported as staleEndpointCount. No protected endpoint, or a device list the paginator
marked truncated, is not evaluated (dataCollection error, no value).
"""
import json
from datetime import datetime, timedelta


ACTIVE_WINDOW_DAYS = 15


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
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPConfigured", "vendor": "Sophos", "category": "Endpoint Security"}
        }
    }


def endpoint_is_healthy(endpoint):
    """A protected endpoint counts as configured when the agent reports healthy
    and its protection services are running. Reads only fields Sophos returns on
    every endpoint object."""
    health = endpoint.get("health") or {}
    if health.get("overall") != "good":
        return False
    services = health.get("services") or {}
    details = services.get("serviceDetails") or []
    # Require the services block to report good AND every listed service running.
    if services.get("status") not in (None, "good"):
        return False
    for service in details:
        if isinstance(service, dict) and service.get("status") != "running":
            return False
    # Explicit tamper-protection = False is a real misconfiguration; a missing
    # field is not held against the endpoint.
    if endpoint.get("tamperProtectionEnabled") is False:
        return False
    return True


def has_endpoint_protection(endpoint):
    """endpointProtection product assigned and installed - the same product
    isEPPEnabled keys off, but here we also require status == installed."""
    for product in endpoint.get("assignedProducts", []):
        if isinstance(product, dict) and product.get("code") == "endpointProtection":
            return product.get("status", "installed") == "installed"
    return False


def evaluate(data):
    try:
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = data.get("items")
            if not isinstance(items, list):
                return {"isEPPConfigured": 0, "dataProblem": True,
                        "reason": "Endpoints response not recognised - no items list present"}
        else:
            return {"isEPPConfigured": 0, "dataProblem": True,
                    "reason": "Endpoints response not recognised"}

        items, stale_endpoints = active_endpoints(items)
        total_protected = 0
        total_configured = 0
        unhealthy_hosts = []

        for endpoint in items:
            if not isinstance(endpoint, dict):
                continue
            if endpoint.get("type") not in ("computer", "server"):
                continue
            if not has_endpoint_protection(endpoint):
                continue
            total_protected = total_protected + 1
            if endpoint_is_healthy(endpoint):
                total_configured = total_configured + 1
            else:
                host = endpoint.get("hostname") or endpoint.get("id") or "unknown"
                unhealthy_hosts = unhealthy_hosts + [host]

        pages = data.get("pages") if isinstance(data, dict) else None
        if isinstance(pages, dict) and str(pages.get("truncated")).lower() == "true":
            return {"isEPPConfigured": None, "dataProblem": True,
                    "reason": "Endpoint list was truncated by pagination; percentage not evaluated on a sample"}
        if total_protected == 0:
            return {"isEPPConfigured": None, "dataProblem": True, "protectedComputers": 0,
                    "staleEndpointCount": stale_endpoints,
                    "reason": "No computer or server has Sophos endpoint protection installed; nothing to measure"}

        configured_pct = (total_configured * 100) // total_protected

        # Return the coverage percentage as the evaluated value. The pass bar
        # lives in the requirement token (greaterThan: 90), mirroring how AWS
        # compliancePercentage works - so the threshold can be tuned without a
        # transform redeploy.
        return {
            "isEPPConfigured": configured_pct,
            "protectedComputers": total_protected,
            "configuredComputers": total_configured,
            "configuredPercentage": configured_pct,
            "unhealthyHosts": unhealthy_hosts[:20],
            "staleEndpointCount": stale_endpoints,
        }
    except Exception as e:
        return {"isEPPConfigured": 0, "dataProblem": True, "error": str(e)}


def transform(input):
    criteriaKey = "isEPPConfigured"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: 0},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        eval_result = evaluate(data)

        result_value = eval_result.get(criteriaKey, 0)
        data_problem = eval_result.get("dataProblem", False)
        extra_fields = {k: v for k, v in eval_result.items()
                        if k not in (criteriaKey, "error", "reason", "dataProblem")}

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        api_errors = []

        protected = eval_result.get("protectedComputers", 0)
        configured = eval_result.get("configuredComputers", 0)
        pct = eval_result.get("configuredPercentage", 0)
        unhealthy = eval_result.get("unhealthyHosts", []) or []

        # Verdict (pass bar) is owned by the requirement token's greaterThan:90;
        # these reasons are informational context only.
        if data_problem:
            reason = eval_result.get("reason") or eval_result.get("error") or "Endpoints response could not be read"
            api_errors.append(reason)
            fail_reasons.append(reason)
            recommendations.append("Verify the Sophos endpoints API (/endpoint/v1/endpoints) is reachable for this tenant")
        elif protected == 0:
            fail_reasons.append("No computer has Sophos endpoint protection installed")
            recommendations.append("Deploy the Sophos endpoint agent to computers")
        else:
            pass_reasons.append(f"{configured} of {protected} protected endpoint(s) (computers and servers) report healthy protection ({pct}%)")
            if unhealthy:
                recommendations.append(f"Endpoints with degraded/stopped protection services: {', '.join(str(h) for h in unhealthy)}")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            api_errors=api_errors,
            input_summary={criteriaKey: result_value, **extra_fields}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: 0},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
