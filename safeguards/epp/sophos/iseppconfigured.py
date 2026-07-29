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

Verdict: passes when there is at least one computer with endpointProtection
installed AND every such computer is healthy (health.overall == "good" and all
protection services running). The raw counts are returned alongside so the
threshold can be reviewed against real estates.
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

        total_protected = 0
        total_configured = 0
        unhealthy_hosts = []

        for endpoint in items:
            if not isinstance(endpoint, dict):
                continue
            if endpoint.get("type") != "computer":
                continue
            if not has_endpoint_protection(endpoint):
                continue
            total_protected = total_protected + 1
            if endpoint_is_healthy(endpoint):
                total_configured = total_configured + 1
            else:
                host = endpoint.get("hostname") or endpoint.get("id") or "unknown"
                unhealthy_hosts = unhealthy_hosts + [host]

        configured_pct = round((total_configured / total_protected) * 100) if total_protected > 0 else 0

        # Return the coverage percentage as the evaluated value. The pass bar
        # lives in the requirement token (greaterThan: 90), mirroring how AWS
        # compliancePercentage works - so the threshold can be tuned without a
        # transform redeploy. A tenant with zero protected computers scores 0
        # and also fails isEPPEnabled, so this is not the only signal there.
        return {
            "isEPPConfigured": configured_pct,
            "protectedComputers": total_protected,
            "configuredComputers": total_configured,
            "configuredPercentage": configured_pct,
            "unhealthyHosts": unhealthy_hosts[:20],
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
            pass_reasons.append(f"{configured} of {protected} protected computer(s) report healthy protection ({pct}%)")
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
