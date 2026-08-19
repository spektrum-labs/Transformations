"""
Transformation: isEPPDeployed
Vendor: ThreatDown (Malwarebytes Nebula)  |  Category: EPP
Evaluates: Percentage of endpoints with ThreatDown EPP agent deployed and reporting.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPDeployed", "vendor": "ThreatDown", "category": "EPP"}
        }
    }


def evaluate(data):
    """Percentage of endpoints running the ThreatDown Endpoint Protection agent.

    Real shape: POST /nebula/v1/endpoints returns {total_count, endpoints[]}. Each
    endpoint carries protection_status, connected, and agent.plugins keyed by
    product (endpoint_protection, endpoint_detection_and_response, ...). The
    documented GET route does not exist; this is a search endpoint.
    """
    endpoints = data.get("endpoints") or []
    if not isinstance(endpoints, list):
        endpoints = []

    try:
        total = int(data.get("total_count") or len(endpoints))
    except Exception:
        total = len(endpoints)
    if total < len(endpoints):
        total = len(endpoints)

    deployed = 0
    protected = 0
    offline = []
    missing = []

    for endpoint in endpoints:
        if not isinstance(endpoint, dict):
            continue
        name = endpoint.get("display_name") or (endpoint.get("agent") or {}).get("host_name") or "Unknown"

        plugins = ((endpoint.get("agent") or {}).get("plugins") or {})
        has_plugin = "endpoint_protection" in plugins

        if has_plugin:
            deployed = deployed + 1
        else:
            missing.append(name)

        if str(endpoint.get("protection_status", "")).strip().lower() == "protected":
            protected = protected + 1

        # Reported but not failed on: an agent can be installed and simply offline.
        if endpoint.get("connected") is False:
            offline.append(name)

    percentage = int(round((deployed * 100.0) / total)) if total else 0

    return {
        "isEPPDeployed": total > 0 and deployed == total,
        "totalEndpoints": total,
        "deployedEndpoints": deployed,
        "deployedPercentage": percentage,
        "protectedEndpoints": protected,
        "endpointsMissingAgent": missing,
        "offlineEndpoints": offline,
    }


def transform(input):
    criteriaKey = "isEPPDeployed"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            pass_reasons.append(f"EPP agent deployed on {extra_fields.get('deployedEndpoints', 0)} of {extra_fields.get('totalEndpoints', 0)} endpoints ({extra_fields.get('deployedPercentage', 0)}%)")
        else:
            total = extra_fields.get("totalEndpoints", 0)
            deployed = extra_fields.get("deployedEndpoints", 0)
            pct = extra_fields.get("deployedPercentage", 0)
            if total == 0:
                fail_reasons.append("No endpoints found in ThreatDown Nebula")
                recommendations.append("Verify ThreatDown agent is installed on managed endpoints")
            else:
                fail_reasons.append(f"EPP coverage is {pct}% ({deployed}/{total} endpoints) - below 80% threshold")
                recommendations.append("Deploy ThreatDown EPP agent to remaining unprotected endpoints")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
