"""
Transformation: isThirdPartyMonitoringEnabled
Vendor: AppOmni  |  Category: Cloud Security
Evaluates: At least one connected service has third-party OAuth app monitoring enabled
API: GET /api/v1/core/monitoredservice/
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
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isThirdPartyMonitoringEnabled", "vendor": "AppOmni", "category": "Cloud Security"}
        }
    }


def transform(input):
    criteriaKey = "isThirdPartyMonitoringEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # === EVALUATION LOGIC ===
        # GET /api/v1/core/monitoredservice/ returns DRF paginated response
        # Each service object has: id, name, service_type, account_id, slug, enabled
        services = data.get("results", data.get("data", data.get("items", [])))

        if not isinstance(services, list):
            return create_response(
                result={criteriaKey: False, "servicesWithThirdPartyMonitoring": 0, "totalServices": 0},
                validation=validation,
                fail_reasons=["Unexpected services response format"],
                recommendations=["Verify the API response contains a list of services"],
                input_summary={"dataType": "non-list"}
            )

        total = len(services)

        monitored = [
            s for s in services
            if s.get("enabled", False) and (
                s.get("third_party_apps_monitored", False) or
                s.get("third_party_monitoring_enabled", False) or
                s.get("oauth_app_monitoring_enabled", False)
            )
        ]

        service_types = [s.get("service_type", "unknown") for s in monitored if s.get("service_type")]
        result = len(monitored) >= 1
        # === END EVALUATION LOGIC ===

        if result:
            pass_reasons.append(f"{len(monitored)} of {total} service(s) have third-party app monitoring enabled")
            if service_types:
                pass_reasons.append(f"Service types with monitoring: {', '.join(service_types)}")
        else:
            fail_reasons.append(f"No enabled services have third-party app monitoring (total services: {total})")
            recommendations.append("Enable third-party OAuth app monitoring on at least one connected service in AppOmni")

        return create_response(
            result={criteriaKey: result, "servicesWithThirdPartyMonitoring": len(monitored), "totalServices": total, "serviceTypes": service_types},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalServices": total, "servicesWithThirdPartyMonitoring": len(monitored)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
