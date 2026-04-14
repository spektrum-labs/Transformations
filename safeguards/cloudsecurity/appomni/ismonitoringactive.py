"""
Transformation: isMonitoringActive
Vendor: AppOmni  |  Category: Cloud Security
Evaluates: At least one SaaS service is connected and actively being monitored
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


def str_to_bool(val):
    """Handle AppOmni string booleans ('True', 'False', 'None')."""
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower() in ("true", "1", "yes")
    return False


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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isMonitoringActive", "vendor": "AppOmni", "category": "Cloud Security"}
        }
    }


def transform(input):
    criteriaKey = "isMonitoringActive"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        # AppOmni /monitoredservice/ returns a paginated dict or bare list
        services = []
        if isinstance(data, list):
            services = [item for item in data if isinstance(item, dict)]
        elif isinstance(data, dict):
            candidate = data.get("results", data.get("data", data.get("items", None)))
            if isinstance(candidate, list):
                services = [item for item in candidate if isinstance(item, dict)]
            else:
                services = [data]

        total = len(services)

        # A service is actively monitored when:
        # 1. integration_connected is true
        # 2. detection_ingest_enabled is true (data collection active)
        # 3. monitoring_reqs_satisfied is true (all prereqs met)
        # 4. not archived
        active = []
        for s in services:
            if not isinstance(s, dict):
                continue
            connected = str_to_bool(s.get("integration_connected", False))
            ingest = str_to_bool(s.get("detection_ingest_enabled", False))
            reqs_met = str_to_bool(s.get("monitoring_reqs_satisfied", False))
            archived = str_to_bool(s.get("is_archived", False))

            if connected and ingest and reqs_met and not archived:
                active.append(s)

        # Collect unique service types from active services
        seen_types = {}
        service_types = []
        for s in active:
            st = s.get("service_type", "")
            if st and st not in seen_types:
                seen_types[st] = True
                service_types.append(st)

        result = len(active) >= 1

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result:
            type_str = ""
            for idx in range(len(service_types)):
                if idx > 0:
                    type_str = type_str + ", "
                type_str = type_str + str(service_types[idx])
            pass_reasons.append(str(len(active)) + " of " + str(total) + " service(s) actively monitored")
            if service_types:
                pass_reasons.append("Monitored types: " + type_str)
        else:
            fail_reasons.append("No services are actively monitored (total services: " + str(total) + ")")
            recommendations.append("Enable monitoring on at least one connected SaaS service in AppOmni")

        return create_response(
            result={criteriaKey: result, "activeServices": len(active), "totalServices": total, "serviceTypes": service_types},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalServices": total, "activeServices": len(active)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
