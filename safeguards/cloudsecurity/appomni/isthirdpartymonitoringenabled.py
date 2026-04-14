"""
Transformation: isThirdPartyMonitoringEnabled
Vendor: AppOmni  |  Category: Cloud Security
Evaluates: At least one connected service has third-party app monitoring enabled
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

        # AppOmni /monitoredservice/ returns a bare list or paginated dict
        # Determine the services array from whichever format we receive
        services = []
        if isinstance(data, list):
            services = [item for item in data if isinstance(item, dict)]
        elif isinstance(data, dict):
            candidate = data.get("results", data.get("data", data.get("items", None)))
            if isinstance(candidate, list):
                services = [item for item in candidate if isinstance(item, dict)]
            else:
                # Single service object — wrap as list
                services = [data]

        if len(services) == 0:
            return create_response(
                result={criteriaKey: False, "servicesWithMonitoring": 0, "totalServices": 0},
                validation=validation,
                fail_reasons=["No service objects found in response"]
            )

        total = len(services)

        # A service has third-party monitoring enabled when:
        # 1. detection_ingest_enabled is true (data collection active)
        # 2. integration_connected is true (integration is live)
        # 3. monitoring_reqs_satisfied is true (all monitoring prereqs met)
        # AppOmni returns these as string "True"/"False"
        monitored = []
        not_monitored = []
        for s in services:
            if not isinstance(s, dict):
                continue
            ingest = str_to_bool(s.get("detection_ingest_enabled", False))
            connected = str_to_bool(s.get("integration_connected", False))
            reqs_met = str_to_bool(s.get("monitoring_reqs_satisfied", False))
            archived = str_to_bool(s.get("is_archived", False))

            if ingest and connected and reqs_met and not archived:
                monitored.append(s)
            else:
                not_monitored.append(s)

        # Collect unique service types from monitored services
        seen_types = {}
        service_types = []
        for s in monitored:
            st = s.get("service_type", "")
            if st and st not in seen_types:
                seen_types[st] = True
                service_types.append(st)

        result = len(monitored) >= 1

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result:
            type_str = ""
            for idx in range(len(service_types)):
                if idx > 0:
                    type_str = type_str + ", "
                type_str = type_str + str(service_types[idx])
            pass_reasons.append(str(len(monitored)) + " of " + str(total) + " service(s) have active monitoring with detection ingest enabled")
            if service_types:
                pass_reasons.append("Monitored service types: " + type_str)
        else:
            fail_reasons.append("No services have active third-party monitoring (total services: " + str(total) + ")")
            if not_monitored:
                reasons = []
                for s in not_monitored:
                    name = s.get("name", "unknown")
                    if not str_to_bool(s.get("integration_connected", False)):
                        reasons.append(name + ": integration not connected")
                    elif not str_to_bool(s.get("detection_ingest_enabled", False)):
                        reasons.append(name + ": detection ingest not enabled")
                    elif not str_to_bool(s.get("monitoring_reqs_satisfied", False)):
                        reasons.append(name + ": monitoring requirements not satisfied")
                if reasons:
                    for r in reasons:
                        fail_reasons.append(r)
            recommendations.append("Enable detection ingest and ensure integration is connected on at least one service in AppOmni")

        return create_response(
            result={criteriaKey: result, "servicesWithMonitoring": len(monitored), "totalServices": total, "serviceTypes": service_types},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalServices": total, "servicesWithMonitoring": len(monitored), "serviceTypes": service_types}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
