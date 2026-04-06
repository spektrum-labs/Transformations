"""
Transformation: isContinuousMonitoringEnabled
Vendor: Vectra Detect
Category: Cloud Security

Evaluates isContinuousMonitoringEnabled for Vectra Detect
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isContinuousMonitoringEnabled", "vendor": "Vectra Detect", "category": "Cloud Security"}
        }
    }


def transform(input):
    criteriaKey = "isContinuousMonitoringEnabled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        data = data.get("apiResponse", data)

        # -- EVALUATION LOGIC --
        sensors = data.get("sensors", data.get("Sensors", {}))
        network = data.get("network", data.get("Network", {}))
        system = data.get("system", data.get("System", {}))

        healthyComponents = 0
        totalComponents = 0

        for component in [sensors, network, system]:
            if isinstance(component, dict) and component:
                totalComponents = totalComponents + 1
                compStatus = component.get("status", component.get("state", ""))
                if isinstance(compStatus, str) and compStatus.lower() in ("ok", "healthy", "active", "green"):
                    healthyComponents = healthyComponents + 1
            elif isinstance(component, list) and len(component) > 0:
                totalComponents = totalComponents + 1
                healthyComponents = healthyComponents + 1

        if totalComponents == 0 and data:
            totalComponents = 1
            healthyComponents = 1

        result = healthyComponents > 0
        # -- END EVALUATION LOGIC --

        return create_response(

            result={
            "isContinuousMonitoringEnabled": result,
            "activeDevices": healthyComponents,
            "totalDevices": totalComponents
        },

            validation=validation

        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
