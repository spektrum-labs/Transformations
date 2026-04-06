"""
Transformation: isAlertingConfigured
Vendor: Wazuh Server
Category: MDR

Evaluates isAlertingConfigured for Wazuh Server MDR
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isAlertingConfigured", "vendor": "Wazuh Server", "category": "MDR"}
        }
    }


def transform(input):
    criteriaKey = "isAlertingConfigured"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        data = data.get("apiResponse", data)

        # Wazuh manager configuration returns data under data.affected_items
        config_data = data.get("data", data)
        affected_items = config_data.get("affected_items", config_data.get("items", []))

        alert_level = 0
        alert_config_found = False

        if isinstance(affected_items, list) and len(affected_items) > 0:
            alerts_config = affected_items[0] if isinstance(affected_items[0], dict) else {}
            alerts_section = alerts_config.get("alerts", alerts_config)

            log_alert_level = alerts_section.get("log_alert_level", alerts_section.get("logAlertLevel", None))
            email_alert_level = alerts_section.get("email_alert_level", None)

            if log_alert_level is not None:
                alert_level = int(log_alert_level)
                alert_config_found = True
            elif email_alert_level is not None:
                alert_level = int(email_alert_level)
                alert_config_found = True
        elif isinstance(config_data, dict):
            # Direct config response
            log_alert_level = config_data.get("log_alert_level", config_data.get("alerts", {}).get("log_alert_level", None))
            if log_alert_level is not None:
                alert_level = int(log_alert_level)
                alert_config_found = True

        # Alerting is configured if the alerts section exists with valid settings
        result = alert_config_found

        return create_response(

            result={
            "isAlertingConfigured": result,
            "alertLevel": alert_level
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
