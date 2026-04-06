"""
Transformation: isContinuousMonitoringEnabled
Vendor: Wazuh Server
Category: MDR

Evaluates isContinuousMonitoringEnabled for Wazuh Server MDR
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isContinuousMonitoringEnabled", "vendor": "Wazuh Server", "category": "MDR"}
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

        # Wazuh manager/status returns daemon statuses under data.affected_items
        status_data = data.get("data", data)
        affected_items = status_data.get("affected_items", status_data.get("items", []))

        daemons = {}
        if isinstance(affected_items, list) and len(affected_items) > 0:
            daemons = affected_items[0] if isinstance(affected_items[0], dict) else {}
        elif isinstance(status_data, dict) and not affected_items:
            # Direct daemon status map
            daemons = status_data

        # Core daemons that must be running for continuous monitoring
        core_daemons = ["wazuh-analysisd", "wazuh-remoted", "wazuh-syscheckd"]
        running_count = 0
        total_count = 0
        core_running = 0

        for daemon_name, daemon_status in daemons.items():
            if isinstance(daemon_status, str):
                total_count += 1
                if daemon_status.lower() in ("running", "active"):
                    running_count += 1
                    if daemon_name in core_daemons:
                        core_running += 1

        # At least analysisd and remoted must be running
        result = core_running >= 2

        return create_response(

            result={
            "isContinuousMonitoringEnabled": result,
            "runningDaemons": running_count,
            "totalDaemons": total_count,
            "coreDaemonsRunning": core_running
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
