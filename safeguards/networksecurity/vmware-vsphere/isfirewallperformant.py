"""
Transformation: isFirewallPerformant
Vendor: Vmware Vsphere
Category: Network Security

Evaluates isFirewallPerformant for VMware vSphere (Network Security)
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isFirewallPerformant", "vendor": "Vmware Vsphere", "category": "Network Security"}
        }
    }


def transform(input):
    criteriaKey = "isFirewallPerformant"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        data = data.get("apiResponse", data)

        # -- EVALUATION LOGIC --
        result = False

        # vSphere host list: check all hosts are connected and powered on (healthy state)
        hosts = data if isinstance(data, list) else data.get("value", [])
        if isinstance(hosts, list) and len(hosts) > 0:
            all_healthy = True
            for host in hosts:
                if isinstance(host, dict):
                    conn = host.get("connection_state", "")
                    power = host.get("power_state", "")
                    if conn != "CONNECTED" or power != "POWERED_ON":
                        all_healthy = False
                        break
            result = all_healthy
        elif isinstance(data, dict):
            cpu = data.get("cpuUsage", data.get("cpu_usage", None))
            mem = data.get("memoryUsage", data.get("memory_usage", None))
            if cpu is not None and mem is not None:
                try:
                    result = float(cpu) < 50 and float(mem) < 50
                except (ValueError, TypeError):
                    result = False

        # -- END EVALUATION LOGIC --

        return create_response(

            result={"isFirewallPerformant": result},

            validation=validation

        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
